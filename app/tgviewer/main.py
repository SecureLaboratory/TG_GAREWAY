"""FastAPI application: routes, security headers, background loops."""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from telethon.errors import FloodWaitError, RPCError

from . import i18n, maintenance
from .config import settings
from .db import init_db
from .audit import audit
from .feeds import store
from .ratelimit import RateLimiter
from .desk import watch_downloads, write_policy
from .routes import admin, auth, chats, desk as desk_routes, gate, users
from .telegram import NotLinked, TelegramNotConfigured, tg
from .deps import via_admin_channel
from .util import utcnow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs can carry feed keys
STATIC = Path(__file__).parent / "static"

CSP = ("default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; "
       "frame-ancestors 'none'; form-action 'self'")
# The KasmVNC client (from the browser image) needs inline code and workers; it's framed by our page.
CSP_DESK = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; "
            "worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await asyncio.to_thread(store.load_all)
    loops = [asyncio.create_task(maintenance.run_forever())]
    if settings.feeds_enabled:
        loops.append(asyncio.create_task(store.run_forever()))
    if settings.access_mode == "browser":
        write_policy()
        loops.append(asyncio.create_task(watch_downloads()))
    else:
        # Client mode: keep every linked user online so messages are scanned on arrival.
        loops.append(asyncio.create_task(tg.start_all()))
    yield
    for task in loops:
        task.cancel()
    await tg.shutdown()


app = FastAPI(title="TG Viewer", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


JSON_BODY_LIMIT = 64 * 1024
RATE_LIMITED = ("/api/login", "/api/telegram/send-code", "/api/telegram/resend-code", "/api/telegram/qr/start",
                "/api/telegram/sign-in", "/api/telegram/password")
PERMISSIONS_POLICY = ("camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), "
                      "hid=(), midi=(), magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=()")
login_limiter = RateLimiter(max_requests=30, window=300)


@app.middleware("http")
async def security(request: Request, call_next):
    path, method = request.url.path, request.method
    # The admin page's own files are not served outside the admin entrance either.
    if path.startswith("/static/admin.") and not via_admin_channel(request):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    # Isolated browsers share a network with the gateway; they must never call its API.
    if request.client and request.client.host.startswith(settings.browser_subnet_prefix + "."):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    if method not in ("GET", "HEAD", "OPTIONS"):
        # CSRF: state-changing API calls must carry a header a cross-site form can't set.
        if path.startswith("/api/") and request.headers.get("x-tgv") != "1":
            return JSONResponse({"detail": "Missing X-TGV header"}, status_code=403)
        # Body size limit before anything is read or spooled to disk.
        limit = (settings.max_file_mb * 2**20 + 2**20) if path.endswith(("/files", "/uploads")) else JSON_BODY_LIMIT
        length = request.headers.get("content-length")
        if length is None and "chunked" in request.headers.get("transfer-encoding", "").lower():
            return JSONResponse({"detail": "Content-Length required"}, status_code=411)
        if length is not None and (not length.isdigit() or int(length) > limit):
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        # Per-IP rate limit on login and Telegram code requests (on top of the per-account lockout).
        if path.startswith(RATE_LIMITED) and not login_limiter.allow(request.client.host if request.client else "-"):
            audit("auth.rate_limited", source_ip=request.client.host if request.client else None, path=path)
            return JSONResponse({"detail": "Too many attempts from this address, try again in a few minutes"},
                                status_code=429, headers={"Retry-After": str(login_limiter.window)})
    response = await call_next(request)
    if path.startswith("/desk/"):
        response.headers["Content-Security-Policy"] = CSP_DESK
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
    else:
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Frame-Options"] = "DENY"
    # OWASP Secure Headers Project recommendations.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if path.startswith(("/api/", "/go/")) or path in ("/", "/admin"):
        response.headers["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        # Revalidate on every load (ETag -> 304), so a new version is never hidden by a cached copy.
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.middleware("http")
async def localize_errors(request: Request, call_next):
    """Error messages in the user's language (registered after `security`, so it wraps it)."""
    response = await call_next(request)
    lang = i18n.pick(request)
    if (lang == "en" or response.status_code < 400
            or not response.headers.get("content-type", "").startswith("application/json")):
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict) and isinstance(data.get("detail"), str):
        data["detail"] = i18n.tr(data["detail"], lang)
        body = json.dumps(data, ensure_ascii=False).encode()
    localized = Response(body, status_code=response.status_code)
    localized.raw_headers = [(k, v) for k, v in response.raw_headers if k.lower() != b"content-length"]
    localized.raw_headers.append((b"content-length", str(len(body)).encode()))
    return localized


@app.exception_handler(RequestValidationError)
async def _invalid(request: Request, exc: RequestValidationError):
    # Generic message: don't echo request content or internal field structure back.
    return JSONResponse({"detail": "Invalid request"}, status_code=422)


@app.get("/.well-known/security.txt", include_in_schema=False)
async def security_txt():
    """RFC 9116; served only when a contact is configured (SECURITY_CONTACT)."""
    if not settings.security_contact:
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    expires = (utcnow() + timedelta(days=180)).strftime("%Y-%m-%dT00:00:00Z")
    body = f"Contact: {settings.security_contact}\nExpires: {expires}\nPreferred-Languages: en, uk\n"
    return PlainTextResponse(body)


# Rejects requests for unexpected Host headers (DNS rebinding against 127.0.0.1).
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)


@app.exception_handler(NotLinked)
async def _not_linked(request: Request, exc: NotLinked):
    return JSONResponse({"detail": "Telegram account is not linked", "code": "not_linked"}, status_code=409)


@app.exception_handler(TelegramNotConfigured)
async def _not_configured(request: Request, exc: TelegramNotConfigured):
    return JSONResponse({"detail": "TG_API_ID / TG_API_HASH are not configured", "code": "not_configured"},
                        status_code=503)


@app.exception_handler(FloodWaitError)
async def _flood(request: Request, exc: FloodWaitError):
    return JSONResponse({"detail": f"Telegram asks to wait {exc.seconds} s before retrying"}, status_code=429)


@app.exception_handler(RPCError)
async def _rpc(request: Request, exc: RPCError):
    message = str(exc).split(" (caused by")[0] or exc.__class__.__name__
    return JSONResponse({"detail": f"Telegram: {message}"}, status_code=400)


@app.exception_handler(LookupError)
async def _lookup(request: Request, exc: LookupError):
    return JSONResponse({"detail": str(exc) or "Not found"}, status_code=404)


app.include_router(auth.router)
app.include_router(chats.router)
app.include_router(gate.router)
app.include_router(admin.router)
app.include_router(users.router)
app.include_router(desk_routes.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/admin", include_in_schema=False)
async def admin_page(request: Request):
    if not via_admin_channel(request):  # admin area only through the admin entrance
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return FileResponse(STATIC / "admin.html")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True}


@app.get("/api/version", include_in_schema=False)
async def version():
    """Release number for the login screen footer (no component or library versions)."""
    return {"version": settings.build_version}
