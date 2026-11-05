"""Request dependencies: database session and the logged-in user."""
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request

from .config import settings
from .db import SessionLocal
from .models import User, WebSession
from .security import token_hash
from .util import utcnow

# __Host- prefix (HTTPS only): the browser guarantees Secure, Path=/ and no Domain (RFC 6265bis).
COOKIE = "__Host-tgv_session" if settings.cookie_secure else "tgv_session"


async def get_db():
    async with SessionLocal() as db:
        yield db


# The admin entrance, two ways in:
# 1. The front door (Caddy) sets this header only on its admin listener, which is bound to
#    127.0.0.1 on the server (SSH tunnel), and strips it on the public listener. The gateway is
#    reachable only through the front door.
# 2. Optional: the client address is in ADMIN_ALLOWED_IPS (operator's choice, empty by default).
#    That address is the real client IP, taken from X-Forwarded-For only via trusted proxies
#    (uvicorn --proxy-headers with FORWARDED_ALLOW_IPS), so a client can't claim it.
ADMIN_CHANNEL_HEADER = "x-tgv-admin-channel"


def client_ip(request) -> str:
    return request.client.host if request.client else ""


def ip_in(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr in net for net in networks)


def via_admin_channel(request) -> bool:
    if request.headers.get(ADMIN_CHANNEL_HEADER) == "1":
        return True
    return bool(settings.admin_allowed_ips) and ip_in(client_ip(request), settings.admin_allowed_ips)


async def _user_from_cookie(request: Request, db) -> User | None:
    user = await user_from_token(db, request.cookies.get(COOKIE))
    if user is not None and user.is_admin and not via_admin_channel(request):
        return None  # admin sessions only work through the admin entrance
    return user


async def user_from_token(db, token: str | None) -> User | None:
    """Validates a session token (also used by the websocket proxy) and refreshes last_seen."""
    if not token:
        return None
    ws = await db.get(WebSession, token_hash(token))
    now = utcnow()
    if ws is None:
        return None
    if ws.expires_at < now or ws.last_seen < now - timedelta(minutes=settings.session_idle_min):
        await db.delete(ws)
        await db.commit()
        return None
    user = await db.get(User, ws.user_id)
    if user is None or user.disabled:
        return None
    ws.last_seen = now
    await db.commit()
    return user


async def current_user(request: Request, db=Depends(get_db)) -> User:
    user = await _user_from_cookie(request, db)
    if user is None:
        raise HTTPException(401, "Not logged in")
    return user


async def optional_user(request: Request, db=Depends(get_db)) -> User | None:
    return await _user_from_cookie(request, db)


ADMIN_NO_TELEGRAM = "Admin accounts manage users and statistics only; they can't use Telegram"

# Date of the current terms and privacy notice (static/i18n.js, "consent.*"). Accepting an older
# version doesn't count: every user is asked again after the text changes. Bump it with the text.
AGREEMENT_DATE = datetime(2026, 11, 5, 7, 30, tzinfo=timezone.utc)


def has_consent(user: User) -> bool:
    return user.consent_at is not None and user.consent_at >= AGREEMENT_DATE


async def telegram_user(user: User = Depends(current_user)) -> User:
    """Everything that touches a Telegram session, chats, files or links."""
    if user.is_admin:
        raise HTTPException(403, ADMIN_NO_TELEGRAM)
    if not has_consent(user):
        raise HTTPException(403, "Please accept the scanning notice first")
    return user


async def require_admin_channel(request: Request) -> None:
    """Outside the admin entrance the admin area doesn't exist (404), before any login check."""
    if not via_admin_channel(request):
        raise HTTPException(404, "Not Found")


async def admin_user(_: None = Depends(require_admin_channel), user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Admins only")
    return user
