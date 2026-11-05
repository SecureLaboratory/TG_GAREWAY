"""Access-control and authentication tests (OWASP A01 / A07) against the real app + database.

Runs inside the api container (needs the postgres service); skipped elsewhere.
"""
import asyncio
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pyotp
import pytest
from fastapi.routing import APIRoute
from sqlalchemy import delete, select

from tgviewer.config import settings
from tgviewer.crypto import encrypt
from tgviewer.db import SessionLocal, engine, init_db
from tgviewer.main import app
from tgviewer.models import FileObj, Link, ScanEvent, User, WebSession
from tgviewer.routes import admin, auth, chats, desk as desk_routes, gate, users
from tgviewer.security import hash_password, new_session_token, token_hash
from tgviewer.util import new_id, utcnow

H = {"X-TGV": "1"}
PASSWORD = "Correct-Horse-Battery-1"
PUBLIC = {"/api/login", "/api/logout", "/api/version"}  # version: the release number for the login screen
# Well-formed body for every route, so each request reaches its access check (not a 422).
ANY_BODY = {"code": "000000", "password": "x" * 12, "username": "x", "role": "user", "phone": "+10000000", "text": "x"}
PRE_AUTH = {"/api/login/totp", "/api/login/enroll", "/api/login/enroll-qr", "/api/login/new-password"}
TELEGRAM_ROUTES = {"/api/telegram/", "/api/chats", "/api/files/", "/api/events", "/api/desk", "/desk/"}


def _db_available() -> bool:
    async def probe():
        try:
            await init_db(attempts=1)
            return True
        except Exception:
            return False
        finally:
            await engine.dispose()
    return asyncio.run(probe())


pytestmark = pytest.mark.skipif(not _db_available(), reason="needs the postgres service")


def run(coro):
    async def wrapper():
        try:
            return await coro
        finally:
            await cleanup()
            await engine.dispose()
    return asyncio.run(wrapper())


_created: list[int] = []


async def cleanup():
    if not _created:
        return
    async with SessionLocal() as db:
        await db.execute(delete(ScanEvent).where(ScanEvent.user_id.in_(_created)))
        await db.execute(delete(User).where(User.id.in_(_created)))
        await db.commit()
    _created.clear()


async def make_user(admin=False, consent=True, totp=None, must_change=False, disabled=False) -> User:
    async with SessionLocal() as db:
        u = User(username=f"t-{secrets.token_hex(4)}", password_hash=hash_password(PASSWORD), totp_secret_enc="",
                 is_admin=admin, consent_at=utcnow() if consent else None, must_change_password=must_change,
                 disabled=disabled)
        db.add(u)
        await db.flush()
        if totp:
            u.totp_secret_enc = encrypt(totp, f"totp:{u.id}")
        await db.commit()
        _created.append(u.id)
        return u


async def session_for(user: User, last_seen_minutes_ago: int = 0) -> str:
    token, now = new_session_token(), utcnow()
    async with SessionLocal() as db:
        db.add(WebSession(token_hash=token_hash(token), user_id=user.id, created_at=now,
                          last_seen=now - timedelta(minutes=last_seen_minutes_ago),
                          expires_at=now + timedelta(hours=1)))
        await db.commit()
    return token


def client(token: str | None = None, admin_channel: bool = False) -> httpx.AsyncClient:
    # admin_channel: as if the request came through the front door's admin entrance
    headers = {"X-TGV-Admin-Channel": "1"} if admin_channel else {}
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers=headers)
    if token:
        c.cookies.set("tgv_session", token)
    return c


def concrete(path: str) -> str:
    return (path.replace("{chat_id}", "1").replace("{msg_id}", "1").replace("{user_id}", "1")
            .replace("{file_id}", "f" * 32).replace("{link_id}", "l" * 32))


def all_routes() -> list[tuple[str, str]]:
    # Collected from the routers themselves (newer FastAPI wraps included routers in app.routes).
    found = []
    for router in (auth.router, chats.router, gate.router, admin.router, users.router, desk_routes.router):
        for r in router.routes:
            if isinstance(r, APIRoute) and r.path.startswith(("/api/", "/go/")):
                found += [(m, r.path) for m in r.methods]
    assert len(found) >= 30, "route discovery broke; the sweeps below would test nothing"
    return found


# ---------------------------------------------------------------- A01: every route needs a session
def test_every_route_requires_login():
    async def t():
        async with client() as c:
            for method, path in all_routes():
                if path in PUBLIC:
                    continue
                r = await c.request(method, concrete(path), headers=H, json=ANY_BODY)
                if path.startswith("/go/"):
                    assert r.status_code == 303 and r.headers["location"] == "/", path
                elif path.startswith("/api/admin/"):
                    assert r.status_code == 404, f"{method} {path} outside admin entrance -> {r.status_code}"
                else:
                    assert r.status_code == 401, f"{method} {path} -> {r.status_code}"
        async with client(admin_channel=True) as c:  # through the admin entrance: still needs a login
            for method, path in all_routes():
                if path.startswith("/api/admin/"):
                    r = await c.request(method, concrete(path), headers=H, json=ANY_BODY)
                    assert r.status_code == 401, f"{method} {path} -> {r.status_code}"
    run(t())


def test_admin_cannot_touch_telegram():
    async def t():
        admin = await make_user(admin=True)
        async with client(await session_for(admin), admin_channel=True) as c:
            checked = 0
            for method, path in all_routes():
                if any(path.startswith(p) for p in TELEGRAM_ROUTES):
                    r = await c.request(method, concrete(path), headers=H, json=ANY_BODY)
                    assert r.status_code == 403, f"admin {method} {path} -> {r.status_code}"
                    checked += 1
            assert checked >= 20
            assert (await c.get("/go/" + "l" * 32)).status_code == 403
    run(t())


def test_user_cannot_use_admin_api():
    async def t():
        user = await make_user()
        token = await session_for(user)
        for channel, expected in ((True, 403), (False, 404)):
            async with client(token, admin_channel=channel) as c:
                for method, path in all_routes():
                    if path.startswith("/api/admin/"):
                        r = await c.request(method, concrete(path), headers=H, json={"username": "x", "role": "admin"})
                        assert r.status_code == expected, f"user {method} {path} (channel={channel}) -> {r.status_code}"
    run(t())


def test_admin_only_through_admin_entrance():
    async def t():
        admin, user = await make_user(admin=True, totp=pyotp.random_base32()), await make_user(totp=pyotp.random_base32())
        login = {"username": admin.username, "password": PASSWORD}
        async with client() as c:  # public entrance
            unknown = await c.post("/api/login", headers=H, json={"username": "nobody-x", "password": PASSWORD})
            r = await c.post("/api/login", headers=H, json=login)
            assert r.status_code == 401 and r.json() == unknown.json()  # looks like a wrong password
            assert (await c.post("/api/login", headers=H, json={"username": user.username, "password": PASSWORD})).json() == {"next": "totp"}
            for path in ("/admin", "/static/admin.js", "/static/admin.html", "/api/admin/stats", "/api/admin/users"):
                assert (await c.get(path)).status_code == 404, path
        async with client(admin_channel=True) as c:  # admin entrance
            assert (await c.post("/api/login", headers=H, json=login)).json() == {"next": "totp"}
            assert (await c.get("/admin")).status_code == 200
            assert (await c.get("/static/admin.js")).status_code == 200
        token = await session_for(admin)
        async with client(token) as c:
            assert (await c.get("/api/me")).status_code == 401  # admin session unusable publicly
        async with client(token, admin_channel=True) as c:
            assert (await c.get("/api/me")).status_code == 200
            assert (await c.get("/api/admin/users")).status_code == 200
        async with SessionLocal() as db:  # a blocked public admin login doesn't count towards lockout
            assert (await db.get(User, admin.id)).failed_logins == 0
    run(t())


def test_admin_through_public_address_from_allowed_ips(monkeypatch):
    """ADMIN_ALLOWED_IPS opens the admin area on the public listener for those client addresses only."""
    import ipaddress
    monkeypatch.setattr(settings, "admin_allowed_ips", [ipaddress.ip_network("203.0.113.0/24")])

    def from_ip(ip: str, token: str | None = None) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 5000)), base_url="http://127.0.0.1")
        if token:
            c.cookies.set("tgv_session", token)
        return c

    async def t():
        admin, user = await make_user(admin=True, totp=pyotp.random_base32()), await make_user()
        login = {"username": admin.username, "password": PASSWORD}
        async with from_ip("203.0.113.7") as c:  # listed address, no admin-listener header
            assert (await c.post("/api/login", headers=H, json=login)).json() == {"next": "totp"}
            assert (await c.get("/admin")).status_code == 200
            assert (await c.get("/static/admin.js")).status_code == 200
        async with from_ip("198.51.100.7") as c:  # any other address: the admin area doesn't exist
            assert (await c.post("/api/login", headers=H, json=login)).status_code == 401
            for path in ("/admin", "/static/admin.js", "/api/admin/users"):
                assert (await c.get(path)).status_code == 404, path
        token = await session_for(admin)
        async with from_ip("203.0.113.7", token) as c:
            assert (await c.get("/api/admin/users")).status_code == 200
        async with from_ip("198.51.100.7", token) as c:
            assert (await c.get("/api/me")).status_code == 401  # the same session is useless elsewhere
        async with from_ip("203.0.113.7", await session_for(user)) as c:
            assert (await c.get("/api/admin/users")).status_code == 403  # the list grants no admin rights
    run(t())


def test_no_cross_user_access_to_files_and_links():
    async def t():
        alice, bob = await make_user(), await make_user()
        fid = new_id()
        clean_dir = settings.data_dir / "clean" / fid
        clean_dir.mkdir(parents=True, exist_ok=True)
        (clean_dir / "a.txt").write_text("alice's file")
        async with SessionLocal() as db:
            db.add(FileObj(id=fid, user_id=alice.id, direction="inbound", chat_id=1, msg_id=1, name="a.txt",
                           status="clean", clean_path=str(clean_dir / "a.txt"), clean_mime="text/plain"))
            db.add(FileObj(id=fid[::-1], user_id=alice.id, direction="outbound", chat_id=1, name="w.txt",
                           status="warn", q_path=str(clean_dir / "a.txt")))
            db.add(Link(id="a" * 32, user_id=alice.id, url="https://example.com/", domain="example.com",
                        verdict="unknown"))
            await db.commit()
        async with client(await session_for(bob)) as c:
            assert (await c.get(f"/api/files/{fid}")).status_code == 404
            assert (await c.get(f"/api/files/{fid}/content")).status_code == 404
            assert (await c.post(f"/api/files/{fid[::-1]}/send", headers=H)).status_code == 404
            assert (await c.get("/go/" + "a" * 32)).status_code == 404
        async with client(await session_for(alice)) as c:
            assert (await c.get(f"/api/files/{fid}")).status_code == 200
            r = await c.get(f"/api/files/{fid}/content")
            assert r.status_code == 200 and r.text == "alice's file"
            assert "attachment" in r.headers["content-disposition"]
            assert (await c.get("/go/" + "a" * 32)).status_code in (200, 303)
    run(t())


def test_consent_disabled_and_idle_sessions():
    async def t():
        fresh = await make_user(consent=False)
        async with client(await session_for(fresh)) as c:
            assert (await c.get("/api/chats")).status_code == 403
            assert (await c.get("/api/me")).status_code == 200
        off = await make_user(disabled=True)
        async with client(await session_for(off)) as c:
            assert (await c.get("/api/me")).status_code == 401
        idle = await make_user()
        async with client(await session_for(idle, last_seen_minutes_ago=settings.session_idle_min + 5)) as c:
            assert (await c.get("/api/me")).status_code == 401
    run(t())


# ---------------------------------------------------------------- A07: login flow
def test_first_login_enroll_change_password_and_replay():
    async def t():
        user = await make_user(must_change=True)
        async with client() as c:
            r = await c.post("/api/login", headers=H, json={"username": user.username, "password": PASSWORD})
            assert r.json() == {"next": "enroll"}
            assert "tgv_session" not in c.cookies
            assert (await c.get("/api/me")).status_code == 401  # pre-auth cookie is not a session
            secret = (await c.get("/api/login/enroll")).json()["secret"]
            assert (await c.post("/api/login/enroll", headers=H, json={"code": "000000"})).status_code == 401
            r = await c.post("/api/login/enroll", headers=H, json={"code": pyotp.TOTP(secret).now()})
            assert r.json() == {"next": "change_password"}
            assert (await c.get("/api/me")).status_code == 401
            assert (await c.get("/api/login/enroll")).status_code == 400  # secret no longer retrievable
            r = await c.post("/api/login/new-password", headers=H, json={"password": PASSWORD})
            assert r.status_code == 400  # must differ from the temporary one
            r = await c.post("/api/login/new-password", headers=H, json={"password": "my-own-new-password"})
            assert r.status_code == 200
            assert (await c.get("/api/me")).status_code == 200
            await c.post("/api/logout", headers=H)
            assert (await c.get("/api/me")).status_code == 401

        async with client() as c:
            r = await c.post("/api/login", headers=H, json={"username": user.username, "password": "my-own-new-password"})
            assert r.json() == {"next": "totp"}
            used = pyotp.TOTP(secret).now()
            assert (await c.post("/api/login/totp", headers=H, json={"code": used})).status_code == 401  # replay
            nxt = pyotp.TOTP(secret).at(time.time() + 30)
            assert (await c.post("/api/login/totp", headers=H, json={"code": nxt})).status_code == 200
            assert (await c.get("/api/me")).status_code == 200
    run(t())


def test_no_account_enumeration_and_lockout():
    async def t():
        user = await make_user(totp=pyotp.random_base32())
        async with client() as c:
            unknown = await c.post("/api/login", headers=H, json={"username": "nobody-xyz", "password": "x"})
            wrong = await c.post("/api/login", headers=H, json={"username": user.username, "password": "x"})
            assert unknown.status_code == wrong.status_code == 401
            assert unknown.json() == wrong.json()
            for _ in range(5):
                await c.post("/api/login", headers=H, json={"username": user.username, "password": "x"})
            locked = await c.post("/api/login", headers=H, json={"username": user.username, "password": PASSWORD})
            assert locked.status_code == 401 and locked.json() == unknown.json()  # locked looks the same
    run(t())


def test_admin_user_management_never_exposes_secrets():
    async def t():
        admin, target = await make_user(admin=True), await make_user(totp=pyotp.random_base32())
        target_token = await session_for(target)
        async with client(await session_for(admin), admin_channel=True) as c:
            users = (await c.get("/api/admin/users")).json()
            blob = str(users).lower()
            for secret_field in ("password_hash", "totp_secret", "session_enc", "phone"):
                assert secret_field not in blob
            r = await c.post("/api/admin/users", headers=H, json={"username": f"n-{secrets.token_hex(3)}", "role": "user"})
            assert r.status_code == 200 and len(r.json()["temporary_password"]) >= 12
            async with SessionLocal() as db:
                new = (await db.execute(select(User).where(User.username == r.json()["username"]))).scalar_one()
                _created.append(new.id)
                assert new.must_change_password and not new.totp_secret_enc
            me = next(u for u in users if u["is_self"])
            assert (await c.post(f"/api/admin/users/{me['id']}/disable", headers=H)).status_code == 400
            assert (await c.post(f"/api/admin/users/{target.id}/reset-password", headers=H)).status_code == 200
        async with client(target_token) as c:
            assert (await c.get("/api/me")).status_code == 401  # reset ended the target's sessions
    run(t())


# ---------------------------------------------------------------- CSRF, body limits, host header
def test_csrf_size_and_host_guards():
    async def t():
        user = await make_user()
        async with client(await session_for(user)) as c:
            assert (await c.post("/api/consent")).status_code == 403  # no X-TGV header
            r = await c.post("/api/consent", headers={**H, "content-length": str(10**9)}, content=b"")
            assert r.status_code == 413
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://evil.example") as c:
            assert (await c.get("/healthz")).status_code == 400
    run(t())


# ---------------------------------------------------------------- isolated-browser mode
def test_desk_guards():
    from starlette.testclient import TestClient
    from starlette.testclient import WebSocketDenialResponse
    from starlette.websockets import WebSocketDisconnect

    async def setup():
        return await make_user(), await make_user(admin=True)
    user, admin = asyncio.run(setup())
    user_token, admin_token = asyncio.run(session_for(user)), asyncio.run(session_for(admin))

    async def http_checks():
        browser_mode = settings.access_mode == "browser"
        async with client(user_token) as c:
            # KasmVNC's direct download folder would bypass scanning: always refused.
            assert (await c.get("/desk/Downloads/x.exe")).status_code == 404
            assert (await c.get("/desk/downloads/")).status_code == 404
            # The stream client comes from the gateway image (not the container); no path escapes.
            # In client mode the whole isolated-browser surface is switched off (404).
            r = await c.get("/desk/index.html")
            assert (r.status_code == 200 and "KasmVNC" in r.text) if browser_mode else r.status_code == 404
            for bad in ("/desk/..%2f..%2fetc%2fpasswd", "/desk/%2e%2e/%2e%2e/etc/passwd", "/desk/../../app/tgviewer/config.py"):
                assert (await c.get(bad)).status_code == 404, bad
        # Requests coming from an isolated browser's network are refused outright.
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.213.7.2", 5000)),
                                     base_url="http://127.0.0.1") as c:
            assert (await c.get("/healthz")).status_code == 403
            assert (await c.post("/api/login", headers=H, json=ANY_BODY)).status_code == 403
    asyncio.run(http_checks())

    tc = TestClient(app, base_url="http://127.0.0.1")
    good_origin = {"origin": "http://127.0.0.1"}

    def ws_result(headers: dict, token: str | None) -> str:
        cookies = {"tgv_session": token} if token else {}
        try:
            with tc.websocket_connect("/desk/websockify", headers=headers, cookies=cookies):
                return "accepted"
        except (WebSocketDenialResponse, WebSocketDisconnect):
            return "denied"

    assert ws_result({}, user_token) == "denied"                               # no Origin
    assert ws_result({"origin": "http://evil.example"}, user_token) == "denied" # cross-site
    assert ws_result(good_origin, None) == "denied"                             # not logged in
    assert ws_result(good_origin, admin_token) == "denied"                      # admins never
    run(asyncio.sleep(0))  # cleanup of created users
