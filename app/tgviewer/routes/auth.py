"""Local login in two steps, logout, consent. SSO replaces this later (TODO).

Step 1: username + password  -> short-lived pre-auth cookie (path /api/login only).
Step 2: authenticator code   -> full session.
A user without an authenticator yet enrolls during step 2 (QR code shown in the
browser, confirmed with one code), so admins only hand out a password.
"""
from datetime import timedelta

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import delete, select

from ..audit import audit
from ..config import settings
from ..crypto import decrypt, encrypt
from ..deps import COOKIE, client_ip, current_user, get_db, has_consent, via_admin_channel
from ..models import PendingLogin, User, WebSession
from ..security import (DUMMY_HASH, hash_password, new_session_token, new_totp_secret, token_hash, totp_uri,
                        verify_password, verify_totp)
from ..util import utcnow

router = APIRouter()
MAX_FAILURES = 5
LOCK_MINUTES = 15
PRE_COOKIE = "__Secure-tgv_preauth" if settings.cookie_secure else "tgv_preauth"
PRE_PATH = "/api/login"
PRE_MINUTES = 5
MAX_CODE_TRIES = 5
DENIED = f"Wrong username or password (after {MAX_FAILURES} failed attempts, wait {LOCK_MINUTES} minutes)"


class PasswordIn(BaseModel):
    username: str
    password: str


class CodeIn(BaseModel):
    code: str


async def _register_failure(db, user: User, ip: str, reason: str) -> None:
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILURES:
        user.locked_until, user.failed_logins = utcnow() + timedelta(minutes=LOCK_MINUTES), 0
        audit("auth.account_locked", user_id=user.id, source_ip=ip)
    await db.commit()
    audit("auth.login_failed", user_id=user.id, reason=reason, source_ip=ip)


@router.post("/api/login")
async def login_password(body: PasswordIn, request: Request, response: Response, db=Depends(get_db)):
    username = body.username.strip().lower()[:64]
    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    now = utcnow()
    ip = client_ip(request)

    # One answer for unknown, disabled, locked and wrong password: no account enumeration.
    denied = HTTPException(401, DENIED)
    if user is None or user.disabled:
        verify_password(DUMMY_HASH, body.password)  # same timing as a real check
        audit("auth.login_failed", username=username, reason="unknown_or_disabled", source_ip=ip)
        raise denied
    if user.is_admin and not via_admin_channel(request):
        # Admins log in only through the admin entrance (localhost on the server). Same answer as
        # a wrong password, and no lockout counting (nobody can lock admins out from outside).
        verify_password(DUMMY_HASH, body.password)
        audit("auth.login_failed", user_id=user.id, reason="admin_outside_admin_channel", source_ip=ip)
        raise denied
    if user.locked_until and user.locked_until > now:
        verify_password(DUMMY_HASH, body.password)
        audit("auth.login_failed", user_id=user.id, reason="locked", source_ip=ip)
        raise denied
    if not verify_password(user.password_hash, body.password):
        await _register_failure(db, user, ip, "bad_password")
        raise denied

    enroll = not user.totp_secret_enc
    token = new_session_token()
    await db.execute(delete(PendingLogin).where(PendingLogin.user_id == user.id))
    db.add(PendingLogin(
        token_hash=token_hash(token), user_id=user.id, expires_at=now + timedelta(minutes=PRE_MINUTES),
        enroll_secret_enc=encrypt(new_totp_secret(), f"totp-enroll:{user.id}") if enroll else ""))
    await db.commit()
    response.set_cookie(PRE_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=PRE_MINUTES * 60, path=PRE_PATH)
    audit("auth.password_ok", user_id=user.id, next="enroll" if enroll else "totp", source_ip=ip)
    return {"next": "enroll" if enroll else "totp"}


async def _pending(request: Request, db) -> tuple[PendingLogin, User]:
    token = request.cookies.get(PRE_COOKIE)
    p = await db.get(PendingLogin, token_hash(token), with_for_update=True) if token else None
    # Row lock: two parallel requests with the same code can't both pass (TOTP replay race).
    user = await db.get(User, p.user_id, with_for_update=True) if p else None
    if (p is None or p.expires_at < utcnow() or user is None or user.disabled
            or (user.locked_until and user.locked_until > utcnow())):
        raise HTTPException(401, "Login expired, please enter your password again")
    return p, user


async def _code_failed(db, p: PendingLogin, user: User, ip: str) -> HTTPException:
    p.attempts += 1
    if p.attempts >= MAX_CODE_TRIES:
        await db.delete(p)
    await _register_failure(db, user, ip, "bad_totp")
    return HTTPException(401, "Wrong code" if p.attempts < MAX_CODE_TRIES
                         else "Too many wrong codes, please enter your password again")


async def _complete(db, request: Request, response: Response, p: PendingLogin, user: User, mfa: str) -> dict:
    now = utcnow()
    await db.delete(p)
    user.failed_logins, user.locked_until = 0, None
    token = new_session_token()
    db.add(WebSession(token_hash=token_hash(token), user_id=user.id, created_at=now, last_seen=now,
                      expires_at=now + timedelta(hours=settings.session_hours)))
    await db.commit()
    response.set_cookie(COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.session_hours * 3600, path="/")
    response.delete_cookie(PRE_COOKIE, path=PRE_PATH)
    audit("auth.login", user_id=user.id, mfa=mfa, source_ip=client_ip(request))
    return {"ok": True}


async def _after_mfa(db, request: Request, response: Response, p: PendingLogin, user: User, mfa: str) -> dict:
    """Second factor passed. A temporary (admin-issued) password must be replaced first."""
    if user.must_change_password:
        p.mfa_done, p.enroll_secret_enc, p.attempts = True, "", 0
        p.expires_at = utcnow() + timedelta(minutes=PRE_MINUTES)
        await db.commit()
        return {"next": "change_password"}
    return await _complete(db, request, response, p, user, mfa)


@router.post("/api/login/totp")
async def login_totp(body: CodeIn, request: Request, response: Response, db=Depends(get_db)):
    p, user = await _pending(request, db)
    if p.mfa_done:
        raise HTTPException(400, "Code already verified")
    if p.enroll_secret_enc:
        raise HTTPException(400, "Set up your authenticator first")
    step = verify_totp(decrypt(user.totp_secret_enc, f"totp:{user.id}"), body.code, user.totp_last_step)
    if step is None:
        raise await _code_failed(db, p, user, client_ip(request))
    user.totp_last_step = step
    return await _after_mfa(db, request, response, p, user, "totp")


class NewPasswordIn(BaseModel):
    password: str


@router.post("/api/login/new-password")
async def login_new_password(body: NewPasswordIn, request: Request, response: Response, db=Depends(get_db)):
    p, user = await _pending(request, db)
    if not p.mfa_done or not user.must_change_password:
        raise HTTPException(400, "No password change pending")
    if len(body.password) < 12:
        raise HTTPException(400, "Use at least 12 characters")
    if len(body.password) > 256:
        raise HTTPException(400, "Password is too long")
    if verify_password(user.password_hash, body.password):
        raise HTTPException(400, "Choose a password different from the temporary one")
    user.password_hash, user.must_change_password = hash_password(body.password), False
    audit("auth.password_changed", user_id=user.id, source_ip=client_ip(request))
    return await _complete(db, request, response, p, user, "totp")


def _enroll_secret(p: PendingLogin, user: User) -> str:
    if not p.enroll_secret_enc or p.mfa_done:
        raise HTTPException(400, "Authenticator is already set up")
    return decrypt(p.enroll_secret_enc, f"totp-enroll:{user.id}")


@router.get("/api/login/enroll")
async def enroll_info(request: Request, db=Depends(get_db)):
    p, user = await _pending(request, db)
    secret = _enroll_secret(p, user)
    return {"secret": secret, "account": f"TG Viewer ({user.username})"}


@router.get("/api/login/enroll-qr")
async def enroll_qr(request: Request, db=Depends(get_db)):
    p, user = await _pending(request, db)
    img = qrcode.make(totp_uri(_enroll_secret(p, user), user.username),
                      image_factory=qrcode.image.svg.SvgFillImage, box_size=12, border=2)
    return Response(img.to_string(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@router.post("/api/login/enroll")
async def enroll_confirm(body: CodeIn, request: Request, response: Response, db=Depends(get_db)):
    p, user = await _pending(request, db)
    secret = _enroll_secret(p, user)
    step = verify_totp(secret, body.code, 0)
    if step is None:
        raise await _code_failed(db, p, user, client_ip(request))
    user.totp_secret_enc, user.totp_last_step = encrypt(secret, f"totp:{user.id}"), step
    audit("auth.totp_enrolled", user_id=user.id, source_ip=client_ip(request))
    return await _after_mfa(db, request, response, p, user, "totp_enrolled")


@router.post("/api/logout")
async def logout(request: Request, response: Response, db=Depends(get_db)):
    if token := request.cookies.get(COOKIE):
        await db.execute(delete(WebSession).where(WebSession.token_hash == token_hash(token)))
        await db.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/api/me")
async def me(user: User = Depends(current_user)):
    return {"username": user.username, "is_admin": user.is_admin, "consent": has_consent(user),
            "access_mode": settings.access_mode,
            # Retention periods shown in the terms and privacy notice (they come from the settings).
            "policy": {"clean_days": settings.clean_retention_days,
                       "quarantine_days": settings.quarantine_retention_days,
                       "link_days": settings.link_retention_days,
                       "session_hours": settings.session_hours}}


@router.post("/api/consent")
async def consent(user: User = Depends(current_user), db=Depends(get_db)):
    db_user = await db.get(User, user.id)
    db_user.consent_at = utcnow()
    await db.commit()
    audit("user.consent_accepted", user_id=user.id)
    return {"ok": True}
