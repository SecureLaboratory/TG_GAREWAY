"""Admin user management.

Admins create users, reset passwords and 2FA, lock/unlock and disable accounts.
They never see secrets: no Telegram sessions, no TOTP keys, no real passwords.
Generated passwords are temporary and must be changed at the user's first login.
"""
import logging
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select

from ..audit import audit
from ..config import settings
from ..deps import admin_user, get_db
from ..desk import desk
from ..models import PendingLogin, TgSession, User, WebSession
from ..security import hash_password
from ..telegram import tg
from ..util import utcnow

log = logging.getLogger(__name__)
router = APIRouter()


class NewUserIn(BaseModel):
    username: str
    role: str = "user"  # user | admin


def _temp_password() -> str:
    return secrets.token_urlsafe(12)


async def _end_sessions(db, user_id: int) -> None:
    await db.execute(delete(WebSession).where(WebSession.user_id == user_id))
    await db.execute(delete(PendingLogin).where(PendingLogin.user_id == user_id))


async def _target(db, admin: User, user_id: int) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "You can't change your own account here (use the CLI)")
    return user


@router.get("/api/admin/users")
async def list_users(admin: User = Depends(admin_user), db=Depends(get_db)):
    linked = set((await db.execute(select(TgSession.user_id))).scalars())
    now = utcnow()
    return [{
        "id": u.id, "username": u.username, "role": "admin" if u.is_admin else "user",
        "disabled": u.disabled, "totp_enrolled": bool(u.totp_secret_enc),
        "must_change_password": u.must_change_password,
        "locked": bool(u.locked_until and u.locked_until > now),
        "telegram_linked": u.id in linked,  # status only; the session itself is never exposed
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "is_self": u.id == admin.id,
    } for u in (await db.execute(select(User).order_by(User.id))).scalars()]


@router.post("/api/admin/users")
async def create_user(body: NewUserIn, admin: User = Depends(admin_user), db=Depends(get_db)):
    username = body.username.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,64}", username):
        raise HTTPException(400, "Username: 3-64 characters, letters, digits, dot, dash, underscore")
    if body.role not in ("user", "admin"):
        raise HTTPException(400, "Role must be user or admin")
    if (await db.execute(select(User).where(User.username == username))).scalar_one_or_none():
        raise HTTPException(409, "User already exists")
    password = _temp_password()
    user = User(username=username, password_hash=hash_password(password), totp_secret_enc="",
                is_admin=body.role == "admin", must_change_password=True)
    db.add(user)
    await db.commit()
    audit("admin.user_created", actor_id=admin.id, user_id=user.id, role=body.role)
    return {"id": user.id, "username": username, "temporary_password": password}


@router.post("/api/admin/users/{user_id}/reset-password")
async def reset_password(user_id: int, admin: User = Depends(admin_user), db=Depends(get_db)):
    user = await _target(db, admin, user_id)
    password = _temp_password()
    user.password_hash, user.must_change_password = hash_password(password), True
    user.failed_logins, user.locked_until = 0, None
    await _end_sessions(db, user.id)
    await db.commit()
    audit("admin.password_reset", actor_id=admin.id, user_id=user.id)
    return {"temporary_password": password}


@router.post("/api/admin/users/{user_id}/reset-2fa")
async def reset_2fa(user_id: int, admin: User = Depends(admin_user), db=Depends(get_db)):
    user = await _target(db, admin, user_id)
    user.totp_secret_enc, user.totp_last_step = "", 0
    await _end_sessions(db, user.id)
    await db.commit()
    audit("admin.2fa_reset", actor_id=admin.id, user_id=user.id)
    return {"ok": True}


@router.post("/api/admin/users/{user_id}/unlock")
async def unlock(user_id: int, admin: User = Depends(admin_user), db=Depends(get_db)):
    user = await _target(db, admin, user_id)
    user.failed_logins, user.locked_until = 0, None
    await db.commit()
    audit("admin.user_unlocked", actor_id=admin.id, user_id=user.id)
    return {"ok": True}


@router.post("/api/admin/users/{user_id}/disable")
async def disable(user_id: int, admin: User = Depends(admin_user), db=Depends(get_db)):
    user = await _target(db, admin, user_id)
    user.disabled = True
    await _end_sessions(db, user.id)
    await db.commit()
    # Offboarding: the Telegram session is revoked (destroyed, never used or exposed).
    if settings.access_mode == "browser":
        try:
            await desk.destroy(user.id)  # isolated browser + its Telegram Web profile
        except Exception:
            log.exception("could not remove the browser of user %s", user.id)
    else:
        await tg.unlink(user.id)
    audit("admin.user_disabled", actor_id=admin.id, user_id=user.id)
    return {"ok": True}


@router.post("/api/admin/users/{user_id}/enable")
async def enable(user_id: int, admin: User = Depends(admin_user), db=Depends(get_db)):
    user = await _target(db, admin, user_id)
    user.disabled, user.failed_logins, user.locked_until = False, 0, None
    await db.commit()
    audit("admin.user_enabled", actor_id=admin.id, user_id=user.id)
    return {"ok": True}
