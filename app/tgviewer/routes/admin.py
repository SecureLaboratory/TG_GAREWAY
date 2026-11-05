"""Admin statistics: aggregated counts only, never chat content."""
import asyncio
import json

from fastapi import APIRouter, Depends
from sqlalchemy import select

from .. import stats
from ..config import settings
from ..deps import admin_user, get_db
from ..feeds import store
from ..models import User
from ..scanning import clamav, yara_engine

router = APIRouter()


@router.get("/api/admin/stats")
async def admin_stats(days: int = 14, _=Depends(admin_user), db=Depends(get_db)):
    data = await stats.aggregate(db, max(1, min(days, 90)))
    data["ops"] = {
        "clamav": await clamav.version() or "unreachable",
        "yara": yara_engine.status(),
        "reputation_mode": settings.reputation_mode,
        "virustotal": "enabled (hash/URL lookups only)" if settings.vt_enabled else "disabled",
        "feeds": store.status(),
    }
    return data


# Login and admin events for the admin page, from the audit log. Only these fields are shown:
# never Telegram data (phones), never scan details of users' files.
AUDIT_TAIL_BYTES = 2 * 2**20
SHOWN_EVENTS = ("auth.", "admin.")
SHOWN_DETAILS = ("mfa", "next", "role", "path")


def _recent_events(limit: int) -> list[dict]:
    path = settings.data_dir / "audit" / "audit.jsonl"
    try:
        with open(path, "rb") as f:
            size = f.seek(0, 2)
            f.seek(max(0, size - AUDIT_TAIL_BYTES))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except FileNotFoundError:
        return []
    if size > AUDIT_TAIL_BYTES:
        lines = lines[1:]  # the first line may be cut off
    events = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and str(e.get("event.action", "")).startswith(SHOWN_EVENTS):
            events.append(e)
            if len(events) >= limit:
                break
    return events


@router.get("/api/admin/events")
async def admin_events(limit: int = 200, _=Depends(admin_user), db=Depends(get_db)):
    events = await asyncio.to_thread(_recent_events, max(1, min(limit, 500)))
    ids = {e[k] for e in events for k in ("user_id", "actor_id") if isinstance(e.get(k), int)}
    names = dict((await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()) if ids else {}
    return [{
        "time": e.get("@timestamp"), "action": e.get("event.action"),
        "user": names.get(e.get("user_id")) or e.get("username") or "",
        "actor": names.get(e.get("actor_id"), ""), "reason": e.get("reason", ""), "ip": e.get("source_ip") or "",
        "detail": {k: e[k] for k in SHOWN_DETAILS if k in e},
    } for e in events]
