"""Scan events (metadata only) and the aggregates behind the admin statistics page."""
from collections import Counter
from datetime import timedelta
from pathlib import Path

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import audit
from .models import FileObj, ScanEvent, User
from .util import utcnow

BAD = ("malicious", "blocked")


def record(db: AsyncSession, *, object_type: str, user_id: int, direction: str = "inbound",
           chat_ref: str = "", chat_kind: str = "", sha256: str = "", true_type: str = "", name: str = "",
           size: int = 0, domain: str = "", url: str = "", url_hash: str = "", results: list | None = None,
           flagged: list | None = None, verdict: str = "", reason: str = "", scan_ms: int = 0,
           action: str = "") -> None:
    ext = Path(name).suffix.lower()[:16] if name else ""
    db.add(ScanEvent(
        object_type=object_type, direction=direction, user_id=user_id, chat_ref=chat_ref,
        chat_kind=chat_kind, sha256=sha256, true_type=true_type[:255], ext=ext, size=size,
        domain=domain[:255], url_hash=url_hash, full_url=url if verdict not in ("clean", "") else "",
        engine_results=results or [], flagged_engines=flagged or [], final_verdict=verdict,
        reason=reason[:2000], scan_ms=scan_ms, action=action))
    audit(f"scan.{object_type}", user_id=user_id, direction=direction, chat_kind=chat_kind,
          sha256=sha256 or None, ext=ext or None, size=size or None, domain=domain or None,
          verdict=verdict, reason=reason or None, flagged_engines=flagged or None, action=action or None)
    if verdict == "malicious":
        audit("alert.malicious", severity="high", object_type=object_type, user_id=user_id,
              direction=direction, sha256=sha256 or None, domain=domain or None, reason=reason)


async def aggregate(db: AsyncSession, days: int = 14) -> dict:
    since = utcnow() - timedelta(days=days)
    E = ScanEvent
    recent = E.ts >= since

    totals = (await db.execute(
        select(E.object_type, E.direction, E.final_verdict, func.count())
        .where(recent, E.object_type != "click")
        .group_by(E.object_type, E.direction, E.final_verdict))).all()

    day = func.date_trunc("day", E.ts)
    daily = (await db.execute(
        select(day, E.object_type, E.final_verdict, func.count())
        .where(recent, E.object_type != "click")
        .group_by(day, E.object_type, E.final_verdict).order_by(day))).all()

    top_domains = (await db.execute(
        select(E.domain, E.final_verdict, func.count().label("n"))
        .where(recent, E.object_type == "url", E.final_verdict != "clean")
        .group_by(E.domain, E.final_verdict).order_by(func.count().desc()).limit(15))).all()

    types = (await db.execute(
        select(E.true_type, func.count()).where(recent, E.object_type == "file")
        .group_by(E.true_type).order_by(func.count().desc()).limit(15))).all()

    detections = (await db.execute(
        select(E.reason, func.count()).where(recent, E.object_type == "file", E.final_verdict.in_(BAD))
        .group_by(E.reason).order_by(func.count().desc()).limit(15))).all()

    clicks = (await db.execute(
        select(E.action, func.count()).where(recent, E.object_type == "click").group_by(E.action))).all()

    per_user = (await db.execute(
        select(User.username, func.count(),
               func.sum(case((E.final_verdict.in_(BAD), 1), else_=0)),
               func.sum(case((E.final_verdict == "suspicious", 1), else_=0)))
        .join(User, User.id == E.user_id)
        .where(recent, E.object_type.in_(("file", "url")))
        .group_by(User.username).order_by(func.count().desc()))).all()

    engines: Counter = Counter()
    for (flagged,) in (await db.execute(
            select(E.flagged_engines).where(recent, E.object_type == "file"))).all():
        engines.update(flagged or [])

    latency = (await db.execute(
        select(func.percentile_cont(0.5).within_group(E.scan_ms),
               func.percentile_cont(0.95).within_group(E.scan_ms))
        .where(recent, E.object_type == "file", E.scan_ms > 0))).one()

    in_flight = (await db.execute(
        select(func.count()).select_from(FileObj).where(FileObj.status == "scanning"))).scalar_one()

    return {
        "days": days,
        "totals": [{"object_type": t, "direction": d, "verdict": v, "count": n} for t, d, v, n in totals],
        "daily": [{"day": d.date().isoformat(), "object_type": t, "verdict": v, "count": n}
                  for d, t, v, n in daily],
        "top_domains": [{"domain": d, "verdict": v, "count": n} for d, v, n in top_domains],
        "file_types": [{"type": t or "unknown", "count": n} for t, n in types],
        "detections": [{"reason": r, "count": n} for r, n in detections],
        "engines": [{"engine": e, "count": n} for e, n in engines.most_common()],
        "clicks": [{"action": a, "count": n} for a, n in clicks],
        "per_user": [{"username": u, "scanned": n, "blocked": b or 0, "suspicious": s or 0}
                     for u, n, b, s in per_user],
        "latency_ms": {"p50": round(latency[0] or 0), "p95": round(latency[1] or 0)},
        "in_flight": in_flight,
    }
