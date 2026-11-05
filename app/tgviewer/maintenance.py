"""Hourly retention cleanup: clean files, quarantine, links, expired sessions."""
import asyncio
import logging
import shutil
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select

from .config import settings
from .db import SessionLocal
from .desk import BROWSERS_DIR
from .models import FileObj, Link, PendingLogin, WebSession
from .telegram import tg
from .util import utcnow

log = logging.getLogger(__name__)


async def cleanup_once() -> None:
    now = utcnow()
    async with SessionLocal() as db:
        old_clean = (await db.execute(select(FileObj).where(
            FileObj.clean_path != "",
            FileObj.updated_at < now - timedelta(days=settings.clean_retention_days)))).scalars().all()
        for f in old_clean:
            shutil.rmtree(Path(f.clean_path).parent, ignore_errors=True)
            f.clean_path = ""
            if f.status == "clean":
                f.status = "expired"
        old_q = (await db.execute(select(FileObj).where(
            FileObj.q_path != "",
            FileObj.updated_at < now - timedelta(days=settings.quarantine_retention_days)))).scalars().all()
        for f in old_q:
            shutil.rmtree(Path(f.q_path).parent, ignore_errors=True)
            f.q_path = ""
        await db.execute(delete(WebSession).where(WebSession.expires_at < now))
        await db.execute(delete(PendingLogin).where(PendingLogin.expires_at < now))
        await db.execute(delete(Link).where(Link.created_at < now - timedelta(days=settings.link_retention_days)))
        await db.commit()
    await tg.drop_stale_pending()
    # Cached chat icons are refreshed weekly.
    for path in (settings.data_dir / "avatars").glob("u*/*"):
        if path.is_file() and path.stat().st_mtime < time.time() - 7 * 24 * 3600:
            path.unlink(missing_ok=True)
    # Scanned uploads waiting in isolated browsers' Uploads folders don't linger.
    cutoff = time.time() - settings.upload_ttl_hours * 3600
    for path in BROWSERS_DIR.glob("u*/uploads/*"):
        if path.is_file() and path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)


async def run_forever() -> None:
    from .files import recover_stuck_scans

    await recover_stuck_scans(older_than_minutes=0)  # at start-up every unfinished scan is orphaned
    tick = 0
    while True:
        try:
            if tick % 6 == 0:  # hourly
                await cleanup_once()
            await recover_stuck_scans()  # every 10 minutes
        except Exception:
            log.exception("maintenance failed")
        tick += 1
        await asyncio.sleep(600)
