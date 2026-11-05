"""Attachment workflows.

Inbound:  download into quarantine -> scan -> clean store (images re-encoded).
Outbound: upload into quarantine -> scan -> DLP -> send / warn / block.
Isolated-browser mode: downloads come from the browser folder, uploads go to its Uploads folder.
Files reach the browser only from the clean store, and only after a clean verdict.
"""
import asyncio
import logging
import shutil
from datetime import timedelta
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import dlp, stats
from .audit import audit
from .config import settings
from .crypto import ref
from .db import SessionLocal
from .hub import hub
from .models import FileObj, User
from .scanning import images, pipeline
from .scanning.result import ScanResult
from .telegram import chat_kind, tg
from .util import new_id, safe_name, spawn, utcnow

log = logging.getLogger(__name__)
_downloads = asyncio.Semaphore(3)


def _qdir(direction: str, file_id: str) -> Path:
    return settings.data_dir / "quarantine" / ("in" if direction == "inbound" else "out") / file_id


def _clean_dir(file_id: str) -> Path:
    return settings.data_dir / "clean" / file_id


def serialize(f: FileObj) -> dict:
    return {"id": f.id, "direction": f.direction, "name": f.name, "size": f.size, "status": f.status,
            "reason": f.reason, "mime": f.mime, "clean_mime": f.clean_mime, "results": f.results,
            "dlp_findings": f.dlp_findings, "chat_id": f.chat_id, "msg_id": f.msg_id,
            "source": "browser" if f.chat_kind == "browser" else "telegram",
            "created_at": f.created_at.isoformat() if f.created_at else None}


def _record(db: AsyncSession, f: FileObj, res: ScanResult | None, action: str = "") -> None:
    stats.record(db, object_type="file", direction=f.direction, user_id=f.user_id,
                 chat_ref=ref(f"chat:{f.user_id}:{f.chat_id}"), chat_kind=f.chat_kind,
                 sha256=f.sha256, true_type=f.mime, name=f.name, size=f.size,
                 results=res.results if res else [], flagged=res.flagged_engines if res else [],
                 verdict=res.verdict if res else "error", reason=f.reason,
                 scan_ms=res.ms if res else 0, action=action)


# inbound -----------------------------------------------------------------
async def start_inbound(db: AsyncSession, user_id: int, chat_id: int, msg_id: int) -> FileObj:
    client = await tg.client(user_id)
    entity = await tg.entity(user_id, chat_id)
    msg = await client.get_messages(entity, ids=msg_id)
    if msg is None or msg.file is None:
        raise HTTPException(404, "This message has no file")
    name = msg.file.name or f"{'photo' if msg.photo else 'file'}_{msg_id}{msg.file.ext or ''}"
    f = FileObj(id=new_id(), user_id=user_id, direction="inbound", chat_id=chat_id,
                chat_kind=chat_kind(entity), msg_id=msg_id, name=safe_name(name),
                size=msg.file.size or 0, mime=msg.file.mime_type or "", status="scanning")
    if f.size > settings.max_file_mb * 2**20:
        f.status, f.reason = "too_large", f"larger than {settings.max_file_mb} MB"
    db.add(f)
    await db.commit()
    if f.status == "scanning":
        spawn(_process_inbound(f.id))
    return f


# Background jobs never hold a database connection while downloading or scanning (that can
# take long, and many run at once): load the record, work, then save in a short session.
async def _load(file_id: str) -> FileObj | None:
    async with SessionLocal() as db:
        return await db.get(FileObj, file_id)


async def _save(f: FileObj, res: ScanResult | None, action: str = "") -> None:
    async with SessionLocal() as db:
        f = await db.merge(f)
        _record(db, f, res, action=action)
        await db.commit()
    hub.publish(f.user_id, {"type": "file", "id": f.id, "status": f.status, "chat_id": f.chat_id})


def _failed(f: FileObj, e: Exception, what: str) -> None:
    log.exception("%s failed for %s", what, f.id)
    f.status, f.reason = "error", f"{e.__class__.__name__}: {e}"[:300]


async def _process_inbound(file_id: str) -> None:
    f, res = await _load(file_id), None
    if f is None:
        return
    qdir = _qdir("inbound", file_id)
    try:
        client = await tg.client(f.user_id)
        msg = await client.get_messages(await tg.entity(f.user_id, f.chat_id), ids=f.msg_id)
        if msg is None or msg.file is None:
            raise RuntimeError("the message or file is no longer available")
        qdir.mkdir(parents=True, exist_ok=True)
        async with _downloads:  # automatic scanning can start many downloads at once
            path = Path(await client.download_media(msg, file=str(qdir / f.name)))
        f.q_path = str(path)
        res = await _scan_inbound(f, path)
    except Exception as e:
        _failed(f, e, "inbound scan")
        shutil.rmtree(qdir, ignore_errors=True)
        f.q_path = ""
    await _save(f, res)


async def _scan_inbound(f: FileObj, path: Path) -> ScanResult:
    """Scan a quarantined inbound file; clean files move to the clean store."""
    res = await pipeline.scan_file(path, f.name, will_reencode=True)  # pictures reach the PC re-encoded only
    f.sha256, f.size, f.mime, f.results, f.reason = res.sha256, res.size, res.mime, res.results, res.reason
    status = res.verdict
    if status == "clean":
        status = await _publish_clean(f, path)
    f.status = status
    if status == "clean":
        shutil.rmtree(_qdir("inbound", f.id), ignore_errors=True)
        f.q_path = ""
    return res


# isolated-browser downloads ------------------------------------------------
async def ingest_browser_download(user_id: int, src: Path) -> None:
    """A file finished downloading in the user's isolated browser: quarantine and scan it."""
    async with SessionLocal() as db:
        user = await db.get(User, user_id)
        if user is None or user.disabled or user.is_admin:
            src.unlink(missing_ok=True)
            return
        f = FileObj(id=new_id(), user_id=user_id, direction="inbound", chat_id=0, chat_kind="browser",
                    name=safe_name(src.name), size=src.lstat().st_size, status="scanning")
        qdir = _qdir("inbound", f.id)
        qdir.mkdir(parents=True, exist_ok=True)
        path = qdir / f.name
        await asyncio.to_thread(shutil.move, str(src), path)
        if path.is_symlink() or not path.is_file():  # swapped for a link after the watcher looked
            shutil.rmtree(qdir, ignore_errors=True)
            log.warning("dropped non-regular browser download for user %s", user_id)
            return
        f.q_path = str(path)
        if f.size > settings.max_file_mb * 2**20:
            f.status, f.reason = "too_large", f"larger than {settings.max_file_mb} MB"
            shutil.rmtree(qdir, ignore_errors=True)
            f.q_path = ""
        db.add(f)
        await db.commit()
    hub.publish(user_id, {"type": "file", "id": f.id, "status": f.status, "new": "download"})
    if f.status == "scanning":
        spawn(_process_browser_download(f.id))


async def _process_browser_download(file_id: str) -> None:
    f, res = await _load(file_id), None
    if f is None:
        return
    try:
        res = await _scan_inbound(f, Path(f.q_path))
    except Exception as e:
        _failed(f, e, "browser download scan")
    await _save(f, res)


async def _publish_clean(f: FileObj, path: Path) -> str:
    """Move a clean file into the clean store. Images are re-encoded."""
    cdir = _clean_dir(f.id)
    cdir.mkdir(parents=True, exist_ok=True)
    if f.mime in images.REENCODABLE:
        out = await asyncio.to_thread(images.reencode, path, cdir, Path(f.name).stem)
        if out is None:
            f.reason = "image could not be decoded and re-encoded safely"
            return "suspicious"
        f.clean_path, f.clean_mime = str(out[0]), out[1]
    else:
        dest = cdir / path.name
        shutil.move(str(path), dest)
        f.clean_path, f.clean_mime = str(dest), f.mime
    return "clean"


# outbound ----------------------------------------------------------------
async def start_outbound(db: AsyncSession, user_id: int, chat_id: int, upload: UploadFile,
                         browser: bool = False) -> FileObj:
    """browser=True: deliver into the user's isolated browser (Uploads folder) instead of sending."""
    kind = "browser" if browser else chat_kind(await tg.entity(user_id, chat_id))
    f = FileObj(id=new_id(), user_id=user_id, direction="outbound", chat_id=chat_id,
                chat_kind=kind, name=safe_name(upload.filename or "file"), status="scanning")
    qdir = _qdir("outbound", f.id)
    qdir.mkdir(parents=True, exist_ok=True)
    path = qdir / f.name
    limit, size = settings.max_file_mb * 2**20, 0
    with open(path, "wb") as out:
        while chunk := await upload.read(1 << 20):
            size += len(chunk)
            if size > limit:
                out.close()
                shutil.rmtree(qdir, ignore_errors=True)
                raise HTTPException(413, f"File is larger than {settings.max_file_mb} MB")
            out.write(chunk)
    f.size, f.q_path = size, str(path)
    db.add(f)
    await db.commit()
    spawn(_process_outbound(f.id))
    return f


async def _process_outbound(file_id: str) -> None:
    f, res, action = await _load(file_id), None, ""
    if f is None:
        return
    try:
        path = Path(f.q_path)
        res = await pipeline.scan_file(path, f.name)
        f.sha256, f.mime, f.results, f.reason = res.sha256, res.mime, res.results, res.reason
        if res.verdict != "clean":
            f.status = res.verdict  # we don't send malware or suspicious files out
        else:
            result = await asyncio.to_thread(dlp.scan, path, res.mime, f.name)
            f.dlp_findings, action = result.findings, result.action
            if result.action == "block":
                f.status, f.reason = "dlp_blocked", "; ".join(result.findings)
            elif result.action == "warn":
                f.status, f.reason = "warn", "; ".join(result.findings)
            else:
                await _send(f)
    except Exception as e:
        _failed(f, e, "outbound processing")
    if f.status in ("sent", "ready", "error"):
        shutil.rmtree(_qdir("outbound", f.id), ignore_errors=True)
        f.q_path = ""
    await _save(f, res, action)


async def recover_stuck_scans(older_than_minutes: int = 10) -> int:
    """Files left in 'scanning' (process restarted, job crashed) become 'error' so the user
    can scan again, instead of spinning forever. At start-up every one of them is orphaned."""
    cutoff = utcnow() - timedelta(minutes=older_than_minutes)
    async with SessionLocal() as db:
        stuck = (await db.execute(select(FileObj).where(
            FileObj.status == "scanning", FileObj.updated_at < cutoff))).scalars().all()
        for f in stuck:
            f.status, f.reason = "error", "scan was interrupted, please try again"
        await db.commit()
    for f in stuck:
        hub.publish(f.user_id, {"type": "file", "id": f.id, "status": f.status, "chat_id": f.chat_id})
    if stuck:
        log.warning("recovered %d interrupted scans", len(stuck))
    return len(stuck)


async def _send(f: FileObj) -> None:
    if f.chat_kind == "browser":
        await _deliver_to_browser(f)
        return
    client = await tg.client(f.user_id)
    await client.send_file(await tg.entity(f.user_id, f.chat_id), f.q_path)
    f.status = "sent"
    audit("file.sent", user_id=f.user_id, sha256=f.sha256, size=f.size)


async def _deliver_to_browser(f: FileObj) -> None:
    """Place a scanned upload into the browser's (read-only) Uploads folder."""
    from .desk import prepare_user_dirs, uploads_dir

    prepare_user_dirs(f.user_id)
    dest = uploads_dir(f.user_id) / f.name
    n = 1
    while dest.exists():
        dest = uploads_dir(f.user_id) / f"{Path(f.name).stem} ({n}){Path(f.name).suffix}"
        n += 1
    await asyncio.to_thread(shutil.copyfile, f.q_path, dest)
    dest.chmod(0o644)
    f.status = "ready"
    audit("file.delivered_to_browser", user_id=f.user_id, sha256=f.sha256, size=f.size)


async def confirm_send(db: AsyncSession, f: FileObj) -> None:
    """The user accepted a DLP warning."""
    if f.status != "warn" or not f.q_path:
        raise HTTPException(409, "This file is not waiting for confirmation")
    audit("dlp.warning_overridden", user_id=f.user_id, sha256=f.sha256, findings=f.dlp_findings)
    await _send(f)
    shutil.rmtree(_qdir("outbound", f.id), ignore_errors=True)
    f.q_path = ""
    stats.record(db, object_type="file", direction="outbound", user_id=f.user_id,
                 chat_kind=f.chat_kind, sha256=f.sha256, name=f.name, size=f.size,
                 verdict="clean", reason=f.reason, action="warn_overridden")
    await db.commit()
    hub.publish(f.user_id, {"type": "file", "id": f.id, "status": f.status, "chat_id": f.chat_id})
