"""Runs every engine on a quarantined file and combines the results."""
import asyncio
import hashlib
import time
from datetime import timedelta
from pathlib import Path

from ..config import settings
from ..db import SessionLocal
from ..models import FileVerdict
from ..util import utcnow
from . import archive, clamav, filetype, images, office, pdf, reputation, yara_engine
from .result import EngineResult, ScanResult, combine

_sem = asyncio.Semaphore(2)


def _sha256(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


async def _timed(fn, *args):
    start = time.monotonic()
    if asyncio.iscoroutinefunction(fn):
        result = await fn(*args)
    else:
        result = await asyncio.to_thread(fn, *args)
    ms = int((time.monotonic() - start) * 1000)
    for r in result if isinstance(result, list) else [result]:
        r.ms = r.ms or ms
    return result


async def _cache_get(key: str) -> FileVerdict | None:
    async with SessionLocal() as db:
        row = await db.get(FileVerdict, key)
    if row is None:
        return None
    fresh = row.scanned_at > utcnow() - timedelta(hours=settings.verdict_cache_hours)
    return row if fresh or row.verdict in ("malicious", "blocked") else None


async def _cache_put(key: str, res: ScanResult) -> None:
    async with SessionLocal() as db:
        await db.merge(FileVerdict(key=key, verdict=res.verdict, reason=res.reason, mime=res.mime,
                                   results=res.results, scanned_at=utcnow()))
        await db.commit()


def is_verified_picture(policy: EngineResult, mime: str) -> bool:
    """Real raster picture by content (not by name), and the type policy found nothing."""
    return policy.verdict == "clean" and mime in images.REENCODABLE


async def scan_file(path: Path, name: str, use_cache: bool = True, will_reencode: bool = False) -> ScanResult:
    """will_reencode: the caller only ever passes on a re-encoded copy of pictures (inbound),
    so verified pictures may take the light path (IMAGE_FAST_PATH)."""
    fast_allowed = will_reencode and settings.image_fast_path
    async with _sem:
        start = time.monotonic()
        sha256, size = await asyncio.to_thread(_sha256, path)
        key = f"{sha256}:{Path(name).suffix.lower()[:16]}" + (":fast" if fast_allowed else "")
        if use_cache and (hit := await _cache_get(key)):
            return ScanResult(sha256, size, hit.mime, hit.verdict, hit.reason, hit.results,
                              int((time.monotonic() - start) * 1000), cached=True)

        t0 = time.monotonic()
        policy, mime, desc = await asyncio.to_thread(filetype.check, path, name)
        policy.ms = int((time.monotonic() - t0) * 1000)
        results: list[EngineResult] = [policy]
        ext = Path(name).suffix.lower()

        if archive.is_zip(path, mime, name):
            results += await _timed(archive.scan_zip, path)
        elif mime in archive.OTHER_ARCHIVES:
            results.append(EngineResult("archive", "suspicious", f"{desc[:60]}: archive type not unpacked yet"))
        if fast_allowed and is_verified_picture(policy, mime):
            # The PC only ever gets a freshly re-encoded copy (and a picture that can't be
            # re-encoded is held), so antivirus/YARA add almost nothing here.
            skip = "verified picture: re-encoded instead (image fast path)"
            results += [EngineResult("clamav", "skipped", skip), EngineResult("yara", "skipped", skip)]
        else:
            results.append(await _timed(clamav.scan, path, mime))
            results.append(await _timed(yara_engine.scan, path, name))
        if office.applies(mime, ext):
            results.append(await _timed(office.scan, path))
        if mime == "application/pdf":
            results.append(await _timed(pdf.scan, path))
        results.append(reputation.local_hash(sha256))
        if settings.vt_enabled:
            results.append(await _timed(reputation.vt_hash, sha256))
        results.append(EngineResult("sandbox", "skipped", "not configured yet (CAPE planned)"))

        verdict, reason = combine(results)
        res = ScanResult(sha256, size, mime, verdict, reason, [r.as_dict() for r in results],
                         int((time.monotonic() - start) * 1000))
        if not any(r.verdict == "error" for r in results):  # don't cache "AV was down"
            await _cache_put(key, res)
        return res
