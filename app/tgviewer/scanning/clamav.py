"""ClamAV via the clamd INSTREAM protocol (TCP)."""
import asyncio
import struct
from pathlib import Path

from ..config import settings
from .result import EngineResult

MEDIA_PREFIXES = ("image/", "video/", "audio/")


def parse_reply(text: str) -> EngineResult:
    text = text.strip()
    if text.endswith(" OK") or text == "stream: OK":
        return EngineResult("clamav", "clean", "no signature matched")
    if text.endswith(" FOUND"):
        name = text.split(": ", 1)[-1][: -len(" FOUND")]
        # Heuristic and PUA hits are signals, not confirmed malware.
        verdict = "suspicious" if name.startswith(("Heuristics.", "PUA.")) else "malicious"
        return EngineResult("clamav", verdict, name)
    if "size limit" in text.lower():
        return EngineResult("clamav", "skipped", "larger than clamd StreamMaxLength")
    return EngineResult("clamav", "error", f"unexpected reply: {text[:120]}")


async def _command(cmd: bytes, payload_path: Path | None = None, timeout: float = 120) -> str:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(settings.clamav_host, settings.clamav_port), 5)
    try:
        writer.write(cmd)
        if payload_path is not None:
            with open(payload_path, "rb") as f:
                while chunk := f.read(1 << 16):
                    writer.write(struct.pack("!L", len(chunk)) + chunk)
                    await writer.drain()
            writer.write(struct.pack("!L", 0))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"\0"), timeout)
        return reply.rstrip(b"\0").decode(errors="replace")
    finally:
        writer.close()


async def scan(path: Path, mime: str) -> EngineResult:
    if path.stat().st_size > settings.clamav_stream_max_mb * 2**20:
        if mime.startswith(MEDIA_PREFIXES):
            return EngineResult("clamav", "skipped", f"media file over {settings.clamav_stream_max_mb} MB")
        return EngineResult("clamav", "suspicious",
                            f"too large for AV scan (> {settings.clamav_stream_max_mb} MB)")
    try:
        reply = await _command(b"zINSTREAM\0", path)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        return EngineResult("clamav", "error", f"ClamAV unavailable ({e.__class__.__name__})")
    return parse_reply(reply)


async def version() -> str | None:
    try:
        return await _command(b"zVERSION\0", timeout=5)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
