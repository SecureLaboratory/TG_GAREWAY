"""Small shared helpers."""
import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
_tasks: set[asyncio.Task] = set()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


def spawn(coro) -> asyncio.Task:
    """Run a background coroutine, keeping a reference so it isn't garbage-collected."""
    task = asyncio.create_task(coro)
    _tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _tasks.discard(t)
        if not t.cancelled() and t.exception():
            log.error("background task failed", exc_info=t.exception())

    task.add_done_callback(_done)
    return task


def safe_name(name: str, default: str = "file") -> str:
    """A filename that is safe to use on disk: no path parts, no odd characters."""
    base = Path(name.replace("\\", "/")).name.strip()
    base = re.sub(r"[^\w.\- ()\[\]]", "_", base)[:120].strip(". ")
    return base or default
