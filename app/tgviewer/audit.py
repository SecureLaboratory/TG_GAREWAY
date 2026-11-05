"""Structured audit events (JSON lines) for a log collector.

Never pass message text here, only metadata and verdicts.
"""
import json
import logging
import sys
import threading

from .config import settings
from .util import utcnow

log = logging.getLogger(__name__)
_lock = threading.Lock()


def audit(event_action: str, /, **fields) -> None:
    record = {"@timestamp": utcnow().isoformat(), "event.action": event_action,
              "service.name": "tg-viewer", **fields}
    line = json.dumps(record, default=str, ensure_ascii=False)
    print(line, file=sys.stdout, flush=True)
    try:
        path = settings.data_dir / "audit" / "audit.jsonl"
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        log.exception("could not write audit log file")
