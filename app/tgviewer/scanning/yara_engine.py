"""YARA: built-in rules plus downloaded rule sets (YARA Forge) when available."""
import logging
import threading
from pathlib import Path

import yara

from .result import EngineResult

log = logging.getLogger(__name__)
BUILTIN_DIR = Path(__file__).resolve().parent.parent / "rules"
_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
_rules = None
_status = "not loaded"
_lock = threading.Lock()


def _compile(paths: list[Path]):
    return yara.compile(filepaths={f"r{i}": str(p) for i, p in enumerate(paths)}, externals=_EXTERNALS)


def load(extra_dir: Path | None = None) -> None:
    global _rules, _status
    builtin = sorted(BUILTIN_DIR.glob("*.yar"))
    rules = _compile(builtin)
    status = f"{len(builtin)} built-in rule file(s)"
    if extra_dir and extra_dir.is_dir():
        extra = sorted(extra_dir.rglob("*.yar"))
        if extra:
            try:
                rules = _compile(builtin + extra)
                status += f" + {len(extra)} downloaded"
            except yara.Error as e:
                log.warning("downloaded YARA rules failed to compile, using built-in only: %s", e)
                status += " (downloaded rules failed to compile)"
    with _lock:
        _rules, _status = rules, status


def status() -> str:
    return _status


def _is_high(meta: dict) -> bool:
    severity = str(meta.get("severity", "")).lower()
    try:
        score = int(meta.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    return severity in ("high", "critical") or score >= 80


def scan(path: Path, name: str) -> EngineResult:
    if _rules is None:
        load()
    ext = Path(name).suffix.lower().lstrip(".")
    try:
        matches = _rules.match(str(path), timeout=60, externals={
            "filename": Path(name).name, "filepath": str(path), "extension": ext,
            "filetype": "", "owner": ""})
    except yara.Error as e:
        return EngineResult("yara", "error", str(e)[:200])
    if not matches:
        return EngineResult("yara", "clean", "no rule matched")
    names = ", ".join(m.rule for m in matches[:5])
    verdict = "malicious" if any(_is_high(m.meta) for m in matches) else "suspicious"
    return EngineResult("yara", verdict, f"rules: {names}")
