"""PDF active content: JavaScript, auto-actions, launch actions, embedded files.

A light pdfid-style keyword scan; '#xx' name obfuscation is decoded first.
"""
import re
from pathlib import Path

from .result import EngineResult

MAX_BYTES = 50 * 2**20
KEYS = {"JavaScript": rb"/JavaScript", "JS": rb"/JS", "OpenAction": rb"/OpenAction", "AA": rb"/AA",
        "Launch": rb"/Launch", "EmbeddedFile": rb"/EmbeddedFile", "XFA": rb"/XFA",
        "RichMedia": rb"/RichMedia", "SubmitForm": rb"/SubmitForm"}
_PATTERNS = {k: re.compile(re.escape(v) + rb"(?![A-Za-z])") for k, v in KEYS.items()}
_HEX_NAME = re.compile(rb"#([0-9A-Fa-f]{2})")


def keywords(data: bytes) -> set[str]:
    data = _HEX_NAME.sub(lambda m: bytes([int(m.group(1), 16)]), data)
    return {k for k, p in _PATTERNS.items() if p.search(data)}


def scan(path: Path) -> EngineResult:
    with open(path, "rb") as f:
        found = keywords(f.read(MAX_BYTES))
    script = found & {"JavaScript", "JS"}
    auto = found & {"OpenAction", "AA"}
    if "Launch" in found or (script and auto):
        return EngineResult("pdf", "suspicious", f"runs code when opened ({', '.join(sorted(found))})")
    if script or found & {"EmbeddedFile", "XFA", "RichMedia"}:
        return EngineResult("pdf", "suspicious", f"active content ({', '.join(sorted(found))})")
    return EngineResult("pdf", "clean", f"no active content{' (' + ', '.join(sorted(found)) + ')' if found else ''}")
