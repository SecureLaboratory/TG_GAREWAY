"""Office documents: VBA/XLM macros (oletools) and remote template/object links."""
import re
import zipfile
from pathlib import Path

from oletools.olevba import VBA_Parser

from .result import EngineResult

OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt",
              ".xltm", ".xla", ".xlam", ".ppt", ".pptx", ".pptm", ".pps", ".ppsm", ".rtf", ".mht"}
OFFICE_MIME = ("application/msword", "application/vnd.ms-", "application/x-ole-storage",
               "application/CDFV2", "application/vnd.openxmlformats-officedocument", "text/rtf")
_EXTERNAL_REL = re.compile(
    r'<Relationship\b[^>]*Type="[^"]*(attachedTemplate|oleObject|frame|subDocument)"[^>]*'
    r'Target="(https?://|\\\\)[^"]*"[^>]*TargetMode="External"', re.I)


def applies(mime: str, ext: str) -> bool:
    return ext in OFFICE_EXT or mime.startswith(OFFICE_MIME)


def _remote_refs(path: Path) -> list[str]:
    if not zipfile.is_zipfile(path):
        return []
    found = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.filename.endswith(".rels") and info.file_size < 1_000_000:
                for m in _EXTERNAL_REL.finditer(z.read(info).decode("utf-8", "replace")):
                    found.append(m.group(1))
    return sorted(set(found))


def scan(path: Path) -> EngineResult:
    try:
        remote = _remote_refs(path)
    except (zipfile.BadZipFile, OSError):
        remote = []
    if remote:
        return EngineResult("oletools", "suspicious", f"loads remote content: {', '.join(remote)}")
    try:
        vp = VBA_Parser(str(path))
    except Exception as e:  # oletools raises its own types for non-Office files
        return EngineResult("oletools", "skipped", f"not parsed ({e.__class__.__name__})")
    try:
        if not vp.detect_vba_macros():
            return EngineResult("oletools", "clean", "no macros")
        found = vp.analyze_macros() or []
        auto = sorted({k for t, k, _ in found if t == "AutoExec"})
        sus = sorted({k for t, k, _ in found if t == "Suspicious"})
        detail = "contains macros"
        if auto:
            detail += f"; auto-run: {', '.join(auto[:5])}"
        if sus:
            detail += f"; suspicious: {', '.join(sus[:5])}"
        return EngineResult("oletools", "suspicious", detail)
    except Exception as e:
        return EngineResult("oletools", "error", f"analysis failed ({e.__class__.__name__})")
    finally:
        vp.close()
