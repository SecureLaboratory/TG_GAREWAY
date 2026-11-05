"""Real file-type detection (libmagic) and the type policy."""
from pathlib import Path

import magic

from .result import EngineResult

BLOCKED_EXT = {
    ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".msc", ".bat", ".cmd", ".ps1",
    ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".iso", ".img",
    ".vhd", ".vhdx", ".jar", ".reg", ".chm", ".dll", ".sys", ".appx", ".msix", ".appinstaller",
    ".application", ".gadget", ".scf", ".url", ".library-ms", ".settingcontent-ms", ".xll",
    ".apk", ".dmg", ".pkg", ".sh",
}
MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam", ".sldm"}
BLOCKED_MIME = {
    "application/x-dosexec", "application/x-msdownload", "application/vnd.microsoft.portable-executable",
    "application/x-executable", "application/x-pie-executable", "application/x-sharedlib",
    "application/x-mach-binary", "application/x-ms-shortcut", "application/x-msi",
    "application/x-ms-installer", "application/x-iso9660-image", "text/x-msdos-batch",
    "application/hta", "application/java-archive", "application/x-java-archive",
    "application/vnd.android.package-archive",
}
BLOCKED_DESC = ("ms windows shortcut", "pe32", "ms-dos executable", "iso 9660", "windows installer",
                "microsoft disk image")
SUSPICIOUS_MIME = {"text/x-shellscript", "text/x-python", "text/x-perl", "application/javascript",
                   "text/javascript", "image/svg+xml", "text/html", "application/x-powershell"}

_OOXML = ("application/zip", "application/octet-stream", "application/encrypted")
_OLE = ("application/msword", "application/vnd.ms-", "application/x-ole-storage", "application/CDFV2")
EXPECTED = {
    ".pdf": ("application/pdf",),
    ".jpg": ("image/jpeg",), ".jpeg": ("image/jpeg",), ".png": ("image/png",),
    ".gif": ("image/gif",), ".webp": ("image/webp",), ".bmp": ("image/bmp", "image/x-ms-bmp"),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml",) + _OOXML,
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml",) + _OOXML,
    ".pptx": ("application/vnd.openxmlformats-officedocument.presentationml",) + _OOXML,
    ".doc": _OLE, ".xls": _OLE, ".ppt": _OLE,
    ".zip": ("application/zip",),
    ".txt": ("text/", "application/json", "inode/x-empty"), ".csv": ("text/", "application/csv"),
    ".mp4": ("video/",), ".mov": ("video/",), ".mp3": ("audio/",), ".ogg": ("audio/", "video/"),
}


def detect(path: Path) -> tuple[str, str]:
    mime = magic.from_file(str(path), mime=True) or "application/octet-stream"
    desc = magic.from_file(str(path)) or ""
    return mime, desc


def check(path: Path, name: str) -> tuple[EngineResult, str, str]:
    """Return (policy result, mime, description)."""
    mime, desc = detect(path)
    ext = Path(name).suffix.lower()
    d = desc.lower()

    def result(verdict: str, detail: str) -> tuple[EngineResult, str, str]:
        return EngineResult("type-policy", verdict, detail), mime, desc

    if ext in BLOCKED_EXT:
        return result("blocked", f"file type {ext} is not allowed")
    if mime in BLOCKED_MIME or d.startswith("elf ") or any(x in d for x in BLOCKED_DESC):
        return result("blocked", f"executable or disk-image content ({desc[:80]})")
    if ext in MACRO_EXT:
        return result("suspicious", f"macro-enabled Office format {ext}")
    if mime in SUSPICIOUS_MIME:
        return result("suspicious", f"active content ({mime})")
    expected = EXPECTED.get(ext)
    if expected and not mime.startswith(expected):
        return result("suspicious", f"extension {ext} but content is {mime}")
    return result("clean", mime)
