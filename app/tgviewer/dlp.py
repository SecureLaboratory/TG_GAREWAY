"""Outbound data-loss checks on files employees send. Outbound text isn't inspected."""
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import settings

MAX_TEXT = 5_000_000
TEXT_EXT = {".txt", ".csv", ".tsv", ".md", ".json", ".xml", ".log", ".ini", ".conf", ".cfg", ".yaml",
            ".yml", ".env", ".sql", ".pem", ".key", ".html", ".htm"}
OOXML_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
_OOXML_TEXT_PARTS = re.compile(
    r"^(word/(document|header\d*|footer\d*)\.xml|xl/sharedStrings\.xml|xl/worksheets/sheet\d+\.xml"
    r"|ppt/slides/slide\d+\.xml)$")
_LABEL = re.compile(r'name="MSIP_Label_[0-9a-fA-F-]+_Name"[^>]*>\s*<vt:lpwstr>([^<]+)</vt:lpwstr>')
_TAGS = re.compile(r"<[^>]+>")

RULES_BLOCK = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]
RULES_WARN = [
    ("confidentiality marker", re.compile(
        r"(?i)\b(strictly confidential|confidential|internal use only|internal only|for internal use)\b"
        r"|конфіденційно|для службового користування|конфиденциально")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")),
]
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


@dataclass
class DlpResult:
    action: str                       # allow | warn | block
    findings: list[str] = field(default_factory=list)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def extract(path: Path, mime: str, name: str) -> tuple[str, list[str]]:
    """Text content and sensitivity labels of a file (best effort)."""
    ext = Path(name).suffix.lower()
    if mime.startswith("text/") or ext in TEXT_EXT:
        with open(path, "rb") as f:
            return f.read(MAX_TEXT).decode("utf-8", "replace"), []
    if (ext in OOXML_EXT or "officedocument" in mime) and zipfile.is_zipfile(path):
        parts, labels, total = [], [], 0
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.file_size > MAX_TEXT:
                    continue
                if _OOXML_TEXT_PARTS.match(info.filename):
                    text = _TAGS.sub(" ", z.read(info).decode("utf-8", "replace"))
                    parts.append(text)
                    total += len(text)
                elif info.filename == "docProps/custom.xml":
                    labels += _LABEL.findall(z.read(info).decode("utf-8", "replace"))
                if total > MAX_TEXT:
                    break
        return " ".join(parts), labels
    return "", []


def scan_text(text: str, labels: list[str] | tuple = ()) -> DlpResult:
    block, warn = [], []
    for label in labels:
        key = label.strip().lower()
        if key in settings.dlp_block_labels:
            block.append(f"sensitivity label: {label}")
        elif key in settings.dlp_warn_labels:
            warn.append(f"sensitivity label: {label}")
    block += [name for name, rx in RULES_BLOCK if rx.search(text)]
    warn += [name for name, rx in RULES_WARN if rx.search(text)]
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn(digits):
            warn.append("payment card number")
            break
    if block:
        return DlpResult("block", block + warn)
    return DlpResult("warn", warn) if warn else DlpResult("allow")


def scan(path: Path, mime: str, name: str) -> DlpResult:
    try:
        text, labels = extract(path, mime, name)
    except (OSError, zipfile.BadZipFile) as e:
        return DlpResult("warn", [f"file could not be read for DLP checks ({e.__class__.__name__})"])
    return scan_text(text, labels)
