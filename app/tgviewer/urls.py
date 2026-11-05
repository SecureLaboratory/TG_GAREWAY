"""URL extraction and normalization (pure helpers, no I/O)."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`​]+")
_TRAILING = ".,;:!?)]}>\"'»…"
_DEFAULT_PORTS = {"http": 80, "https": 443}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "lnkd.in", "t.ly", "v.gd"}


def extract(text: str) -> list[tuple[int, int, str]]:
    """Find URLs in text: (start, end, url) with trailing punctuation trimmed."""
    found = []
    for m in URL_RE.finditer(text or ""):
        url, end = m.group(0), m.end()
        while url and url[-1] in _TRAILING:
            if url[-1] == ")" and url.count("(") >= url.count(")"):
                break
            url, end = url[:-1], end - 1
        if len(url) > 8:
            found.append((m.start(), end, url))
    return found


def normalize(raw: str) -> str | None:
    """Canonical http(s) URL, or None if it isn't a safe web link."""
    raw = (raw or "").strip()
    if not raw or any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        return None
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if scheme not in ("http", "https") or not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    netloc = f"[{host}]" if ":" in host else host
    if port and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def has_userinfo(raw: str) -> bool:
    try:
        return "@" in urlsplit(raw if "://" in raw else "http://" + raw).netloc
    except ValueError:
        return False


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def host_candidates(host: str) -> list[str]:
    """a.b.example.com -> [a.b.example.com, b.example.com, example.com]"""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
