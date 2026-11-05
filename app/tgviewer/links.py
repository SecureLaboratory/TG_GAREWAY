"""Link checks: on receipt (when a message is shown) and again on click."""
import asyncio
import hashlib

from sqlalchemy.ext.asyncio import AsyncSession

from . import stats
from .config import settings
from .crypto import ref
from .feeds import store
from .models import Link
from .urls import SHORTENERS, has_userinfo, host_of, is_ip, normalize
from .vt import get_vt

# Link verdicts: clean | unknown | suspicious | malicious


def local_verdict(url: str, raw: str = "") -> tuple[str, str]:
    host = host_of(url)
    if store.is_bad_url(url):
        return "malicious", "listed in URLhaus / OpenPhish"
    if bad := store.bad_host(host):
        return "malicious", f"host {bad} listed in URLhaus"
    if raw and has_userinfo(raw):
        return "suspicious", "link hides its real host behind '@'"
    if is_ip(host):
        return "suspicious", "link points to a raw IP address"
    if "xn--" in host:
        return "suspicious", "internationalised (punycode) domain, possible look-alike"
    if host in SHORTENERS:
        return "unknown", "URL shortener: final destination unknown"
    if rank := store.tranco_rank(host):
        return "clean", f"well-known domain (Tranco #{rank})"
    return "unknown", "domain is not in the well-known list"


async def vt_verdict(url: str) -> tuple[str, str] | None:
    """VirusTotal lookups by URL hash and domain (GET only). None if unavailable."""
    try:
        vt = get_vt()
        stats_url = await asyncio.wait_for(vt.url(url), 40)
        stats_dom = await asyncio.wait_for(vt.domain(host_of(url)), 40)
    except Exception:
        return None
    worst = max((s.get("malicious", 0) for s in (stats_url, stats_dom) if s), default=0)
    if worst >= settings.vt_malicious_threshold:
        return "malicious", f"VirusTotal: {worst} engines flag this link"
    if worst:
        return "suspicious", f"VirusTotal: {worst} engine(s) flag this link"
    return None


async def ensure_link(db: AsyncSession, user_id: int, raw: str, chat_ref: str, chat_kind: str) -> Link | None:
    url = normalize(raw)
    if not url:
        return None
    link_id = ref(f"link:{user_id}:{url}")
    link = await db.get(Link, link_id)
    if link:
        return link
    verdict, reason = local_verdict(url, raw)
    link = Link(id=link_id, user_id=user_id, url=url, domain=host_of(url), verdict=verdict,
                reason=reason, chat_ref=chat_ref, chat_kind=chat_kind)
    db.add(link)
    stats.record(db, object_type="url", user_id=user_id, chat_ref=chat_ref, chat_kind=chat_kind,
                 domain=link.domain, url=url, url_hash=hashlib.sha256(url.encode()).hexdigest(),
                 results=[{"engine": "local-feeds", "verdict": verdict, "detail": reason}],
                 flagged=["local-feeds"] if verdict in ("suspicious", "malicious") else [],
                 verdict=verdict, reason=reason)
    return link


async def recheck(link: Link) -> tuple[str, str]:
    """Click-time check: feeds may have updated since the link arrived."""
    verdict, reason = local_verdict(link.url)
    if verdict != "malicious" and settings.vt_enabled:
        if vt := await vt_verdict(link.url):
            verdict, reason = vt
    link.verdict, link.reason = verdict, reason
    return verdict, reason
