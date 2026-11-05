"""Hash reputation: local feeds always; VirusTotal hash lookup only in local+vt mode."""
import asyncio

from ..config import settings
from ..feeds import store
from ..vt import get_vt
from .result import EngineResult


def local_hash(sha256: str) -> EngineResult:
    if store.is_malware_hash(sha256):
        return EngineResult("local-feeds", "malicious", "known malware hash (MalwareBazaar)")
    return EngineResult("local-feeds", "clean", f"not in local feeds ({store.hash_count()} known hashes)")


async def vt_hash(sha256: str) -> EngineResult:
    try:
        stats = await asyncio.wait_for(get_vt().file(sha256), 90)
    except Exception as e:  # VT being down must not block scanning
        return EngineResult("virustotal", "skipped", f"unavailable ({e.__class__.__name__})")
    if stats is None:
        return EngineResult("virustotal", "clean", "hash unknown to VirusTotal (file not uploaded, by design)")
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal >= settings.vt_malicious_threshold:
        return EngineResult("virustotal", "malicious", f"{mal} engines detect this hash")
    if mal or sus:
        return EngineResult("virustotal", "suspicious", f"{mal} malicious / {sus} suspicious detections")
    return EngineResult("virustotal", "clean", "0 detections")
