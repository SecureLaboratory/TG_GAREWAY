"""VirusTotal client: lookups only.

Hard rule: no file, and no file content, is ever
sent to VirusTotal. This client has exactly three GET lookups and an HTTP
guard that rejects any other method or path. There is deliberately no
upload code and no setting to enable one.
"""
import asyncio
import hashlib
import re
import time

import httpx

from .audit import audit
from .config import settings

VT_HOST = "www.virustotal.com"
_ALLOWED_PATHS = (
    re.compile(r"/api/v3/files/[0-9a-f]{64}"),
    re.compile(r"/api/v3/urls/[0-9a-f]{64}"),
    re.compile(r"/api/v3/domains/[a-z0-9.-]{1,253}"),
)


class VTPolicyViolation(RuntimeError):
    pass


async def _guard(request: httpx.Request) -> None:
    path = request.url.path
    if (request.method != "GET" or request.url.host != VT_HOST
            or not any(p.fullmatch(path) for p in _ALLOWED_PATHS)):
        audit("security_violation", component="vt_client", method=request.method,
              host=request.url.host, path=path)
        raise VTPolicyViolation(f"blocked VirusTotal request: {request.method} {path}")


class VTClient:
    def __init__(self, api_key: str, min_interval: float = 15.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._http = httpx.AsyncClient(
            base_url=f"https://{VT_HOST}", headers={"x-apikey": api_key}, timeout=20,
            event_hooks={"request": [_guard]}, transport=transport,
            proxy=None if transport else settings.service_proxy, trust_env=False)
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._min_interval = min_interval

    async def _get(self, path: str) -> dict | None:
        async with self._lock:  # simple rate limit for the API quota
            wait = self._last + self._min_interval - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
            r = await self._http.get(path)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _stats(data: dict | None) -> dict | None:
        if data is None:
            return None
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    async def file(self, sha256: str) -> dict | None:
        sha256 = sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("not a sha256")
        return self._stats(await self._get(f"/api/v3/files/{sha256}"))

    async def url(self, url: str) -> dict | None:
        # Looked up by the URL's SHA-256 ID, so the URL itself isn't disclosed.
        url_id = hashlib.sha256(url.encode()).hexdigest()
        return self._stats(await self._get(f"/api/v3/urls/{url_id}"))

    async def domain(self, domain: str) -> dict | None:
        domain = domain.lower()
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain):
            raise ValueError("not a domain")
        return self._stats(await self._get(f"/api/v3/domains/{domain}"))


_client: VTClient | None = None


def get_vt() -> VTClient:
    global _client
    if _client is None:
        _client = VTClient(settings.vt_api_key, settings.vt_min_interval)
    return _client
