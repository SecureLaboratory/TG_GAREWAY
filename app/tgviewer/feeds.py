"""Threat-intel lists and signatures, downloaded and checked locally.

Pull, don't push: nothing about employee files or links is sent anywhere.
The service only downloads public lists and answers lookups from memory.
"""
import asyncio
import logging
import os
import re
import shutil
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .config import settings
from .urls import host_candidates, normalize

log = logging.getLogger(__name__)
MAX_FEED_BYTES = 400 * 2**20


@dataclass(frozen=True)
class Feed:
    name: str
    default_url: str  # "{key}" is replaced by ABUSECH_AUTH_KEY
    max_age_h: float

    @property
    def url(self) -> str:
        # Any feed URL can be overridden, e.g. FEED_URL_URLHAUS_HOSTS=... (exact links are
        # on the abuse.ch docs pages after login).
        return os.environ.get(f"FEED_URL_{self.name.upper()}", self.default_url).strip()

    @property
    def needs_key(self) -> bool:
        return "{key}" in self.url


# abuse.ch exports need a free Auth-Key (https://auth.abuse.ch) and are CSV.
FEEDS = [
    Feed("malwarebazaar_recent", "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv", 1),
    Feed("malwarebazaar_full", "", 24 * 7),
    Feed("urlhaus_recent", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", 1),
    Feed("urlhaus_hosts", "", 1),
    Feed("openphish", "https://openphish.com/feed.txt", 6),
    Feed("tranco", "https://tranco-list.eu/top-1m.csv.zip", 24 * 7),
    Feed("yara_forge", "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip", 24),
]
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")
_URL = re.compile(r"https?://[^\s\",]+")


def _enabled(feed: Feed) -> bool:
    if not feed.url:
        return False
    if feed.name == "malwarebazaar_full":
        return settings.feeds_mb_full
    if feed.name == "yara_forge":
        return settings.feeds_yara_forge
    return True


def _redact(text: str) -> str:
    key = settings.abusech_auth_key
    return text.replace(key, "***") if key else text


def _read(path: Path) -> bytes:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            biggest = max(z.infolist(), key=lambda i: i.file_size)
            return z.read(biggest)
    return path.read_bytes()


def _lines(data: bytes):
    for line in data.decode("utf-8", "replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            yield s


class FeedStore:
    def __init__(self) -> None:
        self.mb_hashes: frozenset[bytes] = frozenset()
        self.bad_urls: frozenset[str] = frozenset()
        self.bad_hosts: frozenset[str] = frozenset()
        self.tranco: dict[str, int] = {}
        self._counts: dict[str, int] = {}
        self._errors: dict[str, str] = {}

    @property
    def dir(self) -> Path:
        return settings.data_dir / "feeds"

    # lookups -------------------------------------------------------------
    def is_malware_hash(self, sha256: str) -> bool:
        try:
            return bytes.fromhex(sha256) in self.mb_hashes
        except ValueError:
            return False

    def hash_count(self) -> int:
        return len(self.mb_hashes)

    def is_bad_url(self, url: str) -> bool:
        return url in self.bad_urls

    def bad_host(self, host: str) -> str | None:
        return next((h for h in host_candidates(host) if h in self.bad_hosts), None)

    def tranco_rank(self, host: str) -> int | None:
        ranks = [self.tranco[h] for h in host_candidates(host) if h in self.tranco]
        return min(ranks) if ranks else None

    def status(self) -> list[dict]:
        out = []
        for feed in FEEDS:
            p = self.dir / feed.name
            updated = (datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()
                       if p.exists() else None)
            out.append({"name": feed.name, "enabled": _enabled(feed), "updated": updated,
                        "entries": self._counts.get(feed.name), "error": self._errors.get(feed.name)})
        return out

    # loading -------------------------------------------------------------
    def load_all(self) -> None:
        """Parse downloaded files into lookup sets (blocking; run in a thread)."""
        from .scanning import yara_engine

        # Parsers accept both plain lists and the abuse.ch CSV exports.
        hashes: set[bytes] = set()

        def add_hash(s: str) -> bool:
            m = _SHA256.search(s.lower())
            return bool(m) and (hashes.add(bytes.fromhex(m.group())) or True)
        for name in ("malwarebazaar_recent", "malwarebazaar_full"):
            self._counts[name] = self._load(name, add_hash)

        urls: set[str] = set()

        def add_url(s: str) -> bool:
            m = _URL.search(s)
            u = normalize(m.group()) if m else None
            return bool(u) and (urls.add(u) or True)
        for name in ("urlhaus_recent", "openphish"):
            self._counts[name] = self._load(name, add_url)

        hosts: set[str] = set()

        def add_host(s: str) -> bool:
            parts = s.split()
            return bool(parts) and (hosts.add(parts[-1].lower()) or True)
        self._counts["urlhaus_hosts"] = self._load("urlhaus_hosts", add_host)
        tranco: dict[str, int] = {}

        def add_tranco(s: str) -> bool:
            rank, _, domain = s.partition(",")
            if rank.isdigit() and int(rank) <= settings.tranco_top:
                tranco[domain.strip().lower()] = int(rank)
                return True
            return False
        self._load("tranco", add_tranco)

        self.mb_hashes, self.bad_urls, self.bad_hosts, self.tranco = (
            frozenset(hashes), frozenset(urls), frozenset(hosts), tranco)
        self._counts["tranco"] = len(tranco)

        rules_dir = self._extract_yara()
        yara_engine.load(rules_dir)
        self._counts["yara_forge"] = len(list(rules_dir.rglob("*.yar"))) if rules_dir else 0
        log.info("feeds loaded: %s; yara: %s", self._counts, yara_engine.status())

    def _load(self, name: str, add) -> int:
        path = self.dir / name
        if not path.exists():
            return 0
        n = 0
        try:
            for s in _lines(_read(path)):
                try:
                    n += 1 if add(s) else 0
                except ValueError:
                    pass
        except (OSError, zipfile.BadZipFile) as e:
            self._errors[name] = f"parse failed: {e}"
        return n

    def _extract_yara(self) -> Path | None:
        src = self.dir / "yara_forge"
        dst = self.dir / "yara_forge_rules"
        if not src.exists() or not zipfile.is_zipfile(src):
            return dst if dst.is_dir() else None
        marker = dst / ".source_mtime"
        if marker.exists() and marker.read_text() == str(src.stat().st_mtime):
            return dst
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True)
        with zipfile.ZipFile(src) as z:
            for i, info in enumerate(z.infolist()):
                if info.filename.endswith(".yar") and info.file_size < 100 * 2**20:
                    (dst / f"forge_{i}.yar").write_bytes(z.read(info))
        marker.write_text(str(src.stat().st_mtime))
        return dst

    # updating ------------------------------------------------------------
    async def _download(self, client: httpx.AsyncClient, feed: Feed) -> None:
        url = feed.url
        if feed.needs_key:
            if not settings.abusech_auth_key:
                raise PermissionError("needs ABUSECH_AUTH_KEY (free at https://auth.abuse.ch)")
            url = url.replace("{key}", settings.abusech_auth_key)
        tmp = self.dir / f"{feed.name}.tmp"
        size = 0
        async with client.stream("GET", url) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                async for chunk in r.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_FEED_BYTES:
                        raise ValueError("feed larger than limit")
                    f.write(chunk)
        if size == 0:
            raise ValueError("empty download")
        if feed.url.endswith(".zip") or feed.name == "malwarebazaar_full":
            if not zipfile.is_zipfile(tmp):
                raise ValueError("expected a zip file")
        os.replace(tmp, self.dir / feed.name)

    async def update_due(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        changed = False
        async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15), follow_redirects=True,
                                     proxy=settings.service_proxy, trust_env=False,
                                     headers={"User-Agent": "tg-viewer-feeds/0.1"}) as client:
            for feed in FEEDS:
                path = self.dir / feed.name
                if not _enabled(feed):
                    continue
                if path.exists() and time.time() - path.stat().st_mtime < feed.max_age_h * 3600:
                    continue
                try:
                    await self._download(client, feed)
                    self._errors.pop(feed.name, None)
                    changed = True
                    log.info("feed updated: %s", feed.name)
                except Exception as e:
                    self._errors[feed.name] = _redact(f"{e.__class__.__name__}: {e}")[:200]
                    log.warning("feed %s failed: %s", feed.name, self._errors[feed.name])
        if changed:
            await asyncio.to_thread(self.load_all)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.update_due()
            except Exception:
                log.exception("feed update loop error")
            await asyncio.sleep(settings.feeds_interval_min * 60)


store = FeedStore()
