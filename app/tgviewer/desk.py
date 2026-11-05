"""Isolated-browser mode (option B).

Each user gets their own Chromium container running the official Telegram Web. The
browser only ever runs on the server; the user's PC receives a screen stream through
the gateway (/desk/). Files:
  downloads  browser -> u<id>/downloads -> watcher -> quarantine -> scan -> clean store -> PC
  uploads    PC -> scan + DLP -> u<id>/uploads (read-only in the browser) -> Telegram Web
"""
import asyncio
import base64
import json
import logging
import os
import shutil
import ssl
from pathlib import Path
from typing import NamedTuple

import httpx

from .config import settings

log = logging.getLogger(__name__)
BROWSERS_DIR = settings.data_dir / "browsers"  # volume shared with the browser containers
TEMP_SUFFIXES = (".crdownload", ".part", ".tmp", ".download")

# Internal hop on the user's private Docker network; KasmVNC uses a self-signed certificate.
UPSTREAM_SSL = ssl.create_default_context()
UPSTREAM_SSL.check_hostname = False
UPSTREAM_SSL.verify_mode = ssl.CERT_NONE


def user_dir(user_id: int) -> Path:
    return BROWSERS_DIR / f"u{user_id}"


def downloads_dir(user_id: int) -> Path:
    return user_dir(user_id) / "downloads"


def uploads_dir(user_id: int) -> Path:
    return user_dir(user_id) / "uploads"


def prepare_user_dirs(user_id: int) -> None:
    # The browser runs as another uid: it writes downloads, and only reads uploads.
    for path, mode in ((user_dir(user_id), 0o755), (downloads_dir(user_id), 0o777), (uploads_dir(user_id), 0o755)):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)


def chromium_policy() -> dict:
    url = settings.browser_launch_url
    policy = {
        "DownloadDirectory": "/home/kasm-user/tgv-downloads",
        "PromptForDownloadLocation": False,
        "AllowFileSelectionDialogs": True,
        "DefaultBrowserSettingEnabled": False,
        "CommandLineFlagSecurityWarningsEnabled": False,
        "PrintingEnabled": False,
        "DeveloperToolsAvailability": 2,
        "PasswordManagerEnabled": False,
        "AutofillAddressEnabled": False,
        "AutofillCreditCardEnabled": False,
        "BrowserSignin": 0,
        "SyncDisabled": True,
        "BrowserAddPersonEnabled": False,
        "BrowserGuestModeEnabled": False,
        "ExtensionInstallBlocklist": ["*"],
        "SafeBrowsingProtectionLevel": 0,  # needs Google; blocked by the egress allowlist
        "HomepageLocation": url,
        "RestoreOnStartup": 4,
        "RestoreOnStartupURLs": [url],
        "URLBlocklist": ["file://*", "chrome://extensions", "chrome://flags", "chrome://inspect"],
        # The browser's network is internal; the egress proxy is its only way out.
        "DnsOverHttpsMode": "off",
        "WebRtcIPHandling": "disable_non_proxied_udp",
        "BackgroundModeEnabled": False,
        # Google services are outside the allowlist anyway; switch their background calls off.
        "ComponentUpdatesEnabled": False,
        "MetricsReportingEnabled": False,
        "SearchSuggestEnabled": False,
        "SpellCheckServiceEnabled": False,
        "TranslateEnabled": False,
        "NetworkPredictionOptions": 2,
        "UrlKeyedAnonymizedDataCollectionEnabled": False,
    }
    if settings.browser_telegram_only:
        # Second layer next to the egress allowlist: other sites don't even start loading.
        policy["URLBlocklist"] = ["*"]
        policy["URLAllowlist"] = ["web.telegram.org", "telegram.org", "t.me", "telegram.me", "telegram.dog", "chrome://*"]
    if settings.browser_proxy:
        policy["ProxySettings"] = {"ProxyMode": "fixed_servers", "ProxyServer": settings.browser_proxy,
                                   "ProxyBypassList": "<-loopback>"}
    return policy


def write_policy() -> None:
    empty = BROWSERS_DIR / "_empty"  # mounted read-only over the browser's ~/Downloads
    empty.mkdir(parents=True, exist_ok=True)
    os.chmod(empty, 0o555)
    directory = BROWSERS_DIR / "_policy"
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / "tgv.json.tmp"
    tmp.write_text(json.dumps(chromium_policy(), indent=2))
    os.chmod(tmp, 0o644)
    os.replace(tmp, directory / "tgv.json")
    os.chmod(directory, 0o755)


class Endpoint(NamedTuple):
    host: str
    port: int
    password: str

    @property
    def authorization(self) -> str:
        return "Basic " + base64.b64encode(f"kasm_user:{self.password}".encode()).decode()


class DeskManager:
    """Talks to the browser-manager service; the gateway itself has no Docker access."""

    def __init__(self) -> None:
        self._endpoints: dict[int, Endpoint] = {}
        self._manager: httpx.AsyncClient | None = None
        self._upstream: httpx.AsyncClient | None = None
        self._locks: dict[int, asyncio.Lock] = {}

    def _mgr(self) -> httpx.AsyncClient:
        if self._manager is None:
            self._manager = httpx.AsyncClient(base_url=settings.manager_url, timeout=90, trust_env=False,
                                              headers={"X-Manager-Token": settings.manager_token})
        return self._manager

    def upstream(self) -> httpx.AsyncClient:
        if self._upstream is None:
            self._upstream = httpx.AsyncClient(verify=UPSTREAM_SSL, timeout=httpx.Timeout(30, connect=10),
                                               trust_env=False)
        return self._upstream

    async def endpoint(self, user_id: int) -> Endpoint:
        if ep := self._endpoints.get(user_id):
            return ep
        return await self.ensure(user_id)

    def forget(self, user_id: int) -> None:
        self._endpoints.pop(user_id, None)

    async def ensure(self, user_id: int) -> Endpoint:
        """Asks the manager to (re)create/start the browser; refreshes the cached address."""
        async with self._locks.setdefault(user_id, asyncio.Lock()):
            prepare_user_dirs(user_id)
            r = await self._mgr().post(f"/browsers/{user_id}/ensure")
            r.raise_for_status()
            data = r.json()
            ep = Endpoint(data["host"], int(data["port"]), data["password"])
            self._endpoints[user_id] = ep
            return ep

    async def status(self, user_id: int) -> str:
        r = await self._mgr().get(f"/browsers/{user_id}")
        r.raise_for_status()
        return r.json()["status"]

    async def restart(self, user_id: int) -> None:
        r = await self._mgr().post(f"/browsers/{user_id}/restart")
        if r.status_code != 404:
            r.raise_for_status()

    async def destroy(self, user_id: int) -> None:
        """Removes the browser, its profile (the Telegram Web login) and the user's file folders."""
        self._endpoints.pop(user_id, None)
        r = await self._mgr().delete(f"/browsers/{user_id}")
        r.raise_for_status()
        await asyncio.to_thread(shutil.rmtree, user_dir(user_id), True)


desk = DeskManager()


async def watch_downloads() -> None:
    """Picks up finished downloads from every user's browser and sends them to scanning."""
    from . import files

    seen: dict[Path, tuple[int, float]] = {}
    while True:
        try:
            for folder in BROWSERS_DIR.glob("u*/downloads"):
                try:
                    user_id = int(folder.parent.name[1:])
                except ValueError:
                    continue
                for path in folder.iterdir():
                    if not path.is_file() or path.name.startswith(".") or path.name.endswith(TEMP_SUFFIXES):
                        continue
                    st = path.stat()
                    signature = (st.st_size, st.st_mtime)
                    if seen.get(path) != signature:  # wait until it stops changing
                        seen[path] = signature
                        continue
                    seen.pop(path, None)
                    await files.ingest_browser_download(user_id, path)
        except Exception:
            log.exception("download watcher error")
        await asyncio.sleep(2)
