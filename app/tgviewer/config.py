"""Runtime settings, read once from environment variables (see .env.example).

Secrets can also come from files: NAME_FILE=/run/secrets/name (Docker secrets,
docker-compose.secrets.yml), filled from a secret store into memory, so secrets never sit in .env
or on disk.
"""
import ipaddress
import os
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit


def secret(name: str, default: str = "") -> str:
    """NAME_FILE (a secret file) wins over NAME (an environment variable)."""
    path = os.environ.get(f"{name}_FILE", "").strip()
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default).strip()


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "postgresql+asyncpg://tgv:tgv-local@postgres:5432/tgv")
    password = secret("DATABASE_PASSWORD")
    if not password:
        return url
    parts = urlsplit(url)  # replace the password in the URL with the secret one
    netloc = f"{parts.username}:{quote(password, safe='')}@{parts.hostname}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    return int(value) if value else default


def _list(name: str, default: str) -> list[str]:
    return [s.strip().lower() for s in os.environ.get(name, default).split(",") if s.strip()]


def _networks(name: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Comma-separated IPs / CIDRs. A wrong entry stops the start instead of being skipped."""
    try:
        return [ipaddress.ip_network(s, strict=False) for s in _list(name, "")]
    except ValueError as e:
        raise RuntimeError(f"{name}: {e}") from None


class Settings:
    def __init__(self) -> None:
        self.database_url = _database_url()
        self.data_dir = Path(os.environ.get("DATA_DIR", "/data"))
        self.master_key_b64 = secret("MASTER_KEY")

        # browser: each user gets an isolated Chromium with the official Telegram Web (no API ID).
        # client:  our own Telegram client (Telethon); needs TG_API_ID / TG_API_HASH.
        self.access_mode = os.environ.get("ACCESS_MODE", "client").strip().lower()
        self.manager_url = os.environ.get("MANAGER_URL", "http://browser-manager:9000").strip()
        self.manager_token = secret("MANAGER_TOKEN")
        self.browser_subnet_prefix = os.environ.get("BROWSER_SUBNET_PREFIX", "10.213").strip()
        self.browser_launch_url = os.environ.get("BROWSER_LAUNCH_URL", "https://web.telegram.org/a/").strip()
        self.browser_telegram_only = _bool("BROWSER_TELEGRAM_ONLY", True)
        self.browser_proxy = os.environ.get("BROWSER_PROXY", "").strip()  # the egress proxy (host:port)
        # Feeds, signatures and VirusTotal go out only through the egress proxy's service allowlist.
        self.service_proxy = os.environ.get("SERVICE_PROXY", "").strip() or None
        self.upload_ttl_hours = _int("UPLOAD_TTL_HOURS", 24)

        # Telegram application credentials from https://my.telegram.org (client mode only)
        self.tg_api_id = int(secret("TG_API_ID") or 0)
        self.tg_api_hash = secret("TG_API_HASH")
        # MTProto goes out only through the egress proxy, to Telegram's published IP ranges.
        self.telegram_proxy = os.environ.get("TELEGRAM_PROXY", "").strip()  # e.g. http://egress:3130
        # Automatic scanning on arrival (client mode).
        self.auto_scan = _bool("AUTO_SCAN", True)
        self.auto_scan_max_mb = _int("AUTO_SCAN_MAX_MB", 50)
        self.auto_scan_chats = _list("AUTO_SCAN_CHATS", "private,group,bot")  # add "channel" if wanted
        self.auto_scan_outgoing = _bool("AUTO_SCAN_OUTGOING", False)
        # Pictures: checked when a chat is opened, not downloaded on arrival (documents etc. still are).
        self.auto_scan_photos = _bool("AUTO_SCAN_PHOTOS", False)
        # Verified incoming pictures skip ClamAV/YARA: the PC only ever gets a re-encoded copy.
        self.image_fast_path = _bool("IMAGE_FAST_PATH", True)

        self.clamav_host = os.environ.get("CLAMAV_HOST", "clamav")
        self.clamav_port = _int("CLAMAV_PORT", 3310)
        self.clamav_stream_max_mb = _int("CLAMAV_STREAM_MAX_MB", 25)

        # local-only: nothing about files/links leaves; local+vt: adds VirusTotal GET lookups
        self.reputation_mode = os.environ.get("REPUTATION_MODE", "local-only").strip()
        self.vt_api_key = secret("VT_API_KEY")
        self.vt_min_interval = float(os.environ.get("VT_MIN_INTERVAL_SEC", "15"))
        self.vt_malicious_threshold = _int("VT_MALICIOUS_THRESHOLD", 3)

        self.abusech_auth_key = secret("ABUSECH_AUTH_KEY")
        self.feeds_enabled = _bool("FEEDS_ENABLED", True)
        self.feeds_interval_min = _int("FEEDS_INTERVAL_MIN", 60)
        self.feeds_mb_full = _bool("FEEDS_MALWAREBAZAAR_FULL", False)
        self.feeds_yara_forge = _bool("FEEDS_YARA_FORGE", True)
        self.tranco_top = _int("TRANCO_TOP", 100_000)

        self.max_file_mb = _int("MAX_FILE_MB", 100)
        self.cookie_secure = _bool("COOKIE_SECURE", False)
        self.session_hours = _int("SESSION_MAX_HOURS", 8)
        self.session_idle_min = _int("SESSION_IDLE_MIN", 60)
        self.clean_retention_days = _int("CLEAN_RETENTION_DAYS", 7)
        self.quarantine_retention_days = _int("QUARANTINE_RETENTION_DAYS", 30)
        self.link_retention_days = _int("LINK_RETENTION_DAYS", 30)
        self.verdict_cache_hours = _int("VERDICT_CACHE_HOURS", 24)

        self.dlp_block_labels = _list("DLP_BLOCK_LABELS", "Highly Confidential,Strictly Confidential")
        self.dlp_warn_labels = _list("DLP_WARN_LABELS", "Confidential,Internal")
        # Host headers the app answers to (DNS-rebinding protection). Add the real hostname in production.
        self.allowed_hosts = _list("ALLOWED_HOSTS", "127.0.0.1,localhost")
        # Client addresses that may use the admin area through the public address too (IPs / CIDRs).
        # Empty (default): admin area only through the localhost admin entrance (SSH tunnel).
        self.admin_allowed_ips = _networks("ADMIN_ALLOWED_IPS")
        # RFC 9116 security.txt contact, e.g. mailto:security@company.com (empty: not served)
        self.security_contact = os.environ.get("SECURITY_CONTACT", "").strip()
        self.build_version = os.environ.get("TGV_BUILD_VERSION", "dev").strip() or "dev"  # baked into the image

    @property
    def vt_enabled(self) -> bool:
        return self.reputation_mode == "local+vt" and bool(self.vt_api_key)

    @property
    def telegram_configured(self) -> bool:
        return bool(self.tg_api_id and self.tg_api_hash)


settings = Settings()
