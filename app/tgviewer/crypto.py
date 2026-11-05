"""Encryption of secrets at rest (Telegram sessions, TOTP seeds).

MVP stand-in for a secret store / key manager: one AES-256-GCM master key from MASTER_KEY, or
generated once into DATA_DIR/master.key. Each value is bound to its purpose
(associated data), so a ciphertext can't be swapped between users or fields.
"""
import base64
import hashlib
import hmac
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

log = logging.getLogger(__name__)
_key: bytes | None = None


def _load_key() -> bytes:
    global _key
    if _key is not None:
        return _key
    if settings.master_key_b64:
        key = base64.b64decode(settings.master_key_b64)
        if (settings.data_dir / "master.key").exists():
            log.warning("MASTER_KEY is set (e.g. from a secret store) but %s still exists on disk: delete it once "
                        "migrated, or anyone with the disk has the key", settings.data_dir / "master.key")
    elif os.environ.get("REQUIRE_MASTER_KEY", "").lower() in ("1", "true", "yes"):
        # Production: never invent a new key (it couldn't decrypt existing sessions/2FA seeds).
        raise RuntimeError("MASTER_KEY / MASTER_KEY_FILE is required (REQUIRE_MASTER_KEY=true)")
    else:
        path = settings.data_dir / "master.key"
        if path.exists():
            key = base64.b64decode(path.read_text().strip())
        else:
            key = AESGCM.generate_key(bit_length=256)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(base64.b64encode(key).decode())
            log.warning("Generated a new master key at %s. Set MASTER_KEY (e.g. from a secret store) "
                        "for real deployments.", path)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must be 32 bytes, base64-encoded")
    _key = key
    return key


def encrypt(plaintext: str, purpose: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_load_key()).encrypt(nonce, plaintext.encode(), purpose.encode())
    return base64.b64encode(nonce + ct).decode()


def decrypt(token: str, purpose: str) -> str:
    raw = base64.b64decode(token)
    return AESGCM(_load_key()).decrypt(raw[:12], raw[12:], purpose.encode()).decode()


def ref(value: str) -> str:
    """Keyed hash used to count/link things (e.g. chats) without storing what they are."""
    return hmac.new(_load_key(), b"ref:" + value.encode(), hashlib.sha256).hexdigest()[:32]
