"""Per-user Telegram clients (Telethon), login flow and session storage.

The session's auth key gives full access to the account, so it is stored only
encrypted (crypto.py) and decrypted in memory when the client starts.
MVP: all clients run in this process; per-user worker isolation is phase 2.
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Chat, UpdateMessageReactions, User as TgUser
from telethon.utils import get_peer_id

from .audit import audit
from .config import settings
from .crypto import decrypt, encrypt
from .db import SessionLocal
from .hub import hub
from .models import TgSession
from .util import spawn

log = logging.getLogger(__name__)
PENDING_TTL = 600


class TelegramNotConfigured(Exception):
    pass


class NotLinked(Exception):
    pass


@dataclass
class _Pending:
    client: TelegramClient
    phone: str
    phone_code_hash: str
    created: float = field(default_factory=time.monotonic)
    # QR login: the current token, how often it was renewed, and the task that waits for the scan
    qr: object = None
    qr_round: int = 0
    qr_task: asyncio.Task | None = None


def _proxy() -> dict | None:
    """TELEGRAM_PROXY=http://egress:3130 -> Telethon proxy settings (HTTP CONNECT)."""
    if not settings.telegram_proxy:
        return None
    parts = urlsplit(settings.telegram_proxy)
    return {"proxy_type": parts.scheme or "http", "addr": parts.hostname, "port": parts.port or 3130}


# Where Telegram delivered a login code (SentCodeType*), and how it can resend it (CodeType*).
_SENT_TO = {"App": "app", "Sms": "sms", "SmsWord": "sms", "SmsPhrase": "sms", "FirebaseSms": "sms",
            "FragmentSms": "fragment", "Call": "call", "FlashCall": "call", "MissedCall": "call",
            "EmailCode": "email", "SetUpEmailRequired": "email_setup"}
_NEXT = {"Sms": "sms", "Call": "call", "FlashCall": "call", "MissedCall": "call", "FragmentSms": "fragment"}


def code_info(sent) -> dict:
    kind = type(getattr(sent, "type", None)).__name__.removeprefix("SentCodeType")
    nxt = getattr(sent, "next_type", None)
    return {"sent_to": _SENT_TO.get(kind, "other"),
            "next": _NEXT.get(type(nxt).__name__.removeprefix("CodeType")) if nxt else None,
            "timeout": getattr(sent, "timeout", None)}


def mask_phone(phone: str) -> str:
    digits = phone.lstrip("+")
    return "+" + digits[:3] + "*" * max(len(digits) - 5, 0) + digits[-2:]


def chat_kind(entity) -> str:
    if isinstance(entity, TgUser):
        return "bot" if entity.bot else "private"
    if isinstance(entity, Channel):
        return "channel" if entity.broadcast else "group"
    return "group"


def can_write(entity) -> bool:
    """Whether this account may post in the chat (so the UI shows a message box only where it works)."""
    if isinstance(entity, TgUser):
        return not getattr(entity, "deleted", False)
    if isinstance(entity, Channel):
        if entity.creator:
            return True
        if getattr(entity, "left", False):
            return False
        if entity.broadcast:  # a channel: only admins with the right to post
            return bool(entity.admin_rights and entity.admin_rights.post_messages)
        if entity.admin_rights:
            return True
        return not any(r and r.send_messages for r in (entity.banned_rights, entity.default_banned_rights))
    if isinstance(entity, Chat):  # basic group
        if entity.deactivated or entity.left:
            return False
        if entity.creator or entity.admin_rights:
            return True
        return not (entity.default_banned_rights and entity.default_banned_rights.send_messages)
    return False  # ChatForbidden / ChannelForbidden: no access any more


def display_name(entity) -> str:
    if entity is None:
        return ""
    if title := getattr(entity, "title", None):
        return title
    parts = [getattr(entity, "first_name", None), getattr(entity, "last_name", None)]
    return " ".join(p for p in parts if p) or getattr(entity, "username", None) or str(getattr(entity, "id", ""))


class TelegramManager:
    def __init__(self) -> None:
        self._clients: dict[int, TelegramClient] = {}
        self._pending: dict[int, _Pending] = {}
        self._entities: dict[int, dict[int, object]] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    def _lock(self, user_id: int) -> asyncio.Lock:
        return self._locks.setdefault(user_id, asyncio.Lock())

    def _new_client(self, session: str = "") -> TelegramClient:
        if not settings.telegram_configured:
            raise TelegramNotConfigured()
        return TelegramClient(StringSession(session), settings.tg_api_id, settings.tg_api_hash,
                              device_model="TG Viewer gateway", system_version="Linux",
                              app_version="0.1", proxy=_proxy(), catch_up=True)

    def _attach(self, user_id: int, client: TelegramClient) -> None:
        async def on_new_message(event) -> None:
            hub.publish(user_id, {"type": "message", "chat_id": event.chat_id})
            if settings.auto_scan:
                from .autoscan import on_message  # avoids an import cycle
                spawn(on_message(user_id, event))

        async def on_reactions(update) -> None:  # someone reacted: refresh that chat in the UI
            hub.publish(user_id, {"type": "message", "chat_id": get_peer_id(update.peer)})

        client.add_event_handler(on_new_message, events.NewMessage())
        client.add_event_handler(on_reactions, events.Raw(types=UpdateMessageReactions))
        self._clients[user_id] = client

    async def start_all(self) -> None:
        """Connect every linked user's client at startup, so messages are scanned as they
        arrive even when nobody has the page open."""
        if not settings.telegram_configured:
            return
        async with SessionLocal() as db:
            user_ids = list((await db.execute(select(TgSession.user_id))).scalars())
        for user_id in user_ids:
            try:
                await self.client(user_id)
                log.info("telegram client online for user %s", user_id)
            except NotLinked:
                pass
            except Exception:
                log.exception("could not start telegram client for user %s", user_id)

    async def is_linked(self, user_id: int) -> TgSession | None:
        async with SessionLocal() as db:
            return await db.get(TgSession, user_id)

    async def client(self, user_id: int) -> TelegramClient:
        async with self._lock(user_id):
            client = self._clients.get(user_id)
            if client is not None:
                if not client.is_connected():
                    await client.connect()
                return client
            row = await self.is_linked(user_id)
            if row is None:
                raise NotLinked()
            client = self._new_client(decrypt(row.session_enc, f"tg-session:{user_id}"))
            await client.connect()
            if not await client.is_user_authorized():
                await client.disconnect()
                await self._forget(user_id)
                audit("telegram.session_revoked", user_id=user_id)
                raise NotLinked()
            self._attach(user_id, client)
            return client

    # login flow ----------------------------------------------------------
    async def send_code(self, user_id: int, phone: str) -> dict:
        await self._drop_pending(user_id)
        client = self._new_client()
        await client.connect()
        try:
            sent = await client.send_code_request(phone)
        except Exception:
            await client.disconnect()
            raise
        self._pending[user_id] = _Pending(client, phone, sent.phone_code_hash)
        info = code_info(sent)
        audit("telegram.code_requested", user_id=user_id, phone=mask_phone(phone), sent_to=info["sent_to"])
        return info

    async def resend_code(self, user_id: int) -> dict:
        """Ask Telegram to deliver the code the next way it offers (usually SMS or a call)."""
        from telethon.tl.functions.auth import ResendCodeRequest

        p = self._get_pending(user_id)
        sent = await p.client(ResendCodeRequest(p.phone, p.phone_code_hash))
        p.phone_code_hash = sent.phone_code_hash
        info = code_info(sent)
        audit("telegram.code_resent", user_id=user_id, phone=mask_phone(p.phone), sent_to=info["sent_to"])
        return info

    async def qr_start(self, user_id: int) -> None:
        """Log in by QR code instead of phone + code: the user scans it in their Telegram app
        (Settings → Devices → Link Desktop Device). A background task renews the token (it lives
        about 30 s) and waits for the scan."""
        await self._drop_pending(user_id)
        client = self._new_client()
        await client.connect()
        try:
            qr = await client.qr_login()
        except Exception:
            await client.disconnect()
            raise
        p = _Pending(client, "", "", qr=qr)
        p.qr_task = asyncio.create_task(self._qr_wait_loop(user_id, p))
        self._pending[user_id] = p
        audit("telegram.qr_requested", user_id=user_id)

    async def _qr_wait_loop(self, user_id: int, p: _Pending) -> str:
        from telethon.errors import SessionPasswordNeededError

        while True:
            try:
                await p.qr.wait()  # until the token expires
            except asyncio.TimeoutError:
                await p.qr.recreate()
                p.qr_round += 1
                continue
            except SessionPasswordNeededError:
                return "password"  # 2FA: finished by password(), like the code login
            me = await p.client.get_me()
            p.phone = me.phone or ""
            await self._finish(user_id, p)
            return "done"

    def qr_url(self, user_id: int) -> str:
        return self._get_qr(user_id).qr.url

    async def qr_status(self, user_id: int, wait: float = 10) -> dict:
        """'done', 'password' (2FA needed) or 'waiting' (with the token round, to refresh the image)."""
        p = self._get_qr(user_id)
        # Answer soon after the token renews, so the page shows the new code quickly.
        left = (p.qr.expires - datetime.now(timezone.utc)).total_seconds()
        wait = max(1.0, min(wait, left + 1.5))
        try:
            result = await asyncio.wait_for(asyncio.shield(p.qr_task), wait)
        except asyncio.TimeoutError:
            return {"next": "waiting", "round": p.qr_round}
        return {"next": result, "round": p.qr_round}

    def _get_qr(self, user_id: int) -> _Pending:
        p = self._get_pending(user_id)
        if p.qr is None or p.qr_task is None:
            raise ValueError("Login expired, please start again")
        return p

    def _get_pending(self, user_id: int) -> _Pending:
        p = self._pending.get(user_id)
        if p is None or time.monotonic() - p.created > PENDING_TTL:
            raise ValueError("Login expired, please start again")
        return p

    async def sign_in(self, user_id: int, code: str) -> str:
        """Returns 'done' or 'password' (2FA needed)."""
        from telethon.errors import SessionPasswordNeededError

        p = self._get_pending(user_id)
        try:
            await p.client.sign_in(phone=p.phone, code=code.strip(), phone_code_hash=p.phone_code_hash)
        except SessionPasswordNeededError:
            return "password"
        await self._finish(user_id, p)
        return "done"

    async def password(self, user_id: int, password: str) -> None:
        p = self._get_pending(user_id)
        await p.client.sign_in(password=password)  # sent to Telegram only, never stored
        if not p.phone:  # QR login: the number comes from the account itself
            p.phone = (await p.client.get_me()).phone or ""
        await self._finish(user_id, p)

    async def _finish(self, user_id: int, p: _Pending) -> None:
        self._pending.pop(user_id, None)
        async with SessionLocal() as db:
            await db.merge(TgSession(user_id=user_id, phone_masked=mask_phone(p.phone),
                                     session_enc=encrypt(p.client.session.save(), f"tg-session:{user_id}")))
            await db.commit()
        old = self._clients.pop(user_id, None)
        if old is not None:
            await old.disconnect()
        self._attach(user_id, p.client)
        audit("telegram.linked", user_id=user_id, phone=mask_phone(p.phone))

    async def _drop_pending(self, user_id: int) -> None:
        if p := self._pending.pop(user_id, None):
            if p.qr_task is not None and not p.qr_task.done():
                p.qr_task.cancel()
            await p.client.disconnect()

    async def drop_stale_pending(self) -> None:
        for user_id, p in list(self._pending.items()):
            if time.monotonic() - p.created > PENDING_TTL:
                await self._drop_pending(user_id)

    # unlink --------------------------------------------------------------
    async def unlink(self, user_id: int) -> None:
        await self._drop_pending(user_id)
        try:
            client = await self.client(user_id)
            await client.log_out()  # ends the session on Telegram's side too
        except NotLinked:
            pass
        except Exception:
            log.exception("log_out failed for user %s; removing local session anyway", user_id)
        await self._forget(user_id)
        audit("telegram.unlinked", user_id=user_id)

    async def _forget(self, user_id: int) -> None:
        client = self._clients.pop(user_id, None)
        if client is not None and client.is_connected():
            await client.disconnect()
        self._entities.pop(user_id, None)
        async with SessionLocal() as db:
            await db.execute(delete(TgSession).where(TgSession.user_id == user_id))
            await db.commit()

    # chats ---------------------------------------------------------------
    async def dialogs(self, user_id: int, limit: int = 100) -> list:
        client = await self.client(user_id)
        cache = self._entities.setdefault(user_id, {})
        result = []
        async for d in client.iter_dialogs(limit=limit):
            cache[d.id] = d.entity
            result.append(d)
        return result

    async def entity(self, user_id: int, chat_id: int):
        cache = self._entities.setdefault(user_id, {})
        if chat_id in cache:
            return cache[chat_id]
        client = await self.client(user_id)
        try:
            ent = await client.get_entity(chat_id)
        except ValueError:
            await self.dialogs(user_id)
            ent = cache.get(chat_id)
            if ent is None:
                raise LookupError("chat not found")
        cache[chat_id] = ent
        return ent

    async def shutdown(self) -> None:
        for user_id in list(self._pending):
            await self._drop_pending(user_id)
        for client in list(self._clients.values()):
            await client.disconnect()
        self._clients.clear()


tg = TelegramManager()
