"""Automatic scanning on arrival (client mode).

Every incoming message is handled as soon as Telegram delivers it, even if nobody has the
page open: its links are checked and recorded, and its attachment is downloaded into
quarantine and scanned. When the user opens the chat, verdicts are already there.
"""
import logging

from sqlalchemy import select
from telethon.tl.types import MessageEntityTextUrl

from . import files
from .config import settings
from .crypto import ref
from .db import SessionLocal
from .links import ensure_link
from .models import FileObj
from .telegram import chat_kind
from .urls import extract

log = logging.getLogger(__name__)
MAX_LINKS_PER_MESSAGE = 20


def message_urls(msg) -> list[str]:
    """Visible links, links hidden behind text, and URL buttons (bots, channels)."""
    urls = [u for _, _, u in extract(msg.message or "")]
    urls += [e.url for e in (msg.entities or []) if isinstance(e, MessageEntityTextUrl) and e.url]
    markup = getattr(msg, "reply_markup", None)
    for row in getattr(markup, "rows", None) or []:
        for button in getattr(row, "buttons", None) or []:
            # Older layers: button.url; newer layers: button.type = InlineButtonTypeUrl(url=...)
            url = getattr(button, "url", None) or getattr(getattr(button, "type", None), "url", None)
            if url:
                urls.append(url)
    return list(dict.fromkeys(urls))[:MAX_LINKS_PER_MESSAGE]


def is_picture(msg) -> bool:
    """Photos and picture documents (not SVG, which can carry scripts and always gets the full scan)."""
    mime = (msg.file.mime_type or "") if msg.file else ""
    return bool(msg.photo) or (mime.startswith("image/") and mime != "image/svg+xml" and not msg.sticker)


def should_scan_file(kind: str, size: int, outgoing: bool, picture: bool = False) -> tuple[bool, str]:
    if outgoing and not settings.auto_scan_outgoing:
        return False, "own message"
    if picture and not settings.auto_scan_photos:
        return False, "pictures are checked when the chat is opened"
    if kind not in settings.auto_scan_chats:
        return False, f"automatic scanning is off for {kind} chats"
    if size > settings.auto_scan_max_mb * 2**20:
        return False, f"larger than {settings.auto_scan_max_mb} MB: scanned when opened"
    return True, ""


async def on_message(user_id: int, event) -> None:
    msg = event.message
    try:
        kind = chat_kind(await event.get_chat())
        chat_id = event.chat_id
        if msg.out and not settings.auto_scan_outgoing:
            return
        if urls := message_urls(msg):
            async with SessionLocal() as db:
                chat_ref = ref(f"chat:{user_id}:{chat_id}")
                for url in urls:
                    await ensure_link(db, user_id, url, chat_ref, kind)
                await db.commit()
        if msg.file is not None:
            ok, why = should_scan_file(kind, msg.file.size or 0, msg.out, is_picture(msg))
            if not ok:
                log.debug("not auto-scanning message %s: %s", msg.id, why)
                return
            async with SessionLocal() as db:
                exists = (await db.execute(select(FileObj.id).where(
                    FileObj.user_id == user_id, FileObj.chat_id == chat_id, FileObj.msg_id == msg.id,
                    FileObj.direction == "inbound").limit(1))).scalar_one_or_none()
                if exists is None:
                    await files.start_inbound(db, user_id, chat_id, msg.id)
    except Exception:
        log.exception("automatic scan failed for user %s message %s", user_id, getattr(msg, "id", "?"))
