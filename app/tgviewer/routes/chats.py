"""Telegram linking, chats, messages, attachments and live events."""
import asyncio
import json
import re
import time
from pathlib import Path

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from telethon.tl.functions.messages import SendReactionRequest
from telethon.tl.types import (DocumentAttributeSticker, MessageEntityTextUrl, ReactionCustomEmoji, ReactionEmoji,
                               ReactionPaid)

from .. import files
from ..scanning import images
from ..audit import audit
from ..config import settings
from ..crypto import ref
from ..deps import telegram_user, get_db
from ..hub import hub
from ..links import ensure_link
from ..models import FileObj, User
from ..telegram import can_write, chat_kind, display_name, tg
from ..urls import extract, host_of

router = APIRouter()


# linking -------------------------------------------------------------------
class PhoneIn(BaseModel):
    phone: str


class CodeIn(BaseModel):
    code: str


class PasswordIn(BaseModel):
    password: str


@router.get("/api/telegram/status")
async def tg_status(user: User = Depends(telegram_user)):
    row = await tg.is_linked(user.id)
    return {"configured": settings.telegram_configured, "linked": row is not None,
            "phone": row.phone_masked if row else None}


@router.post("/api/telegram/send-code")
async def tg_send_code(body: PhoneIn, user: User = Depends(telegram_user)):
    phone = re.sub(r"[\s()-]", "", body.phone)
    if not re.fullmatch(r"\+?\d{7,15}", phone):
        raise HTTPException(400, "Enter the phone number in international format, e.g. +380...")
    return {"ok": True, **await tg.send_code(user.id, phone)}


@router.post("/api/telegram/resend-code")
async def tg_resend_code(user: User = Depends(telegram_user)):
    try:
        return {"ok": True, **await tg.resend_code(user.id)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/api/telegram/qr/start")
async def tg_qr_start(user: User = Depends(telegram_user)):
    """Link by QR code (Telegram app → Settings → Devices → Link Desktop Device): no code needed."""
    await tg.qr_start(user.id)
    return {"ok": True}


@router.get("/api/telegram/qr.svg")
async def tg_qr_image(user: User = Depends(telegram_user)):
    try:
        url = tg.qr_url(user.id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgFillImage, box_size=10, border=2)
    return Response(img.to_string(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@router.get("/api/telegram/qr/status")
async def tg_qr_status(user: User = Depends(telegram_user)):
    """Waits up to 10 s for the scan: next = done | password | waiting (round changes when the code is renewed)."""
    try:
        return await tg.qr_status(user.id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/api/telegram/sign-in")
async def tg_sign_in(body: CodeIn, user: User = Depends(telegram_user)):
    try:
        return {"next": await tg.sign_in(user.id, body.code)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/api/telegram/password")
async def tg_password(body: PasswordIn, user: User = Depends(telegram_user)):
    try:
        await tg.password(user.id, body.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"next": "done"}


@router.post("/api/telegram/unlink")
async def tg_unlink(user: User = Depends(telegram_user), db=Depends(get_db)):
    await tg.unlink(user.id)
    for f in (await db.execute(select(FileObj).where(FileObj.user_id == user.id))).scalars():
        for p in (f.clean_path, f.q_path):
            if p:
                await asyncio.to_thread(_rmtree, Path(p).parent)
        await db.delete(f)
    await db.commit()
    return {"ok": True}


def _rmtree(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


# chats & messages ------------------------------------------------------------
def _media_info(m) -> dict | None:
    if m.file is None:
        return None
    kind = ("photo" if m.photo else "video" if m.video else "voice" if m.voice else "audio" if m.audio
            else "sticker" if m.sticker else "gif" if m.gif else "document")
    name = m.file.name or f"{kind}_{m.id}{m.file.ext or ''}"
    info = {"kind": kind, "name": name, "size": m.file.size or 0, "mime": m.file.mime_type or ""}
    if kind == "sticker":
        alt = next((a.alt for a in getattr(m.document, "attributes", []) or []
                    if isinstance(a, DocumentAttributeSticker)), "")
        # Static stickers (webp) are shown re-encoded; animated/video ones only as their emoji.
        info.update(emoji=alt or "🏷", animated=info["mime"] != "image/webp")
    return info


REACTION_FALLBACK = {ReactionCustomEmoji: "✨", ReactionPaid: "⭐"}


def _reactions(m) -> list[dict]:
    results = getattr(getattr(m, "reactions", None), "results", None) or []
    out = []
    for r in results:
        emoji = getattr(r.reaction, "emoticon", None) or REACTION_FALLBACK.get(type(r.reaction), "•")
        out.append({"emoji": emoji, "count": r.count, "mine": r.chosen_order is not None,
                    "custom": not isinstance(r.reaction, ReactionEmoji)})
    return out


def _preview(m) -> str:
    if m is None:
        return ""
    if m.message:
        return m.message[:80]
    info = _media_info(m)
    return f"[{info['kind']}]" if info else ""


@router.get("/api/chats")
async def list_chats(user: User = Depends(telegram_user)):
    dialogs = await tg.dialogs(user.id)
    return [{"id": d.id, "name": d.name or "(no name)", "unread": d.unread_count,
             "kind": chat_kind(d.entity), "can_write": can_write(d.entity),
             "date": d.date.isoformat() if d.date else None,
             "preview": _preview(d.message)} for d in dialogs]


async def _segments(db, user_id: int, text: str, entities, chat_ref: str, kind: str) -> list[dict]:
    """Message text split into plain-text and link segments. Links point to /go/<id>."""
    segs, pos = [], 0
    for start, end, url in extract(text):
        link = await ensure_link(db, user_id, url, chat_ref, kind)
        if start > pos:
            segs.append({"t": "text", "v": text[pos:start]})
        if link:
            segs.append({"t": "link", "v": text[start:end], "id": link.id, "verdict": link.verdict,
                         "reason": link.reason})
        else:
            segs.append({"t": "text", "v": text[start:end]})
        pos = end
    if pos < len(text):
        segs.append({"t": "text", "v": text[pos:]})
    for ent in entities or []:  # links hidden behind text
        if isinstance(ent, MessageEntityTextUrl):
            if link := await ensure_link(db, user_id, ent.url, chat_ref, kind):
                segs.append({"t": "link", "v": f" [link: {host_of(link.url)}]", "id": link.id,
                             "verdict": link.verdict, "reason": link.reason})
    return segs


@router.get("/api/chats/{chat_id}/messages")
async def list_messages(chat_id: int, before: int = 0, user: User = Depends(telegram_user), db=Depends(get_db)):
    client = await tg.client(user.id)
    entity = await tg.entity(user.id, chat_id)
    msgs = await client.get_messages(entity, limit=40, max_id=before)
    kind, chat_ref = chat_kind(entity), ref(f"chat:{user.id}:{chat_id}")
    ids = [m.id for m in msgs]
    known: dict[int, FileObj] = {}
    if ids:
        rows = (await db.execute(select(FileObj).where(
            FileObj.user_id == user.id, FileObj.chat_id == chat_id, FileObj.direction == "inbound",
            FileObj.msg_id.in_(ids)).order_by(FileObj.created_at))).scalars()
        known = {f.msg_id: f for f in rows}

    out = []
    for m in reversed(msgs):
        text = m.message or ""
        if getattr(m, "action", None) is not None:
            out.append({"id": m.id, "date": m.date.isoformat(), "service": True,
                        "segments": [{"t": "text", "v": type(m.action).__name__.replace("MessageAction", "")}]})
            continue
        f = known.get(m.id)
        out.append({
            "id": m.id, "date": m.date.isoformat(), "out": bool(m.out),
            "sender": "You" if m.out else display_name(m.sender) or display_name(entity),
            "segments": await _segments(db, user.id, text, m.entities, chat_ref, kind),
            "media": _media_info(m), "file": files.serialize(f) if f else None, "reactions": _reactions(m),
        })
    await db.commit()
    if not before:
        try:
            await client.send_read_acknowledge(entity)
        except Exception:
            pass
    return out


class TextIn(BaseModel):
    text: str


async def _writable(user_id: int, chat_id: int):
    entity = await tg.entity(user_id, chat_id)
    if not can_write(entity):
        raise HTTPException(403, "You can't write in this chat")
    return entity


@router.post("/api/chats/{chat_id}/messages")
async def send_message(chat_id: int, body: TextIn, user: User = Depends(telegram_user)):
    text = body.text.strip()
    if not text:
        raise HTTPException(400, "Empty message")
    client = await tg.client(user.id)
    entity = await _writable(user.id, chat_id)
    await client.send_message(entity, text[:4096])
    audit("message.sent", user_id=user.id, length=len(text))  # never the text itself
    return {"ok": True}


class ReactIn(BaseModel):
    emoji: str = ""  # empty: remove my reaction


@router.post("/api/chats/{chat_id}/messages/{msg_id}/react")
async def react(chat_id: int, msg_id: int, body: ReactIn, user: User = Depends(telegram_user)):
    emoji = body.emoji.strip()
    if len(emoji) > 16:
        raise HTTPException(400, "Not a reaction")
    client = await tg.client(user.id)
    await client(SendReactionRequest(peer=await tg.entity(user.id, chat_id), msg_id=msg_id,
                                     reaction=[ReactionEmoji(emoticon=emoji)] if emoji else []))
    return {"ok": True}


# chat icons ------------------------------------------------------------------
AVATAR_TTL = 7 * 24 * 3600
_avatar_sem = asyncio.Semaphore(3)  # don't hammer Telegram when a long chat list loads


@router.get("/api/chats/{chat_id}/avatar")
async def chat_avatar(chat_id: int, user: User = Depends(telegram_user)):
    """The chat's profile photo, re-encoded to a small PNG (like every image shown) and cached."""
    folder = settings.data_dir / "avatars" / f"u{user.id}"
    cached, missing = folder / f"{chat_id}.png", folder / f"{chat_id}.none"
    headers = {"Cache-Control": "private, max-age=86400"}

    def fresh(p: Path) -> bool:
        return p.exists() and time.time() - p.stat().st_mtime < AVATAR_TTL

    if fresh(cached):
        return FileResponse(cached, media_type="image/png", headers=headers)
    if fresh(missing):
        raise HTTPException(404)
    async with _avatar_sem:
        client = await tg.client(user.id)
        raw = await client.download_profile_photo(await tg.entity(user.id, chat_id), file=bytes)
    png = await asyncio.to_thread(images.avatar_png, raw) if raw else None
    folder.mkdir(parents=True, exist_ok=True)
    if png is None:
        missing.touch()
        raise HTTPException(404)
    tmp = cached.with_suffix(".tmp")
    tmp.write_bytes(png)
    tmp.replace(cached)
    return Response(png, media_type="image/png", headers=headers)


# attachments ---------------------------------------------------------------
async def _own_file(db, user: User, file_id: str) -> FileObj:
    f = await db.get(FileObj, file_id)
    if f is None or f.user_id != user.id:
        raise HTTPException(404, "File not found")
    return f


@router.post("/api/chats/{chat_id}/messages/{msg_id}/scan")
async def scan_attachment(chat_id: int, msg_id: int, user: User = Depends(telegram_user), db=Depends(get_db)):
    existing = (await db.execute(select(FileObj).where(
        FileObj.user_id == user.id, FileObj.chat_id == chat_id, FileObj.msg_id == msg_id,
        FileObj.direction == "inbound", FileObj.status.notin_(("error", "expired")))
        .order_by(FileObj.created_at.desc()).limit(1))).scalar_one_or_none()
    if existing:
        return files.serialize(existing)
    return files.serialize(await files.start_inbound(db, user.id, chat_id, msg_id))


@router.post("/api/chats/{chat_id}/files")
async def upload_file(chat_id: int, file: UploadFile = File(...), user: User = Depends(telegram_user),
                      db=Depends(get_db)):
    await _writable(user.id, chat_id)
    return files.serialize(await files.start_outbound(db, user.id, chat_id, file))


@router.get("/api/files/{file_id}")
async def get_file(file_id: str, user: User = Depends(telegram_user), db=Depends(get_db)):
    return files.serialize(await _own_file(db, user, file_id))


@router.post("/api/files/{file_id}/send")
async def confirm_send(file_id: str, user: User = Depends(telegram_user), db=Depends(get_db)):
    f = await _own_file(db, user, file_id)
    await files.confirm_send(db, f)
    return files.serialize(f)


@router.get("/api/files/{file_id}/content")
async def file_content(file_id: str, user: User = Depends(telegram_user), db=Depends(get_db)):
    f = await _own_file(db, user, file_id)
    if f.direction != "inbound" or f.status != "clean" or not f.clean_path or not Path(f.clean_path).exists():
        raise HTTPException(403, "Only files with a clean verdict can be opened")
    audit("file.download", user_id=user.id, sha256=f.sha256)
    is_image = f.clean_mime.startswith("image/")
    name = Path(f.name).stem + Path(f.clean_path).suffix if is_image else f.name
    return FileResponse(f.clean_path, media_type=f.clean_mime if is_image else "application/octet-stream",
                        filename=name, content_disposition_type="inline" if is_image else "attachment")


# live events ----------------------------------------------------------------
@router.get("/api/events")
async def events(request: Request, user: User = Depends(telegram_user)):
    queue = hub.subscribe(user.id)

    async def stream():
        try:
            yield ": connected\n\n"
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), 15)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            hub.unsubscribe(user.id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
