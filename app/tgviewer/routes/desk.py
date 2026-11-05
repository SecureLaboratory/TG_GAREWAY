"""Isolated-browser mode: the screen stream proxy (/desk/*) and the file side panel.

Each logged-in (non-admin) user is routed only to their own browser container. The
container's address and password never reach the PC; the gateway adds them upstream.
"""
import asyncio
import os
import logging
from pathlib import Path
from urllib.parse import urlsplit

import websockets
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import FileResponse
from sqlalchemy import select

from .. import files
from ..audit import audit
from ..config import settings
from ..db import SessionLocal
from ..deps import COOKIE, get_db, has_consent, telegram_user, user_from_token
from ..desk import UPSTREAM_SSL, desk
from ..models import FileObj, User

log = logging.getLogger(__name__)
router = APIRouter()
# Same KasmVNC version as the browser image (see app/Dockerfile and browser/Dockerfile).
KASM_WWW = Path(os.environ.get("KASM_WWW", "/app/kasmvnc-www")).resolve()


def _require_browser_mode() -> None:
    if settings.access_mode != "browser":
        raise HTTPException(404, "Isolated-browser mode is not enabled")


# browser control & files ----------------------------------------------------------
@router.get("/api/desk")
async def desk_status(user: User = Depends(telegram_user)):
    _require_browser_mode()
    return {"status": await desk.status(user.id)}


@router.post("/api/desk/start")
async def desk_start(user: User = Depends(telegram_user)):
    _require_browser_mode()
    await desk.ensure(user.id)  # always asks the manager: recreates a browser that was removed
    return {"ok": True}


@router.post("/api/desk/restart")
async def desk_restart(user: User = Depends(telegram_user)):
    _require_browser_mode()
    await desk.restart(user.id)
    audit("desk.restarted", user_id=user.id)
    return {"ok": True}


@router.post("/api/desk/reset")
async def desk_reset(user: User = Depends(telegram_user)):
    """Deletes the browser and its profile: logs the user out of Telegram Web on the gateway."""
    _require_browser_mode()
    await desk.destroy(user.id)
    audit("desk.reset", user_id=user.id)
    return {"ok": True}


@router.get("/api/desk/files")
async def desk_files(user: User = Depends(telegram_user), db=Depends(get_db)):
    _require_browser_mode()
    rows = (await db.execute(select(FileObj).where(FileObj.user_id == user.id, FileObj.chat_kind == "browser")
                             .order_by(FileObj.created_at.desc()).limit(50))).scalars()
    return [files.serialize(f) for f in rows]


@router.post("/api/desk/uploads")
async def desk_upload(file: UploadFile = File(...), user: User = Depends(telegram_user), db=Depends(get_db)):
    _require_browser_mode()
    return files.serialize(await files.start_outbound(db, user.id, 0, file, browser=True))


# screen stream proxy --------------------------------------------------------------
@router.get("/desk/{path:path}")
async def desk_client(path: str, user: User = Depends(telegram_user)):
    """The stream client (KasmVNC web UI) comes from the gateway image, never from the
    user's browser container: a compromised container can send pixels, not code."""
    _require_browser_mode()
    if path.split("/", 1)[0].lower() == "downloads":  # KasmVNC's direct download folder: never
        raise HTTPException(404)
    target = (KASM_WWW / (path or "index.html")).resolve()
    if not target.is_relative_to(KASM_WWW) or not target.is_file():
        raise HTTPException(404)
    return FileResponse(target, headers={"Cache-Control": "private, max-age=3600"})


@router.websocket("/desk/websockify")
async def desk_ws(ws: WebSocket):
    # Cross-site WebSocket hijacking protection: the page must come from this gateway.
    origin = ws.headers.get("origin", "")
    if settings.access_mode != "browser" or not origin or urlsplit(origin).netloc != ws.headers.get("host"):
        await ws.close(code=4403)
        return
    token = ws.cookies.get(COOKIE)
    async with SessionLocal() as db:
        user = await user_from_token(db, token)
    if user is None or user.is_admin or not has_consent(user):
        await ws.close(code=4401)
        return

    ep = await desk.endpoint(user.id)
    try:
        upstream = await websockets.connect(
            f"wss://{ep.host}:{ep.port}/websockify", ssl=UPSTREAM_SSL,
            # KasmVNC checks that Origin is its own address (we've checked the PC's Origin above).
            additional_headers={"Authorization": ep.authorization, "Origin": f"https://{ep.host}:{ep.port}"},
            subprotocols=ws.scope.get("subprotocols") or ["binary"],
            max_size=None, open_timeout=20, ping_interval=None, compression=None, proxy=None)
    except Exception as e:
        log.warning("browser for user %s not reachable: %s", user.id, e)
        desk.forget(user.id)  # next attempt asks the manager again
        await ws.close(code=1011)
        return
    await ws.accept(subprotocol=upstream.subprotocol)
    audit("desk.connected", user_id=user.id)

    async def to_browser():
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                return
            if msg.get("bytes") is not None:
                await upstream.send(msg["bytes"])
            elif msg.get("text") is not None:
                await upstream.send(msg["text"])

    async def to_pc():
        async for data in upstream:
            if isinstance(data, bytes):
                await ws.send_bytes(data)
            else:
                await ws.send_text(data)

    async def session_guard():
        # A long-lived stream keeps the session alive, and ends as soon as it's revoked.
        while True:
            await asyncio.sleep(60)
            async with SessionLocal() as db:
                if await user_from_token(db, token) is None:
                    return

    tasks = [asyncio.create_task(t()) for t in (to_browser, to_pc, session_guard)]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await upstream.close()
        try:
            await ws.close()
        except RuntimeError:
            pass
        audit("desk.disconnected", user_id=user.id)
