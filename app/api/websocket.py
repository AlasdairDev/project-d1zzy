"""WebSocket relay for Double Ratchet messages, one room per conversation.

Rooms are Redis pub/sub channels (`conv:<id>`), so any number of web processes can serve
participants of the same conversation. The relay only ever sees ratchet headers and
ciphertext; it validates shape and size, stores, and fans out.
"""

import asyncio
import json
import time
import uuid
from urllib.parse import urlsplit

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from pydantic import ValidationError

from app.api.deps import UserManager, get_jwt_strategy
from app.api.routes.messages import get_conversation_for, store_and_publish
from app.core import crypto
from app.core.queue import queue
from app.core.security import ACCESS_COOKIE
from app.db.session import get_sessionmaker
from app.models import User
from app.schemas.message import RatchetMessageIn

router = APIRouter()
log = structlog.get_logger()

MAX_MESSAGES_PER_10S = 20


def _same_origin(ws: WebSocket) -> bool:
    """Browsers send cookies on cross-site WebSocket handshakes; reject foreign origins."""
    origin = ws.headers.get("origin")
    if origin is None:  # non-browser client
        return True
    return urlsplit(origin).netloc == ws.headers.get("host")


@router.websocket("/ws/conversations/{conv_id}")
async def conversation_socket(ws: WebSocket, conv_id: uuid.UUID):
    if not _same_origin(ws):
        await ws.close(code=1008)
        return

    async with get_sessionmaker()() as session:
        manager = UserManager(SQLAlchemyUserDatabase(session, User))
        user = await get_jwt_strategy().read_token(ws.cookies.get(ACCESS_COOKIE), manager)
        if user is None or not user.is_active:
            await ws.close(code=1008)
            return
        try:
            conv = await get_conversation_for(session, conv_id, user)
        except Exception:  # noqa: BLE001
            await ws.close(code=1008)
            return

        try:
            redis = await queue.connect()
            pubsub = redis.pubsub()
            await pubsub.subscribe(f"conv:{conv.id}")
        except Exception as e:  # noqa: BLE001
            log.warning("ws_redis_unavailable", error=str(e))
            await ws.close(code=1011)  # client falls back to REST polling
            return

        await ws.accept()

        async def forward() -> None:
            async for item in pubsub.listen():
                if item["type"] == "message":
                    await ws.send_text(item["data"].decode())

        forwarder = asyncio.create_task(forward())
        window: list[float] = []
        try:
            while True:
                raw = await ws.receive_text()
                t = time.monotonic()
                window = [w for w in window if t - w < 10] + [t]
                if len(window) > MAX_MESSAGES_PER_10S:
                    await ws.close(code=1008, reason="rate limited")
                    break
                try:
                    body = RatchetMessageIn.model_validate(json.loads(raw))
                except (ValueError, ValidationError):
                    await ws.send_text(json.dumps({"error": "invalid message"}))
                    continue
                await session.refresh(user)  # suspended mid-conversation?
                if not user.is_active:
                    await ws.close(code=1008, reason="suspended")
                    break
                await store_and_publish(
                    session, conv, user, crypto.b64d(body.header), crypto.b64d(body.ciphertext)
                )
        except WebSocketDisconnect:
            pass
        finally:
            forwarder.cancel()
            try:
                await pubsub.unsubscribe()
                await pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass
