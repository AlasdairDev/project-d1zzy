"""Conversations and messages.

Chat is end-to-end encrypted when both people use JavaScript and have unlocked keys. The
no-JS fallback is sent over Tor or HTTPS, encrypted at rest with the market key, and marked
as not end-to-end encrypted in the UI.
"""

import json
import uuid

import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, page_user, render
from app.core import crypto
from app.core.market import (
    InvalidBlob,
    get_or_create_conversation,
    now,
    open_listing_ct,
    user_conversations_query,
)
from app.core.queue import queue
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Conversation, Listing, Message, User
from app.schemas.message import RatchetMessageIn

router = APIRouter()
log = structlog.get_logger()

SERVER_HEADER = b'{"mode":"server"}'
MAX_PLAINTEXT = 4000


def _ad(conv_id: uuid.UUID) -> bytes:
    return b"d1zzy-msg:" + str(conv_id).encode()


def message_out(msg: Message) -> dict:
    server_mode = msg.header_ct == SERVER_HEADER
    plaintext = None
    if server_mode:
        try:
            plaintext = crypto.open_sealed(
                msg.ciphertext, crypto.market_key(), _ad(msg.conversation_id)
            ).decode()
        except crypto.CryptoError:
            plaintext = "(unreadable)"
    return {
        "id": msg.id,
        "conversation_id": str(msg.conversation_id),
        "sender_id": str(msg.sender_id),
        "header": crypto.b64e(msg.header_ct),
        "ciphertext": crypto.b64e(msg.ciphertext),
        "mode": "server" if server_mode else "ratchet",
        "plaintext": plaintext,
        "created_at": msg.created_at.isoformat() if msg.created_at else None,
    }


async def get_conversation_for(
    session: AsyncSession, conv_id: uuid.UUID, user: User
) -> Conversation:
    conv = await session.get(Conversation, conv_id)
    if conv is None or not conv.has(user.id):
        raise HTTPException(404, "Conversation not found")
    return conv


async def store_and_publish(
    session: AsyncSession, conv: Conversation, sender: User, header: bytes, ciphertext: bytes
) -> dict:
    msg = Message(
        conversation_id=conv.id, sender_id=sender.id, header_ct=header, ciphertext=ciphertext
    )
    session.add(msg)
    _mark_read(conv, sender.id)
    await session.commit()
    await session.refresh(msg)
    out = message_out(msg)
    other = conv.other(sender.id)
    try:
        redis = await queue.connect()
        await redis.publish(f"conv:{conv.id}", json.dumps(out))
        # One notification per conversation per 5 minutes, not one per message.
        if await redis.set(f"notif_msg:{other.id}:{conv.id}", "1", ex=300, nx=True):
            await queue.enqueue(
                "relay_notifications",
                str(other.id),
                f"New message from @{sender.handle}",
                f"/messages/{conv.id}",
            )
    except Exception as e:  # noqa: BLE001 -- live relay is best-effort; history is in the DB
        log.warning("publish_failed", error=str(e))
    return out


def _mark_read(conv: Conversation, user_id: uuid.UUID) -> None:
    if user_id == conv.participant1_id:
        conv.participant1_read_at = now()
    else:
        conv.participant2_read_at = now()


async def unread_counts(session: AsyncSession, user_id: uuid.UUID) -> dict[uuid.UUID, int]:
    q = (
        select(Message.conversation_id, func.count())
        .join(Conversation, Conversation.id == Message.conversation_id)
        .where(
            Message.sender_id != user_id,
            or_(
                and_(
                    Conversation.participant1_id == user_id,
                    or_(
                        Conversation.participant1_read_at.is_(None),
                        Message.created_at > Conversation.participant1_read_at,
                    ),
                ),
                and_(
                    Conversation.participant2_id == user_id,
                    or_(
                        Conversation.participant2_read_at.is_(None),
                        Message.created_at > Conversation.participant2_read_at,
                    ),
                ),
            ),
        )
        .group_by(Message.conversation_id)
    )
    return dict((await session.execute(q)).all())


async def _listing_title(session: AsyncSession, listing_id: uuid.UUID | None) -> str | None:
    if not listing_id:
        return None
    listing = await session.get(Listing, listing_id)
    try:
        return open_listing_ct(listing.listing_ct).title if listing else None
    except InvalidBlob:
        return None


# --- Pages ------------------------------------------------------------------------------


@router.post("/listings/{listing_id}/contact", dependencies=[Depends(csrf_protect)])
async def contact_seller(
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    listing = await session.get(Listing, listing_id)
    if listing is None or listing.status != "active":
        raise HTTPException(404, "Listing not available")
    if listing.seller_id == user.id:
        raise HTTPException(400, "This is your own listing")
    conv = await get_or_create_conversation(session, user.id, listing.seller_id, listing.id)
    await session.commit()
    return RedirectResponse(f"/messages/{conv.id}", status_code=303)


@router.get("/messages")
async def messages_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    convs = list((await session.scalars(user_conversations_query(user.id))).unique())
    unread = await unread_counts(session, user.id)
    rows = [
        {
            "conv": c,
            "other": c.other(user.id),
            "title": await _listing_title(session, c.listing_id),
            "unread": unread.get(c.id, 0),
        }
        for c in convs
    ]
    rows.sort(key=lambda r: -r["unread"])
    return render(request, "pages/messages.html", {"rows": rows}, user=user)


@router.get("/messages/{conv_id}")
async def conversation_page(
    request: Request,
    conv_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    conv = await get_conversation_for(session, conv_id, user)
    msgs = (
        await session.scalars(
            select(Message)
            .where(Message.conversation_id == conv.id)
            .order_by(Message.id.desc())
            .limit(200)
        )
    ).all()
    _mark_read(conv, user.id)
    await session.commit()
    other = conv.other(user.id)
    e2e_possible = bool(user.exchange_pubkey and other.exchange_pubkey)
    safety_number = None
    if e2e_possible:
        safety_number = crypto.safety_number(
            str(conv.id),
            [
                (str(user.id), user.signing_pubkey, user.exchange_pubkey),
                (str(other.id), other.signing_pubkey, other.exchange_pubkey),
            ],
        )
    return render(
        request,
        "pages/conversation.html",
        {
            "conv": conv,
            "other": other,
            "messages": [message_out(m) for m in reversed(msgs)],
            "title": await _listing_title(session, conv.listing_id),
            "is_alice": str(user.id) == str(conv.participant1_id),
            "e2e_possible": e2e_possible,
            "safety_number": safety_number,
        },
        user=user,
    )


@router.post("/messages/{conv_id}/send", dependencies=[Depends(csrf_protect)])
async def send_server_mode(
    conv_id: uuid.UUID,
    text: str = Form(),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    """No-JS fallback (or a partner without keys). Not end-to-end encrypted."""
    conv = await get_conversation_for(session, conv_id, user)
    text = text.strip()[:MAX_PLAINTEXT]
    if text:
        ct = crypto.seal(text.encode(), crypto.market_key(), _ad(conv.id))
        await store_and_publish(session, conv, user, SERVER_HEADER, ct)
    return RedirectResponse(f"/messages/{conv.id}#end", status_code=303)


# --- JSON API ---------------------------------------------------------------------------


@router.get("/api/conversations/{conv_id}")
async def api_conversation(
    conv_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    conv = await get_conversation_for(session, conv_id, user)
    other = conv.other(user.id)
    e2e_possible = bool(user.exchange_pubkey and other.exchange_pubkey)
    safety_number = None
    if e2e_possible:
        safety_number = crypto.safety_number(
            str(conv.id),
            [
                (str(user.id), user.signing_pubkey, user.exchange_pubkey),
                (str(other.id), other.signing_pubkey, other.exchange_pubkey),
            ],
        )
    return {
        "id": str(conv.id),
        "me": str(user.id),
        "is_alice": str(user.id) == str(conv.participant1_id),
        "safety_number": safety_number,
        "other": {
            "id": str(other.id),
            "handle": other.handle,
            "exchange_pubkey": crypto.b64e(other.exchange_pubkey or b""),
            "signing_pubkey": crypto.b64e(other.signing_pubkey or b""),
        },
    }


@router.get("/api/conversations/{conv_id}/messages")
async def api_history(
    conv_id: uuid.UUID,
    after_id: int = 0,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    conv = await get_conversation_for(session, conv_id, user)
    msgs = (
        await session.scalars(
            select(Message)
            .where(Message.conversation_id == conv.id, Message.id > after_id)
            .order_by(Message.id)
            .limit(500)
        )
    ).all()
    return {"messages": [message_out(m) for m in msgs]}


@router.post(
    "/api/conversations/{conv_id}/messages", status_code=201, dependencies=[Depends(csrf_protect)]
)
async def api_send(
    conv_id: uuid.UUID,
    body: RatchetMessageIn,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """REST twin of the WebSocket relay, used when the socket is unavailable."""
    conv = await get_conversation_for(session, conv_id, user)
    return await store_and_publish(
        session, conv, user, crypto.b64d(body.header), crypto.b64d(body.ciphertext)
    )
