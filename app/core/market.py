"""Domain logic shared by HTTP routes, the WebSocket relay, the worker and the CLI."""

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime

import structlog
from pydantic import ValidationError
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import crypto
from app.core.queue import queue
from app.models import Conversation, Listing, Offer, User
from app.schemas.listing import ListingPlain
from app.schemas.offer import OfferPlain

log = structlog.get_logger()


class InvalidBlob(ValueError):
    pass


def open_listing_ct(ct: bytes) -> ListingPlain:
    try:
        return ListingPlain.model_validate(crypto.open_json(ct))
    except (crypto.CryptoError, ValidationError) as e:
        raise InvalidBlob(str(e)) from e


def open_offer_ct(ct: bytes) -> OfferPlain:
    try:
        return OfferPlain.model_validate(crypto.open_json(ct))
    except (crypto.CryptoError, ValidationError) as e:
        raise InvalidBlob(str(e)) from e


def seal_model(model) -> bytes:
    return crypto.seal_json(model.model_dump(mode="json"))


@dataclass
class ListingView:
    listing: Listing
    plain: ListingPlain | None
    signed_by: str | None  # "user" | "server" | None (tampered)

    @property
    def id(self) -> uuid.UUID:
        return self.listing.id

    @property
    def seller(self) -> User:
        return self.listing.seller

    @property
    def is_expired(self) -> bool:
        return bool(self.plain and self.plain.expires_at and self.plain.expires_at < date.today())


def listing_view(listing: Listing) -> ListingView:
    try:
        plain = open_listing_ct(listing.listing_ct)
    except InvalidBlob:
        plain = None
    signed_by = crypto.sig_origin(
        "listing", listing.listing_ct, listing.sig, listing.seller.signing_pubkey
    )
    return ListingView(listing, plain, signed_by)


def visible_listings_query():
    """Active listings by non-suspended sellers."""
    return (
        select(Listing)
        .join(User, Listing.seller_id == User.id)
        .where(Listing.status == "active", User.is_active.is_(True))
    )


def can_view_listing(listing: Listing, user: User | None) -> bool:
    if listing.status in ("active", "sold") and listing.seller.is_active:
        return True
    return bool(user and (user.is_superuser or user.id == listing.seller_id))


async def get_or_create_conversation(
    session: AsyncSession,
    a: uuid.UUID,
    b: uuid.UUID,
    listing_id: uuid.UUID | None,
    offer_id: uuid.UUID | None = None,
) -> Conversation:
    p1, p2 = sorted([a, b], key=str)
    q = select(Conversation).where(
        Conversation.participant1_id == p1,
        Conversation.participant2_id == p2,
        Conversation.listing_id == listing_id if listing_id else Conversation.listing_id.is_(None),
    )
    conv = await session.scalar(q)
    if conv is None:
        conv = Conversation(
            participant1_id=p1, participant2_id=p2, listing_id=listing_id, offer_id=offer_id
        )
        session.add(conv)
        await session.flush()
        await session.refresh(conv, ["participant1", "participant2"])
    elif offer_id and conv.offer_id is None:
        conv.offer_id = offer_id
    return conv


async def notify(user_id: uuid.UUID, text: str, link: str = "/offers") -> None:
    await queue.enqueue("relay_notifications", str(user_id), text, link)


async def mark_offer_paid(session: AsyncSession, offer: Offer, provider: str) -> bool:
    """Idempotent. Returns True if this call changed the state."""
    if offer.status != "accepted":
        return False

    # Calculate platform fees
    plain = open_offer_ct(offer.offer_ct)
    amount_cents = plain.amount_cents

    # Platform fee (5% in basis points = 500)
    platform_fee_bps = offer.platform_fee_percent or 500
    platform_fee_cents = (amount_cents * platform_fee_bps) // 10000

    # Gateway fee estimation (varies by provider)
    gateway_fee_cents = 0
    if plain.payment_method == "stripe":
        # Stripe: 2.9% + 30¢ (US) or similar in other countries
        gateway_fee_cents = int(plain.amount_cents * 0.029) + 30
    elif plain.payment_method == "lightning":
        # BTCPay/Lightning - minimal fees
        gateway_fee_cents = 100  # ~$1
    elif plain.payment_method == "monero":
        # Monero network fee
        gateway_fee_cents = 50  # ~$0.50
    elif plain.payment_method in ("gcash", "maya", "paymongo", "paypal"):
        # Philippine e-wallets: ~2-3% + fixed fee
        gateway_fee_cents = int(plain.amount_cents * 0.025) + 1500  # 2.5% + ₱15
    elif plain.payment_method == "paypal":
        # PayPal: ~3.4% + fixed fee
        gateway_fee_cents = int(plain.amount_cents * 0.034) + 1500
    elif plain.payment_method == "cod":
        gateway_fee_cents = 0  # No gateway fee for COD

    seller_payout_cents = plain.amount_cents - platform_fee_cents - gateway_fee_cents

    # Store fee breakdown
    offer.platform_fee_cents = platform_fee_cents
    offer.gateway_fee_cents = gateway_fee_cents
    offer.seller_payout_cents = seller_payout_cents
    offer.platform_fee_percent = offer.platform_fee_percent or 500

    offer.status = "paid"
    offer.listing.status = "sold"
    await session.execute(
        update(Offer)
        .where(
            Offer.listing_id == offer.listing_id,
            Offer.id != offer.id,
            Offer.status.in_(["pending", "accepted"]),
        )
        .values(status="rejected")
    )
    await session.commit()
    log.info("offer_paid", offer_id=str(offer.id), provider=provider)
    await notify(offer.listing.seller_id, "An offer on your listing was paid.", "/vendor")
    await notify(offer.buyer_id, "Your payment was received.")
    return True


async def expire_offers(session: AsyncSession) -> int:
    today = date.today()
    q = select(Offer).where(Offer.status.in_(["pending", "accepted"]))
    n = 0
    for offer in (await session.scalars(q)).unique():
        try:
            plain = open_offer_ct(offer.offer_ct)
        except InvalidBlob:
            continue
        if plain.expires_at and plain.expires_at < today:
            offer.status = "expired"
            n += 1
    await session.commit()
    return n


def user_conversations_query(user_id: uuid.UUID):
    return (
        select(Conversation)
        .where(
            or_(Conversation.participant1_id == user_id, Conversation.participant2_id == user_id)
        )
        .order_by(Conversation.created_at.desc())
    )


def now() -> datetime:
    return datetime.now(UTC)
