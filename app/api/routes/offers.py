"""Offers: create, accept or reject, pay, then complete or dispute.

Payment is local by default: GCash, Maya or card through PayMongo, or cash on delivery.
Stripe, BTCPay and Monero live here as optional adapters for other deployments.
"""

import json
import uuid
from datetime import date
from decimal import Decimal

import stripe as stripe_lib
import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    current_user,
    decode_b64,
    done,
    page_user,
    render,
    require_user_sig,
    wants_json,
)
from app.config import get_settings
from app.core import btcpay, crypto, monero, paymongo
from app.core import stripe as stripe_core
from app.core.market import (
    InvalidBlob,
    get_or_create_conversation,
    mark_offer_paid,
    notify,
    open_listing_ct,
    open_offer_ct,
    seal_model,
)
from app.core.queue import queue
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Listing, Offer, Rating, User
from app.schemas.offer import OfferCreate, OfferPlain

router = APIRouter()
log = structlog.get_logger()
OPEN_STATUSES = ("pending", "accepted", "paid", "disputed")


async def _get_offer(session: AsyncSession, offer_id: uuid.UUID) -> Offer:
    offer = await session.get(Offer, offer_id)
    if offer is None:
        raise HTTPException(404, "Offer not found")
    return offer


async def _check_can_offer(session: AsyncSession, listing: Listing | None, user: User) -> Listing:
    if listing is None or listing.status != "active" or not listing.seller.is_active:
        raise HTTPException(404, "Listing not available")
    if listing.seller_id == user.id:
        raise HTTPException(400, "You cannot make an offer on your own listing")
    existing = await session.scalar(
        select(Offer.id).where(
            Offer.listing_id == listing.id,
            Offer.buyer_id == user.id,
            Offer.status.in_(OPEN_STATUSES),
        )
    )
    if existing:
        raise HTTPException(409, "You already have an open offer on this listing")
    return listing


async def _store_offer(session, listing: Listing, user: User, ct: bytes, sig: bytes) -> Offer:
    offer = Offer(listing_id=listing.id, buyer_id=user.id, offer_ct=ct, sig=sig)
    session.add(offer)
    await session.flush()
    await get_or_create_conversation(session, user.id, listing.seller_id, listing.id, offer.id)
    await session.commit()
    await notify(listing.seller_id, "You received a new offer.", "/offers?tab=selling")
    return offer


@router.post("/listings/{listing_id}/offer", dependencies=[Depends(csrf_protect)])
async def create_offer_form(
    request: Request,
    listing_id: uuid.UUID,
    amount: str = Form(),
    currency: str = Form(),
    payment_method: str = Form(),
    message: str = Form(""),
    expires_at: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    listing = await _check_can_offer(session, await session.get(Listing, listing_id), user)
    try:
        plain = OfferPlain(
            amount_cents=round(Decimal(amount) * 100),
            currency=currency,
            payment_method=payment_method,
            message=message.strip(),
            expires_at=date.fromisoformat(expires_at) if expires_at else None,
        )
    except (ValidationError, ArithmeticError, ValueError) as e:
        raise HTTPException(422, f"Invalid offer: {e}") from e
    ct = seal_model(plain)
    offer = await _store_offer(session, listing, user, ct, crypto.server_sign("offer", ct))
    return done(request, "/offers?tab=buying", {"id": str(offer.id)}, "offer_sent")


@router.post("/api/offers", status_code=201, dependencies=[Depends(csrf_protect)])
async def api_create_offer(
    body: OfferCreate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    listing = await _check_can_offer(session, await session.get(Listing, body.listing_id), user)
    ct = decode_b64(body.offer_ct, "offer_ct")
    sig = require_user_sig(user, "offer", ct, body.sig)
    try:
        open_offer_ct(ct)
    except InvalidBlob as e:
        raise HTTPException(422, f"offer_ct invalid: {e}") from e
    offer = await _store_offer(session, listing, user, ct, sig)
    return {"id": str(offer.id)}


# --- Seller / buyer actions -------------------------------------------------------------


@router.post("/offers/{offer_id}/accept", dependencies=[Depends(csrf_protect)])
async def accept_offer(
    request: Request,
    offer_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _get_offer(session, offer_id)
    if offer.listing.seller_id != user.id:
        raise HTTPException(403, "Only the seller can accept")
    if offer.status != "pending" or offer.listing.status != "active":
        raise HTTPException(409, f"Offer is {offer.status}")
    offer.status = "accepted"
    await session.commit()
    await notify(offer.buyer_id, "Your offer was accepted. You can pay now.", "/offers")
    return done(request, "/offers?tab=selling", {"status": offer.status}, "offer_accepted")


@router.post("/offers/{offer_id}/reject", dependencies=[Depends(csrf_protect)])
async def reject_offer(
    request: Request,
    offer_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _get_offer(session, offer_id)
    is_seller = offer.listing.seller_id == user.id
    is_buyer = offer.buyer_id == user.id  # buyers may withdraw
    if not (is_seller or is_buyer):
        raise HTTPException(403)
    if offer.status not in ("pending", "accepted"):
        raise HTTPException(409, f"Offer is {offer.status}")
    offer.status = "rejected"
    await session.commit()
    await notify(offer.listing.seller_id if is_buyer else offer.buyer_id, "An offer was closed.")
    return done(request, "/offers", {"status": offer.status}, "offer_rejected")


@router.post("/offers/{offer_id}/pay", dependencies=[Depends(csrf_protect)])
async def pay_offer(
    request: Request,
    offer_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _get_offer(session, offer_id)
    if offer.buyer_id != user.id:
        raise HTTPException(403, "Only the buyer can pay")
    if offer.status != "accepted":
        raise HTTPException(409, f"Offer is {offer.status}")
    plain = open_offer_ct(offer.offer_ct)
    if plain.payment_method in ("cod", "paypal"):
        raise HTTPException(400, "This payment method has no online payment step")
    s = get_settings()
    try:
        title = open_listing_ct(offer.listing.listing_ct).title
    except InvalidBlob:
        title = "D1zzy listing"

    try:
        if plain.payment_method == "stripe":
            if not s.stripe_enabled:
                return done(request, "/offers", {"error": "stripe disabled"}, "payment_unavailable")
            session_id, url = await stripe_core.create_checkout_session(
                offer_id=offer.id,
                amount_cents=plain.amount_cents,
                currency=plain.currency,
                title=title,
            )
            offer.payment_ref = session_id
        elif plain.payment_method == "lightning":
            if not s.btcpay_enabled:
                return done(request, "/offers", {"error": "btcpay disabled"}, "payment_unavailable")
            async with btcpay.BTCPayClient() as client:
                invoice = await client.create_invoice(
                    offer_id=offer.id,
                    amount=str(Decimal(plain.amount_cents) / 100),
                    currency=plain.currency,
                    redirect_url=f"{s.public_base_url}/offers?tab=buying",
                )
            offer.payment_ref, url = invoice["id"], invoice["checkoutLink"]
        elif plain.payment_method in ("gcash", "maya", "paymongo"):
            if not s.paymongo_enabled:
                return done(
                    request, "/offers", {"error": "paymongo disabled"}, "payment_unavailable"
                )
            async with paymongo.PayMongoClient() as client:
                checkout = await client.create_checkout_session(
                    amount_cents=plain.amount_cents,
                    currency=plain.currency,
                    payment_method_allowed=["gcash", "maya", "card", "dob"],
                    success_url=f"{s.public_base_url}/offers?tab=buying&m=paid",
                    cancel_url=f"{s.public_base_url}/offers?tab=buying",
                    metadata={"offer_id": str(offer.id)},
                )
            offer.payment_ref = checkout["data"]["id"]
            url = checkout["data"]["attributes"]["checkout_url"]
        else:  # monero
            if not s.monero_enabled:
                return done(request, "/offers", {"error": "monero disabled"}, "payment_unavailable")
            async with monero.WalletRPC() as wallet:
                await wallet.ensure_wallet()
                address, _ = await wallet.create_subaddress(f"offer:{offer.id}")
            offer.payment_ref, url = address, "/offers?tab=buying"
    except (
        stripe_lib.StripeError,
        stripe_core.StripeNotConfigured,
        btcpay.BTCPayError,
        monero.MoneroError,
    ) as e:
        log.warning("payment_start_failed", offer_id=str(offer.id), error=str(e))
        return done(request, "/offers", {"error": "provider error"}, "payment_error")

    await session.commit()
    if wants_json(request):
        return JSONResponse({"url": url, "payment_ref": offer.payment_ref})
    return RedirectResponse(url, status_code=303)


@router.post("/offers/{offer_id}/complete", dependencies=[Depends(csrf_protect)])
async def complete_offer(
    request: Request,
    offer_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _get_offer(session, offer_id)
    if offer.buyer_id != user.id:
        raise HTTPException(403, "Only the buyer confirms receipt")
    if offer.status != "paid":
        raise HTTPException(409, f"Offer is {offer.status}")
    offer.status = "completed"
    await session.commit()
    await notify(offer.listing.seller_id, "The buyer confirmed receipt. Leave a rating!")
    return done(request, "/offers?tab=buying", {"status": offer.status}, "offer_completed")


@router.post("/offers/{offer_id}/dispute", dependencies=[Depends(csrf_protect)])
async def dispute_offer(
    request: Request,
    offer_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _get_offer(session, offer_id)
    if user.id not in (offer.buyer_id, offer.listing.seller_id):
        raise HTTPException(403)
    if offer.status != "paid":
        raise HTTPException(409, "Only paid offers can be disputed")
    offer.status = "disputed"
    await session.commit()
    other = offer.listing.seller_id if user.id == offer.buyer_id else offer.buyer_id
    await notify(other, "A dispute was opened on one of your orders.")
    return done(request, "/offers", {"status": offer.status}, "offer_disputed")


# --- Pages ------------------------------------------------------------------------------


async def _pop_notifications(user: User) -> list[dict]:
    try:
        redis = await queue.connect()
        key = f"notifications:{user.id}"
        items = await redis.lrange(key, 0, 19)
        await redis.delete(key, f"notif_unread:{user.id}")
        return [json.loads(i) for i in items]
    except Exception:  # noqa: BLE001 -- notifications are best-effort
        return []


def offer_row(offer: Offer) -> dict:
    try:
        plain = open_offer_ct(offer.offer_ct)
    except InvalidBlob:
        plain = None
    try:
        title = open_listing_ct(offer.listing.listing_ct).title
    except InvalidBlob:
        title = "(unreadable listing)"
    return {
        "offer": offer,
        "plain": plain,
        "title": title,
        "signed_by": crypto.sig_origin(
            "offer", offer.offer_ct, offer.sig, offer.buyer.signing_pubkey
        ),
    }


@router.get("/offers")
async def offers_page(
    request: Request,
    tab: str = "buying",
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    if tab == "selling":
        q = select(Offer).join(Listing).where(Listing.seller_id == user.id)
    else:
        tab, q = "buying", select(Offer).where(Offer.buyer_id == user.id)
    offers = (await session.scalars(q.order_by(Offer.updated_at.desc()).limit(100))).unique()
    rows = [offer_row(o) for o in offers]
    rated = set(
        await session.scalars(
            select(Rating.offer_id).where(
                Rating.rater_id == user.id, Rating.offer_id.in_([r["offer"].id for r in rows])
            )
        )
    )
    return render(
        request,
        "pages/offers.html",
        {
            "tab": tab,
            "rows": rows,
            "rated": rated,
            "notifications": await _pop_notifications(user),
        },
        user=user,
    )


# --- Webhooks ---------------------------------------------------------------------------


async def _offer_by_ref(session: AsyncSession, ref: str, offer_id: str | None = None):
    q = select(Offer).where(Offer.payment_ref == ref)
    if offer_id:
        try:
            q = q.where(Offer.id == uuid.UUID(offer_id))
        except ValueError:
            return None
    return await session.scalar(q)


@router.post("/webhooks/stripe", include_in_schema=False)
async def stripe_webhook(request: Request, session: AsyncSession = Depends(get_session)):
    payload = await request.body()
    try:
        event = stripe_core.construct_event(payload, request.headers.get("stripe-signature", ""))
    except stripe_core.StripeNotConfigured as e:
        raise HTTPException(503, "Stripe webhooks not configured") from e
    except (ValueError, stripe_lib.SignatureVerificationError) as e:
        raise HTTPException(400, "Invalid signature") from e

    if event["type"] in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        obj = event["data"]["object"]
        if obj.get("payment_status") == "paid":
            offer = await _offer_by_ref(
                session, obj["id"], (obj.get("metadata") or {}).get("offer_id")
            )
            if offer:
                await mark_offer_paid(session, offer, "stripe")
    return {"received": True}


@router.post("/webhooks/btcpay", include_in_schema=False)
async def btcpay_webhook(request: Request, session: AsyncSession = Depends(get_session)):
    payload = await request.body()
    if not btcpay.verify_webhook(payload, request.headers.get("btcpay-sig")):
        raise HTTPException(400, "Invalid signature")
    event = json.loads(payload)
    if event.get("type") in ("InvoiceSettled", "InvoicePaymentSettled"):
        offer = await _offer_by_ref(session, event.get("invoiceId", ""))
        if offer:
            await mark_offer_paid(session, offer, "btcpay")
    return {"received": True}
