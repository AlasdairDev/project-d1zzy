"""Background jobs. Polling tasks are the safety net for missed webhooks."""

import json
from email.message import EmailMessage

import aiosmtplib
import structlog
from sqlalchemy import select

from app.config import get_settings
from app.core import btcpay, monero
from app.core import stripe as stripe_core
from app.core.ipfs import IPFSClient, IPFSError
from app.core.market import expire_offers as _expire_offers
from app.core.market import mark_offer_paid, open_offer_ct
from app.db.session import get_sessionmaker
from app.models import Offer

log = structlog.get_logger()


async def send_email(ctx, to: str, subject: str, body: str) -> None:
    s = get_settings()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.email_from, to, subject
    msg.set_content(body)
    await aiosmtplib.send(
        msg,
        hostname=s.smtp_host,
        port=s.smtp_port,
        username=s.smtp_user or None,
        password=s.smtp_password or None,
        start_tls=False if s.is_dev else None,
    )
    log.info("email_sent", subject=subject)


async def pin_cids(ctx, cids: list[str]) -> int:
    pinned = 0
    async with IPFSClient() as ipfs:
        for cid in cids:
            try:
                await ipfs.pin(cid)
                pinned += 1
            except IPFSError as e:
                log.warning("pin_failed", cid=cid, error=str(e))
    return pinned


async def relay_notifications(ctx, user_id: str, text: str, link: str = "/offers") -> None:
    """Store a notification for the navbar badge and push it to any live listener."""
    redis = ctx["redis"]
    item = json.dumps({"text": text, "link": link})
    await redis.lpush(f"notifications:{user_id}", item)
    await redis.ltrim(f"notifications:{user_id}", 0, 49)
    await redis.incr(f"notif_unread:{user_id}")
    await redis.publish(f"notify:{user_id}", item)


async def _accepted_with_ref(session, prefix: str | None = None):
    q = select(Offer).where(Offer.status == "accepted", Offer.payment_ref.is_not(None))
    offers = (await session.scalars(q)).unique().all()
    return [o for o in offers if prefix is None or o.payment_ref.startswith(prefix)]


async def poll_stripe(ctx) -> int:
    if not get_settings().stripe_enabled:
        return 0
    n = 0
    async with get_sessionmaker()() as session:
        for offer in await _accepted_with_ref(session, "cs_"):
            try:
                if await stripe_core.retrieve_session_status(offer.payment_ref) == "paid":
                    n += await mark_offer_paid(session, offer, "stripe")
            except Exception as e:  # noqa: BLE001
                log.warning("poll_stripe_failed", offer_id=str(offer.id), error=str(e))
    return n


async def poll_btcpay(ctx) -> int:
    if not get_settings().btcpay_enabled:
        return 0
    n = 0
    async with get_sessionmaker()() as session, btcpay.BTCPayClient() as client:
        for offer in await _accepted_with_ref(session):
            if open_offer_ct(offer.offer_ct).payment_method != "lightning":
                continue
            try:
                invoice = await client.get_invoice(offer.payment_ref)
            except btcpay.BTCPayError as e:
                log.warning("poll_btcpay_failed", offer_id=str(offer.id), error=str(e))
                continue
            if invoice.get("status") in btcpay.SETTLED:
                n += await mark_offer_paid(session, offer, "btcpay")
    return n


async def poll_monero(ctx) -> int:
    if not get_settings().monero_enabled:
        return 0
    n = 0
    async with get_sessionmaker()() as session, monero.WalletRPC() as wallet:
        offers = [
            o
            for o in await _accepted_with_ref(session)
            if open_offer_ct(o.offer_ct).payment_method == "monero"
        ]
        if not offers:
            return 0
        try:
            await wallet.ensure_wallet()
        except monero.MoneroError as e:
            log.warning("poll_monero_unavailable", error=str(e))
            return 0
        for offer in offers:
            plain = open_offer_ct(offer.offer_ct)
            needed = plain.amount_cents * 10**10  # 1/100 XMR -> piconero
            try:
                index = await wallet.get_address_index(offer.payment_ref)
                received = await wallet.received_atomic(index, min_confirmations=1)
            except monero.MoneroError as e:
                log.warning("poll_monero_failed", offer_id=str(offer.id), error=str(e))
                continue
            if received >= needed:
                n += await mark_offer_paid(session, offer, "monero")
    return n


async def expire_offers(ctx) -> int:
    async with get_sessionmaker()() as session:
        return await _expire_offers(session)
