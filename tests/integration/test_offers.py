import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.core import crypto
from app.models import Listing, Offer
from tests.integration.test_payments import stripe_signature


@pytest.fixture
def fake_stripe(monkeypatch):
    from app.core import stripe as stripe_core

    async def create(*, offer_id, amount_cents, currency, title):
        create.calls.append((offer_id, amount_cents, currency, title))
        return f"cs_test_{uuid.uuid4().hex}", "https://checkout.stripe.com/c/pay/test"

    create.calls = []
    monkeypatch.setattr(stripe_core, "create_checkout_session", create)
    return create


async def test_offer_accept_pay_stripe_complete(make_user, helpers, db, fake_stripe):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller, title="Raspberry Pi", price_cents=6000)
    offer_id = await helpers.create_offer(buyer, listing_id, amount_cents=5500)

    # Seller sees the offer, signed by the buyer, and accepts it.
    page = await seller.client.get("/offers?tab=selling")
    assert "$55.00" in page.text and f"Signed by @{buyer.handle}" in page.text
    assert (await buyer.api("POST", f"/offers/{offer_id}/accept")).status_code == 403
    r = await seller.api("POST", f"/offers/{offer_id}/accept")
    assert r.status_code == 200 and r.json()["status"] == "accepted"

    # Buyer pays: redirected to Stripe Checkout for the decrypted amount.
    r = await buyer.form(f"/offers/{offer_id}/pay")
    assert r.status_code == 303 and r.headers["location"].startswith("https://checkout.stripe.com")
    assert fake_stripe.calls[0][1:] == (5500, "usd", "Raspberry Pi")
    offer = await db.get(Offer, uuid.UUID(offer_id))
    await db.refresh(offer)
    session_id = offer.payment_ref

    # Stripe calls the webhook.
    event = {
        "id": "evt_1",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "object": "checkout.session",
                "payment_status": "paid",
                "metadata": {"offer_id": offer_id},
            }
        },
    }
    payload = json.dumps(event).encode()
    r = await buyer.client.post(
        "/webhooks/stripe",
        content=payload,
        headers={"stripe-signature": stripe_signature(payload, "whsec_test_secret")},
    )
    assert r.status_code == 200, r.text
    await db.refresh(offer)
    assert offer.status == "paid"
    listing = await db.get(Listing, uuid.UUID(listing_id))
    await db.refresh(listing)
    assert listing.status == "sold"

    # Buyer confirms receipt.
    r = await buyer.api("POST", f"/offers/{offer_id}/complete")
    assert r.status_code == 200 and r.json()["status"] == "completed"


async def test_offer_pay_lightning_via_btcpay(make_user, helpers, db, monkeypatch):
    from app.core import btcpay

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(
            200, json={"id": "inv_123", "checkoutLink": "http://btcpay.test/i/inv_123"}
        )

    original = btcpay.BTCPayClient.__init__

    def patched(self, *a, **kw):
        original(self, *a, transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(btcpay.BTCPayClient, "__init__", patched)

    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    offer_id = await helpers.create_offer(
        buyer, listing_id, payment_method="lightning", amount_cents=1234, currency="usd"
    )
    await seller.api("POST", f"/offers/{offer_id}/accept")
    r = await buyer.api("POST", f"/offers/{offer_id}/pay")
    assert r.status_code == 200 and r.json()["url"] == "http://btcpay.test/i/inv_123"
    assert seen["path"] == "/api/v1/stores/store1/invoices"
    assert seen["body"]["amount"] == "12.34" and seen["body"]["metadata"]["orderId"] == offer_id
    assert seen["auth"] == "token btcpay-test-key"

    # Settlement webhook marks it paid.
    from tests.integration.test_payments import btcpay_signature

    payload = json.dumps({"type": "InvoiceSettled", "invoiceId": "inv_123"}).encode()
    r = await buyer.client.post(
        "/webhooks/btcpay", content=payload, headers={"btcpay-sig": btcpay_signature(payload)}
    )
    assert r.status_code == 200
    status = await db.scalar(select(Offer.status).where(Offer.id == uuid.UUID(offer_id)))
    assert status == "paid"


async def test_offer_rules(make_user, helpers):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)

    # Cannot offer on your own listing.
    plain = {
        "amount_cents": 100,
        "currency": "usd",
        "message": "",
        "expires_at": None,
        "payment_method": "stripe",
    }
    ct = crypto.seal_json(plain)
    r = await seller.api(
        "POST",
        "/api/offers",
        {
            "listing_id": listing_id,
            "offer_ct": crypto.b64e(ct),
            "sig": crypto.b64e(seller.identity.sign("offer", ct)),
        },
    )
    assert r.status_code == 400

    # Only one open offer per buyer and listing.
    await helpers.create_offer(buyer, listing_id)
    ct = crypto.seal_json(plain)
    r = await buyer.api(
        "POST",
        "/api/offers",
        {
            "listing_id": listing_id,
            "offer_ct": crypto.b64e(ct),
            "sig": crypto.b64e(buyer.identity.sign("offer", ct)),
        },
    )
    assert r.status_code == 409

    # Stripe needs fiat; Monero needs XMR (validated after server-side decryption).
    other = await make_user()
    bad = crypto.seal_json(plain | {"currency": "xmr"})
    r = await other.api(
        "POST",
        "/api/offers",
        {
            "listing_id": listing_id,
            "offer_ct": crypto.b64e(bad),
            "sig": crypto.b64e(other.identity.sign("offer", bad)),
        },
    )
    assert r.status_code == 422


async def test_noscript_offer_is_server_signed(make_user, helpers, db):
    seller = await make_user(vendor=True)
    buyer = await make_user(keys=False)
    listing_id = await helpers.create_listing(seller)
    r = await buyer.form(
        f"/listings/{listing_id}/offer",
        {"amount": "19.99", "currency": "usd", "payment_method": "stripe", "message": "hi"},
    )
    assert r.status_code == 303 and "m=offer_sent" in r.headers["location"]
    offer = await db.scalar(select(Offer).where(Offer.buyer_id == buyer.id))
    assert crypto.sig_origin("offer", offer.offer_ct, offer.sig, None) == "server"
    assert crypto.open_json(offer.offer_ct)["amount_cents"] == 1999


async def test_dispute_flow(make_user, helpers, db):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    offer_id = await helpers.create_offer(buyer, listing_id)
    r = await buyer.api("POST", f"/offers/{offer_id}/dispute")
    assert r.status_code == 409  # not paid yet
    await helpers.set_offer_status(db, offer_id, "paid")
    r = await seller.api("POST", f"/offers/{offer_id}/dispute")
    assert r.status_code == 200 and r.json()["status"] == "disputed"
