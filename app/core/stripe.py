"""Stripe Checkout (test mode only).

Funds land in the platform account. Paying sellers out requires Stripe Connect, which is
not implemented; the vendor dashboard reports what each seller is owed.
"""

import asyncio
import uuid

import stripe

from app.config import get_settings


class StripeNotConfigured(RuntimeError):
    pass


def _client() -> stripe.StripeClient:
    s = get_settings()
    if not s.stripe_enabled:
        raise StripeNotConfigured("STRIPE_SECRET_KEY must be an sk_test_ key")
    return stripe.StripeClient(s.stripe_secret_key)


async def create_checkout_session(
    *, offer_id: uuid.UUID, amount_cents: int, currency: str, title: str
) -> tuple[str, str]:
    """Returns (session_id, checkout_url)."""
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    params = {
        "mode": "payment",
        "line_items": [
            {
                "quantity": 1,
                "price_data": {
                    "currency": currency,
                    "unit_amount": amount_cents,
                    "product_data": {"name": title[:120]},
                },
            }
        ],
        "client_reference_id": str(offer_id),
        "metadata": {"offer_id": str(offer_id)},
        "success_url": f"{base}/offers?paid={offer_id}",
        "cancel_url": f"{base}/offers",
    }
    session = await asyncio.to_thread(_client().checkout.sessions.create, params=params)
    return session.id, session.url


async def retrieve_session_status(session_id: str) -> str:
    """'paid' | 'unpaid' | 'no_payment_required'"""
    session = await asyncio.to_thread(_client().checkout.sessions.retrieve, session_id)
    return session.payment_status


def construct_event(payload: bytes, sig_header: str) -> dict:
    """Verifies the Stripe-Signature header (and its timestamp, against replays) and returns
    the event as a plain dict. Raises stripe.SignatureVerificationError."""
    secret = get_settings().stripe_webhook_secret
    if not secret or "..." in secret:
        raise StripeNotConfigured("STRIPE_WEBHOOK_SECRET not set")
    return stripe.Webhook.construct_event(payload, sig_header, secret).to_dict()
