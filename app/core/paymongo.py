"""PayMongo integration for GCash, Maya, Card, and Bank Transfer payments.
Docs: https://developers.paymongo.com/reference
"""

import base64
import json
from typing import Any

import httpx

from app.config import get_settings


class PayMongoError(RuntimeError):
    pass


class PayMongoClient:
    def __init__(self, secret_key: str | None = None):
        s = get_settings()
        self.secret_key = secret_key or s.paymongo_secret_key
        if not self.secret_key:
            raise PayMongoError("PAYMONGO_SECRET_KEY not configured")

        self.base_url = "https://api.paymongo.com/v1"
        auth = base64.b64encode(f"{self.secret_key}:".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(timeout=30.0, headers=self.headers)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def _request(self, method: str, endpoint: str, json_data: dict | None = None) -> Any:
        try:
            r = await self._client.request(method, f"{self.base_url}{endpoint}", json=json_data)
        except httpx.HTTPError as e:
            raise PayMongoError(f"PayMongo request failed: {e}") from e

        if r.status_code >= 400:
            raise PayMongoError(f"PayMongo error {r.status_code}: {r.text}")
        return r.json()

    async def create_payment_intent(
        self,
        amount_cents: int,
        currency: str = "PHP",
        payment_method_allowed: list[str] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create a PaymentIntent for GCash, Maya, Card, or Bank Transfer."""
        allowed = payment_method_allowed or ["gcash", "maya", "card", "dob"]
        data = {
            "data": {
                "attributes": {
                    "amount": amount_cents,
                    "currency": currency.upper(),
                    "payment_method_allowed": allowed,
                    "metadata": metadata or {},
                }
            }
        }
        return await self._request("POST", "/payment_intents", data)

    async def create_checkout_session(
        self,
        amount_cents: int,
        currency: str = "PHP",
        success_url: str = "",
        cancel_url: str = "",
        payment_method_allowed: list[str] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create a Checkout Session for hosted payment page (redirect flow)."""
        allowed = payment_method_allowed or ["gcash", "maya", "card", "dob"]
        data = {
            "data": {
                "attributes": {
                    "amount": amount_cents,
                    "currency": currency.upper(),
                    "payment_method_allowed": allowed,
                    "success_url": success_url,
                    "cancel_url": cancel_url,
                    "metadata": metadata or {},
                }
            }
        }
        return await self._request("POST", "/checkout_sessions", data)

    async def create_payout(
        self,
        amount_cents: int,
        currency: str = "PHP",
        destination: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create a payout to seller's bank account or e-wallet.

        destination: {"type": "bank_account", "account_number": "...", "bank_code": "...",
        "account_name": "..."}
        """
        data = {
            "data": {
                "attributes": {
                    "amount": amount_cents,
                    "currency": currency.upper(),
                    "destination": destination or {},
                    "metadata": metadata or {},
                }
            }
        }
        return await self._request("POST", "/payouts", data)

    async def verify_webhook(self, payload: bytes, signature: str) -> dict:
        """Verify PayMongo webhook signature."""
        # PayMongo uses HMAC-SHA256 with webhook secret
        import hashlib
        import hmac

        expected = hmac.new(
            get_settings().paymongo_webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise PayMongoError("Invalid webhook signature")

        return json.loads(payload)
