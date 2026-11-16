"""BTCPay Server Greenfield API client (Lightning / on-chain invoices).

Docs: https://docs.btcpayserver.org/API/Greenfield/v1/
"""

import hashlib
import hmac
import uuid

import httpx

from app.config import get_settings

SETTLED = {"Settled"}
FAILED = {"Expired", "Invalid"}


class BTCPayError(RuntimeError):
    pass


class BTCPayClient:
    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        store_id: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        s = get_settings()
        self.store_id = store_id or s.btcpay_store_id
        self._client = httpx.AsyncClient(
            base_url=(url or s.btcpay_url).rstrip("/"),
            headers={"Authorization": f"token {api_key or s.btcpay_api_key}"},
            timeout=20.0,
            transport=transport,
        )

    async def __aenter__(self) -> "BTCPayClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            r = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise BTCPayError(f"BTCPay unreachable: {e}") from e
        if r.status_code >= 400:
            raise BTCPayError(f"BTCPay {path}: {r.status_code} {r.text[:200]}")
        return r.json()

    async def create_invoice(
        self, *, offer_id: uuid.UUID, amount: str, currency: str, redirect_url: str
    ) -> dict:
        """amount is a decimal string in `currency` (BTCPay converts fiat at its own rate)."""
        return await self._request(
            "POST",
            f"/api/v1/stores/{self.store_id}/invoices",
            json={
                "amount": amount,
                "currency": currency.upper(),
                "metadata": {"orderId": str(offer_id)},
                "checkout": {
                    "redirectURL": redirect_url,
                    "paymentMethods": ["BTC-LightningNetwork", "BTC"],
                },
            },
        )

    async def get_invoice(self, invoice_id: str) -> dict:
        return await self._request("GET", f"/api/v1/stores/{self.store_id}/invoices/{invoice_id}")


def verify_webhook(payload: bytes, sig_header: str | None, secret: str | None = None) -> bool:
    """BTCPay sends `BTCPay-Sig: sha256=<hex HMAC of body>`."""
    secret = secret if secret is not None else get_settings().btcpay_webhook_secret
    if not secret or not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header.removeprefix("sha256="))
