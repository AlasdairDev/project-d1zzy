import uuid
from datetime import date

from pydantic import BaseModel, Field, model_validator

from app.models.offer import PAYMENT_METHODS
from app.schemas.listing import CURRENCIES, FIAT


class OfferPlain(BaseModel):
    """Plaintext inside offer_ct. amount_cents is in the currency's minor unit
    (cents; for btc/xmr: 1/100 of a coin)."""

    amount_cents: int = Field(gt=0, le=1_000_000_000)
    currency: str = Field(pattern="^(" + "|".join(CURRENCIES) + ")$")
    message: str = Field(default="", max_length=1000)
    expires_at: date | None = None
    payment_method: str = Field(pattern="^(" + "|".join(PAYMENT_METHODS) + ")$")
    # Shipping info (optional, filled by seller after payment)
    shipping_carrier: str | None = Field(default=None, max_length=100)
    shipping_tracking_number: str | None = Field(default=None, max_length=100)
    shipping_tracking_url: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _method_matches_currency(self):
        if self.payment_method == "stripe" and self.currency not in FIAT:
            raise ValueError("Stripe only accepts fiat currencies")
        if self.payment_method == "monero" and self.currency != "xmr":
            raise ValueError("Monero offers must be priced in XMR")
        if (
            self.payment_method in ("gcash", "maya", "paymongo", "paypal")
            and self.currency not in FIAT
        ):
            raise ValueError(f"{self.payment_method} only accepts fiat currencies")
        if self.payment_method == "cod" and self.currency not in FIAT:
            raise ValueError("COD only accepts fiat currencies")
        return self


class OfferCreate(BaseModel):
    listing_id: uuid.UUID
    offer_ct: str
    sig: str
