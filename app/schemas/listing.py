import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field

from app.models.listing import CATEGORIES

CURRENCIES = ("usd", "eur", "gbp", "sgd", "php", "btc", "xmr")
FIAT = ("usd", "eur", "gbp", "sgd", "php")
# This deployment is Philippines-only; the UI offers PHP while the schema keeps the wider
# set for tests and older data.
MARKET_CURRENCIES = ("php",)
CONDITIONS = ("new", "like_new", "good", "fair", "for_parts")
IMAGE_MIMES = ("image/jpeg", "image/png", "image/webp", "image/gif")


class ListingImage(BaseModel):
    cid: str = Field(min_length=10, max_length=128, pattern=r"^[a-zA-Z0-9]+$")
    key: str = Field(min_length=44, max_length=44)  # base64 of 32 bytes
    mime: str = Field(pattern="^(" + "|".join(IMAGE_MIMES) + ")$")


class ListingPlain(BaseModel):
    """Plaintext inside listing_ct. Validated server-side after decrypting with the market
    key, so a client cannot store garbage or oversized content."""

    title: str = Field(min_length=3, max_length=120)
    desc: str = Field(default="", max_length=5000)
    price_cents: int = Field(ge=0, le=1_000_000_000)
    currency: str = Field(pattern="^(" + "|".join(CURRENCIES) + ")$")
    category: str = Field(pattern="^(" + "|".join(CATEGORIES) + ")$")
    condition: str = Field(pattern="^(" + "|".join(CONDITIONS) + ")$")
    images: list[ListingImage] = Field(default_factory=list, max_length=8)
    location_approx: str = Field(default="", max_length=80)
    expires_at: date | None = None


class SignedBlob(BaseModel):
    ct: str  # base64
    sig: str  # base64


class ListingOut(BaseModel):
    id: uuid.UUID
    seller_id: uuid.UUID
    seller_handle: str
    seller_signing_pubkey: str | None
    listing_ct: str
    sig: str
    status: str
    created_at: datetime
