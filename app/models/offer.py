import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.listing import Listing
from app.models.user import User

OFFER_STATUSES = ("pending", "accepted", "rejected", "expired", "paid", "disputed", "completed")
PAYMENT_METHODS = ("stripe", "lightning", "monero", "gcash", "maya", "paymongo", "paypal", "cod")

# Platform fee in basis points (5% = 500 basis points)
PLATFORM_FEE_BPS = 500


class Offer(Base):
    __tablename__ = "offers"
    __table_args__ = (CheckConstraint(f"status IN {OFFER_STATUSES!r}", name="status"),)

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    listing_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    buyer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # {amount_cents, currency, message, expires_at, payment_method, shipping_carrier,
    #  shipping_tracking_number, shipping_tracking_url}
    offer_ct: Mapped[bytes] = mapped_column(LargeBinary)
    sig: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(
        Text, default="pending", server_default="pending", index=True
    )
    # Stripe session id / BTCPay invoice id / Monero address
    payment_ref: Mapped[str | None] = mapped_column(Text)
    # Shipping/tracking
    shipping_carrier: Mapped[str | None] = mapped_column(Text)
    shipping_tracking_number: Mapped[str | None] = mapped_column(Text)
    shipping_tracking_url: Mapped[str | None] = mapped_column(Text)
    shipping_status: Mapped[str | None] = mapped_column(
        Text
    )  # shipped, in_transit, delivered, etc.
    shipped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Platform fees and payout
    platform_fee_percent: Mapped[int] = mapped_column(default=500)  # basis points (5% = 500)
    platform_fee_cents: Mapped[int] = mapped_column(default=0)
    gateway_fee_cents: Mapped[int] = mapped_column(default=0)
    seller_payout_cents: Mapped[int] = mapped_column(default=0)
    payout_status: Mapped[str] = mapped_column(
        default="pending"
    )  # pending, processing, paid, failed
    payout_ref: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    listing: Mapped[Listing] = relationship(lazy="joined")
    buyer: Mapped[User] = relationship(lazy="joined")
