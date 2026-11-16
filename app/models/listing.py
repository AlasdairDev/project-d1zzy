import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import User

LISTING_STATUSES = ("active", "sold", "removed", "expired", "hidden")
CATEGORIES = (
    "electronics",
    "fashion",
    "home",
    "books",
    "collectibles",
    "sports",
    "services",
    "other",
)
# Material Symbols ligature names, shown on the category cards.
CATEGORY_ICONS = {
    "electronics": "devices",
    "fashion": "checkroom",
    "home": "chair",
    "books": "menu_book",
    "collectibles": "diamond",
    "sports": "sports_basketball",
    "services": "handyman",
    "other": "category",
}


class Listing(Base):
    __tablename__ = "listings"
    __table_args__ = (
        CheckConstraint(f"status IN {LISTING_STATUSES!r}", name="status"),
        Index("idx_listings_status_created", "status", text("created_at DESC")),
        Index("idx_listings_price_cents", "price_cents"),
        Index("idx_listings_condition", "condition"),
        Index("idx_listings_location_approx", "location_approx"),
        Index("idx_listings_view_count", "view_count"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    seller_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # XChaCha20-Poly1305 (market key): {title, desc, price_cents, currency, category,
    # condition, images[], location_approx, expires_at}
    listing_ct: Mapped[bytes] = mapped_column(LargeBinary)
    sig: Mapped[bytes] = mapped_column(LargeBinary)  # Ed25519 over "d1zzy:listing:v1" || ct
    # Extracted from the plaintext so the category grid works without decrypting everything.
    category: Mapped[str] = mapped_column(Text, index=True, default="other")
    # Filterable fields (stored in plaintext for search/filtering)
    price_cents: Mapped[int] = mapped_column(Integer, default=0, index=True)
    condition: Mapped[str] = mapped_column(Text, default="good", index=True)
    location_approx: Mapped[str] = mapped_column(Text, index=True, default="", server_default="")
    status: Mapped[str] = mapped_column(Text, default="active", server_default="active")
    # Analytics
    view_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    report_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    seller: Mapped["User"] = relationship(lazy="joined")
