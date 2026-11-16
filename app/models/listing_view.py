import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.listing import Listing
from app.models.user import User


class ListingView(Base):
    """Track views of listings for analytics."""

    __tablename__ = "listing_views"
    __table_args__ = (
        Index("idx_listing_view_listing_created", "listing_id", "created_at"),
        Index("idx_listing_view_user_created", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    listing_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    ip_hash: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # Hashed IP for anonymous tracking
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    listing: Mapped["Listing"] = relationship(lazy="joined")
    user: Mapped["User | None"] = relationship(lazy="joined")
