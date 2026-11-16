import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.listing import Listing
from app.models.user import User


class SavedItem(Base):
    """User's saved/bookmarked listings."""

    __tablename__ = "saved_items"
    __table_args__ = (
        Index("idx_saved_item_user_created", "user_id", "created_at"),
        # A user can only save a listing once
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    listing_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User"] = relationship(foreign_keys=[user_id], lazy="joined")
    listing: Mapped["Listing"] = relationship(lazy="joined")


class Follow(Base):
    """User follows another user (shop)."""

    __tablename__ = "follows"
    __table_args__ = (
        Index("idx_follow_follower_created", "follower_id", "created_at"),
        Index("idx_follow_following_created", "following_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    follower_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    following_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    follower: Mapped["User"] = relationship(
        foreign_keys=[follower_id], backref="following", lazy="joined"
    )
    following: Mapped["User"] = relationship(
        foreign_keys=[following_id], backref="followers", lazy="joined"
    )
