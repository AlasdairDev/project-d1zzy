import uuid
from datetime import datetime
from enum import StrEnum

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
from app.models.listing import Listing
from app.models.user import User


class DiscussionType(StrEnum):
    QUESTION = "question"
    REVIEW = "review"
    ANNOUNCEMENT = "announcement"
    DISCUSSION = "discussion"


class Discussion(Base):
    __tablename__ = "discussions"
    __table_args__ = (
        CheckConstraint(
            "type IN ('question', 'review', 'announcement', 'discussion')", name="discussion_type"
        ),
        Index("idx_discussion_listing_type", "listing_id", "type"),
        Index("idx_discussion_parent", "parent_id"),
        Index("idx_discussion_created", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    listing_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("listings.id", ondelete="CASCADE"), index=True, nullable=True
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("discussions.id", ondelete="CASCADE"), index=True, nullable=True
    )
    type: Mapped[str] = mapped_column(Text, default="discussion", server_default="discussion")
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_ct: Mapped[bytes] = mapped_column(LargeBinary)
    sig: Mapped[bytes] = mapped_column(LargeBinary)
    # For reviews
    rating: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Moderation
    is_pinned: Mapped[bool] = mapped_column(default=False, server_default="false")
    is_locked: Mapped[bool] = mapped_column(default=False, server_default="false")
    is_hidden: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Counters
    upvotes: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    downvotes: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    reply_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    listing: Mapped[Listing | None] = relationship(lazy="joined")
    author: Mapped[User] = relationship(foreign_keys=[author_id], lazy="joined")
    parent: Mapped["Discussion | None"] = relationship(
        remote_side="Discussion.id", backref="replies", lazy="joined"
    )
    upvoters: Mapped[list["DiscussionVote"]] = relationship(
        back_populates="discussion", foreign_keys="DiscussionVote.discussion_id"
    )


class DiscussionVote(Base):
    __tablename__ = "discussion_votes"
    __table_args__ = (CheckConstraint("vote IN (1, -1)", name="vote_value"),)

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    discussion_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discussions.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    vote: Mapped[int] = mapped_column(Integer)  # 1 for upvote, -1 for downvote
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    discussion: Mapped["Discussion"] = relationship(back_populates="upvoters")
    user: Mapped["User"] = relationship()


class DiscussionReport(Base):
    __tablename__ = "discussion_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    discussion_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discussions.id", ondelete="CASCADE"), index=True
    )
    reporter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(Text)
    details_ct: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    status: Mapped[str] = mapped_column(
        Text, default="open", server_default="open"
    )  # open, reviewed, dismissed, actioned
    moderator_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    discussion: Mapped["Discussion"] = relationship()
    reporter: Mapped[User] = relationship(foreign_keys=[reporter_id])
    moderator: Mapped[User | None] = relationship(foreign_keys=[moderator_id])
