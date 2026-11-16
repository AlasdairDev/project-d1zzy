import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import User

ACTION_TYPES = (
    "hide_listing",
    "unhide_listing",
    "suspend_user",
    "unsuspend_user",
    "delete_message",
    "warn_user",
    "resolve_dispute",
)


class ModerationAction(Base):
    __tablename__ = "moderation_actions"
    __table_args__ = (CheckConstraint(f"action_type IN {ACTION_TYPES!r}", name="action_type"),)

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    moderator_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    action_type: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str] = mapped_column(Text)
    target_id: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    moderator: Mapped[User] = relationship(lazy="joined")
