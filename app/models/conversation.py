import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import User


class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        UniqueConstraint("participant1_id", "participant2_id", "listing_id", name="participants"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    # Always stored with participant1_id < participant2_id so the unique constraint holds.
    participant1_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    participant2_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    listing_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("listings.id"))
    offer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("offers.id"))
    participant1_read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    participant2_read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    participant1: Mapped[User] = relationship(foreign_keys=[participant1_id], lazy="joined")
    participant2: Mapped[User] = relationship(foreign_keys=[participant2_id], lazy="joined")

    def has(self, user_id: uuid.UUID) -> bool:
        return user_id in (self.participant1_id, self.participant2_id)

    def other(self, user_id: uuid.UUID) -> User:
        return self.participant2 if user_id == self.participant1_id else self.participant1
