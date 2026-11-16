import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, SmallInteger, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import User


class Rating(Base):
    __tablename__ = "ratings"
    __table_args__ = (UniqueConstraint("rater_id", "offer_id", name="rater_offer"),)

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    rater_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    subject_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    # Extracted from the plaintext so "one rating per completed offer" is enforceable.
    offer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("offers.id", ondelete="CASCADE"))
    score: Mapped[int] = mapped_column(SmallInteger)
    rating_ct: Mapped[bytes] = mapped_column(LargeBinary)  # {score, note, listing_id, offer_id}
    sig: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    rater: Mapped[User] = relationship(foreign_keys=[rater_id], lazy="joined")
