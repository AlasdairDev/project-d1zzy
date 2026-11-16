import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import User

REPORT_TARGETS = ("listing", "user", "message")
REPORT_STATUSES = ("open", "reviewed", "dismissed", "actioned")
REPORT_REASONS = (
    "prohibited_item",
    "scam",
    "harassment",
    "spam",
    "counterfeit",
    "illegal",
    "other",
)


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(f"target_type IN {REPORT_TARGETS!r}", name="target_type"),
        CheckConstraint(f"status IN {REPORT_STATUSES!r}", name="status"),
        Index("idx_reports_target", "target_type", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    reporter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    target_type: Mapped[str] = mapped_column(Text)
    # TEXT rather than UUID: message ids are BIGSERIAL.
    target_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    # Market-key sealed. For message reports this carries the plaintext the reporter
    # chose to disclose, which is the only way moderators ever see E2E content.
    details_ct: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(Text, default="open", server_default="open", index=True)
    moderator_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    reporter: Mapped[User] = relationship(foreign_keys=[reporter_id], lazy="joined")
