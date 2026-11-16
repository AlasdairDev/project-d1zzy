import enum
from datetime import datetime

from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID
from sqlalchemy import Boolean, DateTime, Enum, LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserRole(enum.StrEnum):
    USER = "user"
    VENDOR = "vendor"
    MODERATOR = "moderator"  # Content moderator (can hide listings, warn users)
    ADMIN = "admin"  # Full moderation + manage vendors, disputes
    SUPERADMIN = "superadmin"  # Full platform control, manage admins


class User(SQLAlchemyBaseUserTableUUID, Base):
    __tablename__ = "users"

    # Public pseudonym shown instead of the email address.
    handle: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=False, length=16),
        default=UserRole.USER,
        server_default=UserRole.USER.value,
        nullable=False,
    )
    is_vendor: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    vendor_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vendor_bio_ct: Mapped[bytes | None] = mapped_column(LargeBinary)
    vendor_avatar_cid: Mapped[str | None] = mapped_column(Text)
    # Verification workflow
    vendor_application_submitted: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    vendor_application_reviewed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    vendor_application_notes: Mapped[str | None] = mapped_column(Text)
    signing_pubkey: Mapped[bytes | None] = mapped_column(LargeBinary)  # Ed25519, 32 bytes
    exchange_pubkey: Mapped[bytes | None] = mapped_column(LargeBinary)  # X25519, 32 bytes
    profile_enc_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # X25519, 32 bytes
    # Response metrics
    response_rate: Mapped[int] = mapped_column(default=0, server_default="0")  # percentage 0-100
    response_time_minutes: Mapped[int] = mapped_column(
        default=0, server_default="0"
    )  # average minutes
    messages_received: Mapped[int] = mapped_column(default=0, server_default="0")
    messages_replied: Mapped[int] = mapped_column(default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def is_superadmin(self) -> bool:
        return self.role == UserRole.SUPERADMIN

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN  # Only ADMIN, not SUPERADMIN

    @property
    def is_superadmin_or_admin(self) -> bool:
        """Check if user is admin or superadmin (for backward compat)"""
        return self.role in (UserRole.ADMIN, UserRole.SUPERADMIN)

    @property
    def is_moderator_or_above(self) -> bool:
        """Check if user is moderator, admin, or superadmin"""
        return self.role in (UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPERADMIN)

    @property
    def is_vendor_active(self) -> bool:
        return self.is_vendor and self.role == UserRole.VENDOR

    @property
    def can_moderate(self) -> bool:
        return self.role in (UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPERADMIN)

    @property
    def can_access_admin_panel(self) -> bool:
        return self.role in (UserRole.ADMIN, UserRole.SUPERADMIN)

    @property
    def can_manage_admins(self) -> bool:
        """Only superadmin can manage other admins"""
        return self.role == UserRole.SUPERADMIN

    @property
    def can_manage_moderators(self) -> bool:
        """Admin and superadmin can manage moderators"""
        return self.role in (UserRole.ADMIN, UserRole.SUPERADMIN)
