import uuid
from enum import StrEnum

from fastapi_users import schemas
from pydantic import BaseModel, Field

HANDLE_PATTERN = r"^[a-z0-9_]{3,32}$"


class UserRole(StrEnum):
    USER = "user"
    VENDOR = "vendor"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class UserRead(schemas.BaseUser[uuid.UUID]):
    handle: str
    is_vendor: bool


class UserCreate(schemas.BaseUserCreate):
    handle: str = Field(pattern=HANDLE_PATTERN)


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_vendor: bool | None = None
    is_active: bool | None = None


class PublicKeys(BaseModel):
    user_id: uuid.UUID
    handle: str
    signing_pubkey: str | None
    exchange_pubkey: str | None


class KeysUpload(BaseModel):
    signing_pubkey: str
    exchange_pubkey: str
    profile_enc_key: str
    # Ed25519 signature by the new signing key over keys_payload(): proof of possession.
    proof: str
