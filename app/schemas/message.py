import json
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.core.crypto import b64d

MAX_HEADER = 512
MAX_CIPHERTEXT = 16 * 1024


class RatchetMessageIn(BaseModel):
    header: str = Field(max_length=MAX_HEADER * 2)
    ciphertext: str = Field(max_length=MAX_CIPHERTEXT * 2)

    @field_validator("header")
    @classmethod
    def _header_shape(cls, v: str) -> str:
        raw = b64d(v)
        if len(raw) > MAX_HEADER:
            raise ValueError("header too large")
        try:
            h = json.loads(raw)
        except ValueError as e:
            raise ValueError("header must be JSON") from e
        if not isinstance(h, dict) or not isinstance(h.get("n"), int):
            raise ValueError("header must contain n")
        if not (h.get("i") == 1 or isinstance(h.get("dh"), str)):
            raise ValueError("header must contain dh or i")
        return v

    @field_validator("ciphertext")
    @classmethod
    def _ct_size(cls, v: str) -> str:
        if not 40 <= len(b64d(v)) <= MAX_CIPHERTEXT:
            raise ValueError("ciphertext size out of range")
        return v


class MessageOut(BaseModel):
    id: int
    conversation_id: uuid.UUID
    sender_id: uuid.UUID
    header: str
    ciphertext: str
    mode: str  # "ratchet" | "server"
    plaintext: str | None = None  # only for server-mode (no-JS) messages
    created_at: datetime
