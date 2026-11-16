import uuid
from enum import StrEnum

from pydantic import BaseModel, Field


class DiscussionTypeSchema(StrEnum):
    QUESTION = "question"
    REVIEW = "review"
    ANNOUNCEMENT = "announcement"
    DISCUSSION = "discussion"


class DiscussionPlain(BaseModel):
    """Plaintext inside discussion content_ct."""

    title: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1, max_length=10000)
    type: DiscussionTypeSchema = "discussion"
    rating: int | None = Field(default=None, ge=1, le=5)


class DiscussionCreate(BaseModel):
    listing_id: uuid.UUID | None = None
    parent_id: uuid.UUID | None = None
    type: str = "discussion"
    title: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1, max_length=10000)
    rating: int | None = Field(default=None, ge=1, le=5)


class DiscussionUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    content: str | None = Field(default=None, max_length=10000)


class DiscussionOut(BaseModel):
    id: uuid.UUID
    listing_id: uuid.UUID | None
    author_id: uuid.UUID
    author_handle: str
    author_signing_pubkey: str | None
    parent_id: uuid.UUID | None
    type: str
    title: str | None
    content: str
    rating: int | None
    is_pinned: bool
    is_locked: bool
    is_hidden: bool
    upvotes: int
    downvotes: int
    reply_count: int
    created_at: str
    updated_at: str
    edited_at: str | None
    user_vote: int | None  # 1, -1, or None
    signed_by: str | None  # "user" | "server" | None


class DiscussionVoteCreate(BaseModel):
    vote: int = Field(ge=-1, le=1)  # 1 or -1


class DiscussionReportCreate(BaseModel):
    reason: str = Field(min_length=1, max_length=100)
    details: str | None = Field(default=None, max_length=1000)
