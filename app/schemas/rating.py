import uuid

from pydantic import BaseModel, Field


class RatingPlain(BaseModel):
    score: int = Field(ge=1, le=5)
    note: str = Field(default="", max_length=500)
    listing_id: uuid.UUID
    offer_id: uuid.UUID


class RatingCreate(BaseModel):
    offer_id: uuid.UUID
    rating_ct: str
    sig: str
