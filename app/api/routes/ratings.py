"""Signed ratings. Only the two parties of a completed offer can rate each other, once."""

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, decode_b64, done, require_user_sig
from app.core import crypto
from app.core.market import notify
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Offer, Rating, User
from app.schemas.rating import RatingCreate, RatingPlain

router = APIRouter()


async def _subject_for(session: AsyncSession, offer_id: uuid.UUID, user: User) -> Offer:
    offer = await session.get(Offer, offer_id)
    if offer is None:
        raise HTTPException(404, "Offer not found")
    if offer.status != "completed":
        raise HTTPException(409, "You can rate only after the order is completed")
    if user.id not in (offer.buyer_id, offer.listing.seller_id):
        raise HTTPException(403)
    return offer


async def _store(session, offer: Offer, user: User, plain: RatingPlain, ct: bytes, sig: bytes):
    subject = offer.listing.seller_id if user.id == offer.buyer_id else offer.buyer_id
    if plain.offer_id != offer.id or plain.listing_id != offer.listing_id:
        raise HTTPException(422, "Rating does not match the offer")
    session.add(
        Rating(
            rater_id=user.id,
            subject_id=subject,
            offer_id=offer.id,
            score=plain.score,
            rating_ct=ct,
            sig=sig,
        )
    )
    try:
        await session.commit()
    except IntegrityError as e:
        raise HTTPException(409, "You already rated this order") from e
    await notify(subject, f"You received a {plain.score}-star rating.")


@router.post("/offers/{offer_id}/rate", dependencies=[Depends(csrf_protect)])
async def rate_form(
    request: Request,
    offer_id: uuid.UUID,
    score: int = Form(),
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _subject_for(session, offer_id, user)
    try:
        plain = RatingPlain(
            score=score, note=note.strip(), listing_id=offer.listing_id, offer_id=offer.id
        )
    except ValidationError as e:
        raise HTTPException(422, "Score must be 1-5") from e
    ct = crypto.seal_json(plain.model_dump(mode="json"))
    await _store(session, offer, user, plain, ct, crypto.server_sign("rating", ct))
    return done(request, "/offers", code="rated")


@router.post("/api/ratings", status_code=201, dependencies=[Depends(csrf_protect)])
async def api_rate(
    body: RatingCreate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    offer = await _subject_for(session, body.offer_id, user)
    ct = decode_b64(body.rating_ct, "rating_ct")
    sig = require_user_sig(user, "rating", ct, body.sig)
    try:
        plain = RatingPlain.model_validate(crypto.open_json(ct))
    except (crypto.CryptoError, ValidationError) as e:
        raise HTTPException(422, f"rating_ct invalid: {e}") from e
    await _store(session, offer, user, plain, ct, sig)
    return {"ok": True}


def rating_row(r: Rating) -> dict:
    try:
        plain = RatingPlain.model_validate(crypto.open_json(r.rating_ct))
    except (crypto.CryptoError, ValidationError):
        plain = None
    return {
        "rating": r,
        "plain": plain,
        "signed_by": crypto.sig_origin("rating", r.rating_ct, r.sig, r.rater.signing_pubkey),
    }


@router.get("/api/users/{user_id}/ratings")
async def api_ratings_for(user_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    """Raw signed blobs so clients can verify each rating against the rater's key."""
    ratings = (
        await session.scalars(
            select(Rating).where(Rating.subject_id == user_id).order_by(Rating.created_at.desc())
        )
    ).unique()
    return {
        "ratings": [
            {
                "id": str(r.id),
                "rater_id": str(r.rater_id),
                "rater_handle": r.rater.handle,
                "rater_signing_pubkey": crypto.b64e(r.rater.signing_pubkey or b""),
                "rating_ct": crypto.b64e(r.rating_ct),
                "sig": crypto.b64e(r.sig),
                "signed_by": crypto.sig_origin(
                    "rating", r.rating_ct, r.sig, r.rater.signing_pubkey
                ),
            }
            for r in ratings
        ]
    }
