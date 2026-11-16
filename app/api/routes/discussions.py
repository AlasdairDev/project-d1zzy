"""Discussions: Q&A, reviews, announcements, and general discussions on listings."""

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, optional_user, render
from app.core import crypto
from app.core.queue import queue
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Discussion, DiscussionVote, Listing, User
from app.schemas.discussion import (
    DiscussionCreate,
    DiscussionReportCreate,
    DiscussionUpdate,
    DiscussionVoteCreate,
)

router = APIRouter()
log = structlog.get_logger()

MAX_PLAINTEXT = 10000


async def _discussion_or_404(
    session: AsyncSession,
    discussion_id: uuid.UUID,
    user: User | None = None,
    require_active: bool = True,
) -> "Discussion":
    from app.models import Discussion

    d = await session.get(Discussion, discussion_id)
    if d is None:
        raise HTTPException(404, "Discussion not found")
    if d.is_hidden and not (user and user.is_superuser):
        raise HTTPException(404, "Discussion not found")
    return d


async def _user_vote(
    session: AsyncSession, discussion_id: uuid.UUID, user_id: uuid.UUID
) -> int | None:
    v = await session.scalar(
        select(DiscussionVote).where(
            DiscussionVote.discussion_id == discussion_id,
            DiscussionVote.user_id == user_id,
        )
    )
    return v.vote if v else None


# --- Pages ------------------------------------------------------------------------------


@router.get("/listings/{listing_id}/discussions")
async def listing_discussions_page(
    request: Request,
    listing_id: uuid.UUID,
    type: str | None = Query(None),
    page: int = 1,
    sort: str = "newest",  # newest, oldest, top, controversial
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    from app.models import Discussion, Listing

    listing = await session.get(Listing, listing_id)
    if not listing or listing.status != "active":
        raise HTTPException(404, "Listing not found")

    q = select(Discussion).where(
        Discussion.listing_id == listing_id,
        Discussion.parent_id.is_(None),  # only top-level threads
    )
    if type:
        q = q.where(Discussion.type == type)

    if sort == "newest":
        q = q.order_by(Discussion.created_at.desc())
    elif sort == "oldest":
        q = q.order_by(Discussion.created_at.asc())
    elif sort == "top":
        q = q.order_by((Discussion.upvotes - Discussion.downvotes).desc())
    elif sort == "controversial":
        q = q.order_by((Discussion.upvotes + Discussion.downvotes).desc())

    offset = (page - 1) * 20
    discussions = (await session.scalars(q.offset(offset).limit(20))).all()

    user_votes = {}
    if user:
        votes = await session.scalars(
            select(DiscussionVote).where(
                DiscussionVote.discussion_id.in_([d.id for d in discussions]),
                DiscussionVote.user_id == user.id,
            )
        )
        user_votes = {v.discussion_id: v.vote for v in votes}

    return render(
        request,
        "pages/listing_discussions.html",
        {
            "listing": listing,
            "discussions": discussions,
            "user_votes": user_votes,
            "current_type": type,
            "sort": sort,
            "page": page,
        },
        user=user,
    )


# --- API Routes ---------------------------------------------------------------------


@router.get("/api/discussions/{discussion_id}")
async def api_discussion(
    discussion_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    d = await _discussion_or_404(session, discussion_id, user)
    user_vote = await _user_vote(session, d.id, user.id) if user else None
    plain = None
    try:
        from app.core.market import open_discussion_ct

        plain = open_discussion_ct(d.content_ct)
    except Exception:
        pass

    return {
        "id": str(d.id),
        "listing_id": str(d.listing_id) if d.listing_id else None,
        "author_id": str(d.author_id),
        "author_handle": d.author.handle,
        "author_signing_pubkey": crypto.b64e(d.author.signing_pubkey)
        if d.author.signing_pubkey
        else None,
        "parent_id": str(d.parent_id) if d.parent_id else None,
        "type": d.type,
        "title": d.title,
        "content": plain.content if plain else "",
        "rating": d.rating,
        "is_pinned": d.is_pinned,
        "is_locked": d.is_locked,
        "is_hidden": d.is_hidden,
        "upvotes": d.upvotes,
        "downvotes": d.downvotes,
        "reply_count": d.reply_count,
        "created_at": d.created_at.isoformat(),
        "updated_at": d.updated_at.isoformat(),
        "edited_at": d.edited_at.isoformat() if d.edited_at else None,
        "user_vote": user_vote,
        "signed_by": crypto.sig_origin("discussion", d.content_ct, d.sig, d.author.signing_pubkey),
    }


@router.post("/api/discussions", status_code=201, dependencies=[Depends(csrf_protect)])
async def api_create_discussion(
    body: "DiscussionCreate",
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(current_user),
):

    # Verify listing exists if provided
    if body.listing_id:
        listing = await session.get(Listing, body.listing_id)
        if not listing or listing.status != "active":
            raise HTTPException(404, "Listing not found")

    if body.parent_id:
        parent = await session.get(Discussion, body.parent_id)
        if not parent:
            raise HTTPException(404, "Parent discussion not found")
        if parent.is_locked:
            raise HTTPException(409, "Discussion is locked")

    plain = {
        "title": body.title,
        "content": body.content,
        "type": body.type,
        "rating": body.rating,
    }
    ct = crypto.seal_json(plain)
    sig = crypto.server_sign(
        "discussion",
        crypto.seal_json({"title": body.title, "content": body.content, "type": body.type}),
    )

    d = Discussion(
        listing_id=body.listing_id,
        author_id=user.id,
        parent_id=body.parent_id,
        type=body.type,
        title=body.title,
        content_ct=ct,
        sig=sig,
        rating=body.rating,
    )
    session.add(d)
    if body.parent_id:
        parent = await session.get(Discussion, body.parent_id)
        parent.reply_count = (parent.reply_count or 0) + 1
    await session.commit()
    await session.refresh(d)

    # Notify listing seller if this is a question/review on their listing
    if d.listing_id:
        listing = await session.get(Listing, d.listing_id)
        if listing and listing.seller_id != user.id:
            await queue.enqueue(
                "relay_notifications",
                str(listing.seller_id),
                f"New {d.type} on your listing: {d.title or 'Discussion'}",
                f"/listings/{d.listing_id}/discussions",
            )

    return {"id": str(d.id)}


@router.patch("/api/discussions/{discussion_id}", dependencies=[Depends(csrf_protect)])
async def api_update_discussion(
    discussion_id: uuid.UUID,
    body: "DiscussionUpdate",
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(current_user),
):

    d = await _discussion_or_404(session, discussion_id, user)
    if d.author_id != user.id and not user.is_superuser:
        raise HTTPException(403, "Not your discussion")
    if d.is_locked:
        raise HTTPException(409, "Discussion is locked")

    plain = {
        "title": body.title
        if body.title is not None
        else (await open_discussion_ct(d.content_ct)).title,
        "content": body.content
        if body.content is not None
        else (await open_discussion_ct(d.content_ct)).content,
        "type": (await open_discussion_ct(d.content_ct)).type,
        "rating": (await open_discussion_ct(d.content_ct)).rating,
    }
    if body.title is not None:
        plain["title"] = body.title
    if body.content is not None:
        plain["content"] = body.content
    plain["edited_at"] = datetime.now(UTC).isoformat()

    d.content_ct = crypto.seal_json(plain)
    d.sig = crypto.server_sign(
        "discussion",
        crypto.seal_json(
            {"title": plain["title"], "content": plain["content"], "type": plain["type"]}
        ),
    )
    d.updated_at = datetime.now(UTC)
    d.edited_at = datetime.now(UTC)
    await session.commit()

    return {"id": str(d.id), "updated_at": d.updated_at.isoformat()}


@router.post("/api/discussions/{discussion_id}/vote", dependencies=[Depends(csrf_protect)])
async def vote_discussion(
    discussion_id: uuid.UUID,
    body: "DiscussionVoteCreate",
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(current_user),
):

    d = await _discussion_or_404(session, discussion_id)
    if d.is_locked:
        raise HTTPException(409, "Discussion is locked")

    existing = await session.scalar(
        select(DiscussionVote).where(
            DiscussionVote.discussion_id == discussion_id,
            DiscussionVote.user_id == user.id,
        )
    )

    if existing:
        if existing.vote == body.vote:
            # Remove vote
            await session.delete(existing)
            if body.vote == 1:
                d.upvotes -= 1
            else:
                d.downvotes -= 1
        else:
            # Change vote
            if existing.vote == 1:
                d.upvotes -= 1
                d.downvotes += 1
            else:
                d.upvotes += 1
                d.downvotes -= 1
            existing.vote = body.vote
    else:
        session.add(DiscussionVote(discussion_id=discussion_id, user_id=user.id, vote=body.vote))
        if body.vote == 1:
            d.upvotes += 1
        else:
            d.downvotes += 1

    await session.commit()
    return {"upvotes": d.upvotes, "downvotes": d.downvotes, "user_vote": body.vote}


@router.post("/api/discussions/{discussion_id}/report", dependencies=[Depends(csrf_protect)])
async def report_discussion(
    discussion_id: uuid.UUID,
    body: "DiscussionReportCreate",
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(current_user),
):
    from app.models import DiscussionReport

    await _discussion_or_404(session, discussion_id)
    existing = await session.scalar(
        select(DiscussionReport).where(
            DiscussionReport.discussion_id == discussion_id,
            DiscussionReport.reporter_id == user.id,
        )
    )
    if existing:
        raise HTTPException(409, "Already reported")

    details_ct = crypto.seal_json({"text": body.details}) if body.details else None
    report = DiscussionReport(
        discussion_id=discussion_id,
        reporter_id=user.id,
        reason=body.reason,
        details_ct=details_ct,
    )
    session.add(report)
    await session.commit()
    return {"ok": True}


# --- Helpers ---------------------------------------------------------------------------


async def _discussion_or_404(
    session: AsyncSession,
    discussion_id: uuid.UUID,
    user: User | None = None,
) -> "Discussion":
    from app.models import Discussion

    d = await session.get(Discussion, discussion_id)
    if d is None:
        raise HTTPException(404, "Discussion not found")
    if d.is_hidden and not (user and user.is_superuser):
        raise HTTPException(404, "Discussion not found")
    return d


async def _user_vote(
    session: AsyncSession, discussion_id: uuid.UUID, user_id: uuid.UUID
) -> int | None:
    v = await session.scalar(
        select(DiscussionVote).where(
            DiscussionVote.discussion_id == discussion_id,
            DiscussionVote.user_id == user_id,
        )
    )
    return v.vote if v else None


async def open_discussion_ct(ct: bytes):
    from app.core.market import open_discussion_ct as _open

    return _open(ct)
