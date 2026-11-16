"""Saved items and follows."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, done, page_user, render
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Follow, Listing, SavedItem, User

router = APIRouter()


# --- Saved Items ---------------------------------------------------------------------


@router.get("/saved")
async def saved_items_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(page_user),
):
    """User's saved items page."""
    from app.core.market import listing_view
    from app.models import Listing

    saved = (
        await session.scalars(
            select(SavedItem)
            .where(SavedItem.user_id == user.id)
            .order_by(SavedItem.created_at.desc())
        )
    ).all()

    listings = []
    for row in saved:
        listing = await session.get(Listing, row.listing_id)
        if listing and listing.status == "active":
            view = listing_view(listing)
            if view.plain:
                listings.append(view)

    return render(
        request,
        "pages/saved.html",
        {"listings": listings},
        user=user,
    )


@router.post("/listings/{listing_id}/save", dependencies=[Depends(csrf_protect)])
async def save_listing(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(page_user),
):
    """Save/bookmark a listing."""

    listing = await session.get(Listing, listing_id)
    if not listing or listing.status != "active":
        raise HTTPException(404, "Listing not found")

    existing = await session.scalar(
        select(SavedItem).where(
            SavedItem.user_id == user.id,
            SavedItem.listing_id == listing_id,
        )
    )
    if existing:
        raise HTTPException(409, "Already saved")

    saved = SavedItem(user_id=user.id, listing_id=listing_id)
    session.add(saved)
    await session.commit()

    return done(request, "/saved", code="saved")


@router.delete("/listings/{listing_id}/save", dependencies=[Depends(csrf_protect)])
async def unsave_listing(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(page_user),
):
    """Remove a saved listing."""

    saved = await session.scalar(
        select(SavedItem).where(
            SavedItem.user_id == user.id,
            SavedItem.listing_id == listing_id,
        )
    )
    if not saved:
        raise HTTPException(404, "Not saved")

    await session.delete(saved)
    await session.commit()

    return done(request, "/saved", code="unsaved")


@router.get("/api/saved")
async def api_saved(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: "User" = Depends(current_user),
):
    """Check if current user has saved specific listings."""
    ids = request.query_params.getlist("ids")
    if not ids:
        return {"saved": []}

    try:
        parsed_ids = [uuid.UUID(id_str) for id_str in ids]
    except ValueError:
        raise HTTPException(400, "Invalid listing IDs") from None

    saved = await session.scalars(
        select(SavedItem.listing_id).where(
            SavedItem.user_id == user.id,
            SavedItem.listing_id.in_(parsed_ids),
        )
    )

    return {"saved": [str(id) for id in saved]}


# --- Follows ----------------------------------------------------------------------------


@router.post("/users/{user_id}/follow", dependencies=[Depends(csrf_protect)])
async def follow_user(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: "User" = Depends(current_user),
):
    """Follow a user (shop)."""

    if user_id == current_user.id:
        raise HTTPException(400, "Cannot follow yourself")

    target = await session.get(User, user_id)
    if not target or not target.is_active:
        raise HTTPException(404, "User not found")

    if not target.is_vendor:
        raise HTTPException(400, "Can only follow vendors")

    existing = await session.scalar(
        select(Follow).where(
            Follow.follower_id == current_user.id,
            Follow.following_id == user_id,
        )
    )
    if existing:
        raise HTTPException(409, "Already following")

    follow = Follow(follower_id=current_user.id, following_id=user_id)
    session.add(follow)
    await session.commit()

    return {"ok": True, "following": True}


@router.delete("/users/{user_id}/follow", dependencies=[Depends(csrf_protect)])
async def unfollow_user(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: "User" = Depends(current_user),
):
    """Unfollow a user."""

    follow = await session.scalar(
        select(Follow).where(
            Follow.follower_id == current_user.id,
            Follow.following_id == user_id,
        )
    )
    if not follow:
        raise HTTPException(404, "Not following")

    await session.delete(follow)
    await session.commit()

    return {"ok": True, "following": False}


@router.get("/users/{user_id}/followers")
async def user_followers(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Get user's followers."""
    from app.models import User

    target = await session.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")

    follows = (
        await session.scalars(
            select(Follow).where(Follow.following_id == user_id).order_by(Follow.created_at.desc())
        )
    ).all()

    followers = []
    for f in follows:
        follower = await session.get(User, f.follower_id)
        if follower:
            followers.append(
                {
                    "id": str(follower.id),
                    "handle": follower.handle,
                    "avatar_cid": follower.vendor_avatar_cid,
                    "followed_at": f.created_at.isoformat(),
                }
            )

    return {"followers": followers}


@router.get("/users/{user_id}/following")
async def user_following(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Get users this user is following."""
    from app.models import User

    target = await session.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")

    follows = (
        await session.scalars(
            select(Follow).where(Follow.follower_id == user_id).order_by(Follow.created_at.desc())
        )
    ).all()

    following = []
    for f in follows:
        followed = await session.get(User, f.following_id)
        if followed:
            following.append(
                {
                    "id": str(followed.id),
                    "handle": followed.handle,
                    "avatar_cid": followed.vendor_avatar_cid,
                    "followed_at": f.created_at.isoformat(),
                }
            )

    return {"following": following}


@router.get("/api/users/{user_id}/following/status")
async def check_following_status(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    current_user: "User" = Depends(current_user),
):
    """Check if current user is following a specific user."""

    follow = await session.scalar(
        select(Follow).where(
            Follow.follower_id == current_user.id,
            Follow.following_id == user_id,
        )
    )

    return {"following": follow is not None}
