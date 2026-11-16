"""Listing pages, the signed JSON API, no-JS form writes, encrypted image uploads, and the
media proxy that decrypts images for display."""

import os
import uuid
from datetime import date

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    current_user,
    decode_b64,
    done,
    optional_user,
    page_user,
    page_vendor,
    render,
    require_user_sig,
)
from app.config import get_settings
from app.core import crypto
from app.core.images import sniff_image_mime
from app.core.ipfs import IPFSClient, IPFSError
from app.core.market import (
    InvalidBlob,
    can_view_listing,
    listing_view,
    open_listing_ct,
    seal_model,
    visible_listings_query,
)
from app.core.queue import queue
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Discussion, Listing, Offer, Rating, User
from app.models.listing import CATEGORIES, CATEGORY_ICONS
from app.schemas.listing import (
    CONDITIONS,
    IMAGE_MIMES,
    MARKET_CURRENCIES,
    ListingPlain,
    SignedBlob,
)

router = APIRouter()
PAGE_SIZE = 24
INDEX_LIMIT = 500


def _listing_json(lst: Listing) -> dict:
    return {
        "id": str(lst.id),
        "seller_id": str(lst.seller_id),
        "seller_handle": lst.seller.handle,
        "seller_signing_pubkey": crypto.b64e(lst.seller.signing_pubkey or b""),
        "listing_ct": crypto.b64e(lst.listing_ct),
        "sig": crypto.b64e(lst.sig),
        "status": lst.status,
        "created_at": lst.created_at.isoformat() if lst.created_at else None,
    }


async def _get_listing(session: AsyncSession, listing_id: uuid.UUID) -> Listing:
    lst = await session.get(Listing, listing_id)
    if lst is None:
        raise HTTPException(404, "Listing not found")
    return lst


# --- Pages ------------------------------------------------------------------------------


@router.get("/")
async def home(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    recent = (
        await session.scalars(visible_listings_query().order_by(Listing.created_at.desc()).limit(8))
    ).unique()
    counts = dict(
        (
            await session.execute(
                visible_listings_query()
                .with_only_columns(Listing.category, func.count())
                .group_by(Listing.category)
            )
        ).all()
    )
    views = [v for v in map(listing_view, recent) if v.plain]

    # Fetch recent discussions for homepage
    discussions = (
        await session.scalars(
            select(Discussion)
            .where(Discussion.parent_id.is_(None))
            .order_by(Discussion.created_at.desc())
            .limit(5)
        )
    ).all()

    return render(
        request,
        "pages/home.html",
        {
            "listings": views,
            "categories": CATEGORIES,
            "counts": counts,
            "category_icons": CATEGORY_ICONS,
            "discussions": discussions,
        },
        user=user,
    )


async def _browse(
    session: AsyncSession,
    category: str | None,
    q: str | None,
    page: int,
    price_min: int | None = None,
    price_max: int | None = None,
    condition: str | None = None,
    location: str | None = None,
):
    query = visible_listings_query().order_by(Listing.created_at.desc())
    if category in CATEGORIES:
        query = query.where(Listing.category == category)
    if q:
        needle = q.lower()
        rows = (await session.scalars(query.limit(INDEX_LIMIT))).unique()
        views = [
            v
            for v in map(listing_view, rows)
            if v.plain and (needle in v.plain.title.lower() or needle in v.plain.desc.lower())
        ]
        start = (page - 1) * PAGE_SIZE
        return views[start : start + PAGE_SIZE], len(views) > start + PAGE_SIZE

    # Apply filters to the query before pagination
    if price_min is not None:
        query = query.where(Listing.listing_ct.op("->>")("price_cents") >= str(price_min))
    if price_max is not None:
        query = query.where(Listing.listing_ct.op("->>")("price_cents") <= str(price_max))
    if condition:
        query = query.where(Listing.listing_ct.op("->>")("condition") == condition)
    if location:
        query = query.where(Listing.listing_ct.op("->>")("location_approx").ilike(f"%{location}%"))

    rows = list(
        (await session.scalars(query.offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE + 1))).unique()
    )
    views = [v for v in map(listing_view, rows[:PAGE_SIZE]) if v.plain and not v.is_expired]
    return views, len(rows) > PAGE_SIZE


@router.get("/listings")
async def listings_page(
    request: Request,
    category: str | None = None,
    q: str | None = None,
    page: int = 1,
    price_min: int | None = None,
    price_max: int | None = None,
    condition: str | None = None,
    location: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    page = max(page, 1)
    views, has_more = await _browse(
        session,
        category,
        (q or "").strip()[:100] or None,
        page,
        price_min=price_min,
        price_max=price_max,
        condition=condition,
        location=location,
    )
    ctx = {
        "listings": views,
        "has_more": has_more,
        "page": page,
        "category": category if category in CATEGORIES else None,
        "q": q or "",
        "categories": CATEGORIES,
        "conditions": CONDITIONS,
        "filters": {
            "price_min": price_min,
            "price_max": price_max,
            "condition": condition,
            "location": location,
        },
    }
    if request.headers.get("hx-request") and page > 1:
        return render(request, "partials/listing-page.html", ctx, user=user)
    return render(request, "pages/listings.html", ctx, user=user)


def _form_options() -> dict:
    return {"categories": CATEGORIES, "conditions": CONDITIONS, "currencies": MARKET_CURRENCIES}


@router.get("/listings/new")
async def new_listing_page(request: Request, user: User = Depends(page_vendor)):
    return render(request, "pages/listing_new.html", _form_options(), user=user)


@router.get("/listings/{listing_id}")
async def listing_detail(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    lst = await _get_listing(session, listing_id)
    if not can_view_listing(lst, user):
        raise HTTPException(404, "Listing not found")
    view = listing_view(lst)
    my_offer = None
    if user:
        my_offer = await session.scalar(
            select(Offer)
            .where(Offer.listing_id == lst.id, Offer.buyer_id == user.id)
            .order_by(Offer.created_at.desc())
        )
    avg, n = (
        await session.execute(
            select(func.avg(Rating.score), func.count()).where(Rating.subject_id == lst.seller_id)
        )
    ).one()
    return render(
        request,
        "pages/listing_detail.html",
        {
            "view": view,
            "my_offer": my_offer,
            "rating_avg": float(avg) if avg else None,
            "rating_count": n,
            "currencies": MARKET_CURRENCIES,
            "payment": {
                "stripe": get_settings().stripe_enabled,
                "lightning": get_settings().btcpay_enabled,
                "monero": get_settings().monero_enabled,
                "paymongo": get_settings().paymongo_enabled,
            },
        },
        user=user,
    )


# --- Discussions on Listings ---------------------------------------------------------


@router.get("/listings/{listing_id}/discussions")
async def listing_discussions_page(
    request: Request,
    listing_id: uuid.UUID,
    type: str | None = None,
    page: int = 1,
    sort: str = "newest",
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    from app.models import Discussion, DiscussionVote, Listing

    listing = await session.get(Listing, listing_id)
    if not listing or listing.status != "active":
        raise HTTPException(404, "Listing not found")

    q = select(Discussion).where(
        Discussion.listing_id == listing_id,
        Discussion.parent_id.is_(None),
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


@router.get("/listings/{listing_id}/discussions/new")
async def new_discussion_page(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    listing = await session.get(Listing, listing_id)
    if not listing or listing.status != "active":
        raise HTTPException(404, "Listing not found")
    return render(
        request,
        "pages/listing_discussions_new.html",
        {"listing": listing},
        user=user,
    )


@router.post("/listings/{listing_id}/discussions", dependencies=[Depends(csrf_protect)])
async def create_discussion(
    request: Request,
    listing_id: uuid.UUID,
    type: str = Form(...),
    title: str = Form(""),
    content: str = Form(...),
    rating: int | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    from app.core.market import seal_model
    from app.models import Discussion

    listing = await session.get(Listing, listing_id)
    if not listing or listing.status != "active":
        raise HTTPException(404, "Listing not found")

    plain = {
        "title": title,
        "content": content,
        "type": type,
        "rating": rating,
    }
    ct = seal_model(plain)
    sig = crypto.server_sign(
        "discussion", crypto.seal_json({"title": title, "content": content, "type": type})
    )

    d = Discussion(
        listing_id=listing_id,
        author_id=user.id,
        type=type,
        title=title,
        content_ct=ct,
        sig=sig,
        rating=rating,
    )
    session.add(d)
    await session.commit()
    await session.refresh(d)

    # Notify listing seller
    if listing.seller_id != user.id:
        await queue.enqueue(
            "relay_notifications",
            str(listing.seller_id),
            f"New {d.type} on your listing: {d.title or 'Discussion'}",
            f"/listings/{listing_id}/discussions",
        )

    return done(request, f"/listings/{listing_id}/discussions", code="discussion_created")


@router.get("/listings/{listing_id}/edit")
async def edit_listing_page(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    lst = await _get_listing(session, listing_id)
    if lst.seller_id != user.id:
        raise HTTPException(403, "Not your listing")
    return render(
        request,
        "pages/listing_edit.html",
        {"view": listing_view(lst), **_form_options()},
        user=user,
    )


# --- No-JS form writes (server encrypts with the market key and signs on the user's behalf)


async def _encrypt_and_add_images(files: list[UploadFile]) -> list[dict]:
    images = []
    files = [f for f in files if f and f.filename]
    if not files:
        return images
    max_bytes = get_settings().max_upload_bytes
    async with IPFSClient() as ipfs:
        for f in files[:8]:
            data = await f.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise HTTPException(413, f"{f.filename}: image too large")
            if f.content_type not in IMAGE_MIMES or sniff_image_mime(data) != f.content_type:
                raise HTTPException(422, f"{f.filename}: only JPEG, PNG, WebP or GIF images")
            key = os.urandom(32)
            try:
                cid = await ipfs.add(crypto.seal(data, key), pin=False)
            except IPFSError as e:
                raise HTTPException(503, "Image storage is unavailable") from e
            images.append({"cid": cid, "key": crypto.b64e(key), "mime": f.content_type})
    return images


async def listing_form_fields(
    title: str = Form(),
    desc: str = Form(""),
    price: str = Form(),
    currency: str = Form("usd"),
    category: str = Form("other"),
    condition: str = Form("good"),
    location_approx: str = Form(""),
    expires_at: str = Form(""),
) -> dict:
    return {
        "title": title,
        "desc": desc,
        "price": price,
        "currency": currency,
        "category": category,
        "condition": condition,
        "location_approx": location_approx,
        "expires_at": expires_at,
    }


def _plain_from_form(form: dict, images: list[dict]) -> ListingPlain:
    try:
        price = round(float(form["price"]) * 100)
        return ListingPlain(
            title=form["title"].strip(),
            desc=form["desc"].strip(),
            price_cents=price,
            currency=form["currency"],
            category=form["category"],
            condition=form["condition"],
            images=images,
            location_approx=form["location_approx"].strip(),
            expires_at=date.fromisoformat(form["expires_at"]) if form["expires_at"] else None,
        )
    except (ValidationError, ValueError) as e:
        raise HTTPException(422, f"Invalid listing: {e}") from e


@router.post("/listings/new", dependencies=[Depends(csrf_protect)])
async def create_listing_form(
    request: Request,
    form: dict = Depends(listing_form_fields),
    images: list[UploadFile] = File(default=[]),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_vendor),
):
    imgs = await _encrypt_and_add_images(images)
    plain = _plain_from_form(form, imgs)
    ct = seal_model(plain)
    lst = Listing(
        seller_id=user.id,
        listing_ct=ct,
        sig=crypto.server_sign("listing", ct),
        category=plain.category,
    )
    session.add(lst)
    await session.commit()
    if imgs:
        await queue.enqueue("pin_cids", [i["cid"] for i in imgs])
    return done(request, f"/listings/{lst.id}", {"id": str(lst.id)}, "listing_created")


@router.post("/listings/{listing_id}/edit", dependencies=[Depends(csrf_protect)])
async def edit_listing_form(
    request: Request,
    listing_id: uuid.UUID,
    form: dict = Depends(listing_form_fields),
    remove_images: list[int] = Form(default=[]),
    images: list[UploadFile] = File(default=[]),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    lst = await _get_listing(session, listing_id)
    if lst.seller_id != user.id or lst.status not in ("active", "expired"):
        raise HTTPException(403, "You cannot edit this listing")
    try:
        old = open_listing_ct(lst.listing_ct)
        kept = [i.model_dump() for n, i in enumerate(old.images) if n not in remove_images]
    except InvalidBlob:
        kept = []
    new_imgs = await _encrypt_and_add_images(images)
    plain = _plain_from_form(form, (kept + new_imgs)[:8])
    lst.listing_ct = seal_model(plain)
    lst.sig = crypto.server_sign("listing", lst.listing_ct)
    lst.category = plain.category
    lst.status = "active"
    await session.commit()
    if new_imgs:
        await queue.enqueue("pin_cids", [i["cid"] for i in new_imgs])
    return done(request, f"/listings/{lst.id}", code="listing_updated")


@router.post("/listings/{listing_id}/delete", dependencies=[Depends(csrf_protect)])
async def delete_listing(
    request: Request,
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    lst = await _get_listing(session, listing_id)
    if lst.seller_id != user.id:
        raise HTTPException(403, "Not your listing")
    if lst.status != "hidden":  # a seller cannot "un-hide" by deleting and editing
        lst.status = "removed"
    await session.commit()
    return done(request, "/vendor", code="listing_removed")


# --- JSON API (client-side encrypted + signed) ------------------------------------------


@router.get("/api/market-key")
async def market_key():
    """The listing key is public by design: listings are meant to be read by anyone who can
    reach the site. It keeps database dumps, backups and IPFS-stored content opaque."""
    return {
        "key": crypto.b64e(crypto.market_key()),
        "server_signing_pubkey": crypto.b64e(crypto.server_verify_key()),
    }


@router.get("/api/listings")
async def api_list_listings(
    category: str | None = None, session: AsyncSession = Depends(get_session)
):
    """Encrypted index for client-side (Fuse.js) search; the query never reaches the server."""
    query = visible_listings_query().order_by(Listing.created_at.desc()).limit(INDEX_LIMIT)
    if category in CATEGORIES:
        query = query.where(Listing.category == category)
    return {"listings": [_listing_json(lst) for lst in (await session.scalars(query)).unique()]}


@router.get("/api/listings/{listing_id}")
async def api_get_listing(
    listing_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    lst = await _get_listing(session, listing_id)
    if not can_view_listing(lst, user):
        raise HTTPException(404, "Listing not found")
    return _listing_json(lst)


def _validated_blob(user: User, body: SignedBlob) -> tuple[bytes, bytes, ListingPlain]:
    ct = decode_b64(body.ct, "ct")
    sig = require_user_sig(user, "listing", ct, body.sig)
    try:
        plain = open_listing_ct(ct)
    except InvalidBlob as e:
        raise HTTPException(422, f"listing_ct invalid: {e}") from e
    return ct, sig, plain


@router.post("/api/listings", status_code=201, dependencies=[Depends(csrf_protect)])
async def api_create_listing(
    body: SignedBlob,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    if not user.is_vendor:
        raise HTTPException(403, "Become a vendor first")
    ct, sig, plain = _validated_blob(user, body)
    lst = Listing(seller_id=user.id, listing_ct=ct, sig=sig, category=plain.category)
    session.add(lst)
    await session.commit()
    if plain.images:
        await queue.enqueue("pin_cids", [i.cid for i in plain.images])
    return {"id": str(lst.id)}


@router.put("/api/listings/{listing_id}", dependencies=[Depends(csrf_protect)])
async def api_update_listing(
    listing_id: uuid.UUID,
    body: SignedBlob,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    lst = await _get_listing(session, listing_id)
    if lst.seller_id != user.id or lst.status not in ("active", "expired"):
        raise HTTPException(403, "You cannot edit this listing")
    ct, sig, plain = _validated_blob(user, body)
    lst.listing_ct, lst.sig, lst.category, lst.status = ct, sig, plain.category, "active"
    await session.commit()
    if plain.images:
        await queue.enqueue("pin_cids", [i.cid for i in plain.images])
    return {"id": str(lst.id)}


@router.post("/api/ipfs/upload", dependencies=[Depends(csrf_protect)])
async def api_upload(file: UploadFile = File(), user: User = Depends(current_user)):
    """Accepts ciphertext only (encrypted in the browser with a fresh per-image key)."""
    max_bytes = get_settings().max_upload_bytes + 64
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(413, "File too large")
    try:
        async with IPFSClient() as ipfs:
            return {"cid": await ipfs.add(data, pin=False)}
    except IPFSError as e:
        raise HTTPException(503, "Image storage is unavailable") from e


@router.get("/media/{listing_id}/{index}")
async def media(
    listing_id: uuid.UUID,
    index: int,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    lst = await _get_listing(session, listing_id)
    if not can_view_listing(lst, user):
        raise HTTPException(404)
    try:
        img = open_listing_ct(lst.listing_ct).images[index]
    except (InvalidBlob, IndexError) as e:
        raise HTTPException(404) from e
    try:
        async with IPFSClient() as ipfs:
            blob = await ipfs.cat(img.cid, get_settings().max_upload_bytes + 64)
        data = crypto.open_sealed(blob, crypto.b64d(img.key))
    except (IPFSError, crypto.CryptoError) as e:
        raise HTTPException(502, "Image unavailable") from e
    return Response(
        data,
        media_type=img.mime,
        headers={"cache-control": "private, max-age=3600", "x-content-type-options": "nosniff"},
    )
