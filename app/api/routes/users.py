"""Profiles, settings (E2E keys, vendor application), vendor dashboard, public keys."""

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, decode_b64, done, optional_user, page_user, render
from app.api.routes.messages import unread_counts
from app.api.routes.offers import offer_row
from app.api.routes.ratings import rating_row
from app.config import get_settings
from app.core import crypto
from app.core.market import listing_view, now
from app.core.queue import queue
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Listing, ModerationAction, Offer, Rating, User
from app.schemas.user import KeysUpload

router = APIRouter()


@router.get("/u/{handle}")
async def profile_page(
    request: Request,
    handle: str,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    subject = await session.scalar(select(User).where(User.handle == handle.lower()))
    if subject is None or (not subject.is_active and not (user and user.is_superuser)):
        raise HTTPException(404, "No such user")
    listings = (
        await session.scalars(
            select(Listing)
            .where(Listing.seller_id == subject.id, Listing.status == "active")
            .order_by(Listing.created_at.desc())
            .limit(48)
        )
    ).unique()
    ratings = (
        await session.scalars(
            select(Rating)
            .where(Rating.subject_id == subject.id)
            .order_by(Rating.created_at.desc())
            .limit(50)
        )
    ).unique()
    avg, count = (
        await session.execute(
            select(func.avg(Rating.score), func.count()).where(Rating.subject_id == subject.id)
        )
    ).one()
    bio = None
    if subject.vendor_bio_ct:
        try:
            bio = crypto.open_json(subject.vendor_bio_ct).get("bio")
        except crypto.CryptoError:
            pass
    return render(
        request,
        "pages/profile.html",
        {
            "subject": subject,
            "bio": bio,
            "listings": [v for v in map(listing_view, listings) if v.plain],
            "ratings": [rating_row(r) for r in ratings],
            "rating_avg": float(avg) if avg else None,
            "rating_count": count,
        },
        user=user,
    )


@router.get("/settings")
async def settings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    warnings = (
        await session.scalars(
            select(ModerationAction)
            .where(
                ModerationAction.action_type == "warn_user",
                ModerationAction.target_id == str(user.id),
            )
            .order_by(ModerationAction.created_at.desc())
        )
    ).unique()
    s = get_settings()
    return render(
        request,
        "pages/settings.html",
        {
            "warnings": list(warnings),
            "payment": {
                "stripe": s.stripe_enabled,
                "lightning": s.btcpay_enabled,
                "monero": s.monero_enabled,
                "paymongo": s.paymongo_enabled,
            },
        },
        user=user,
    )


@router.put("/api/users/me/keys", dependencies=[Depends(csrf_protect)])
async def upload_keys(
    body: KeysUpload,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Public keys derived in the browser from the passphrase. The passphrase and secret keys
    never reach the server; the proof shows the client holds the new signing key."""
    spk = decode_b64(body.signing_pubkey, "signing_pubkey")
    xpk = decode_b64(body.exchange_pubkey, "exchange_pubkey")
    ppk = decode_b64(body.profile_enc_key, "profile_enc_key")
    if not (len(spk) == len(xpk) == len(ppk) == 32):
        raise HTTPException(422, "Keys must be 32 bytes")
    if xpk != crypto.ed25519_pk_to_x25519(spk):
        raise HTTPException(422, "exchange_pubkey must be derived from signing_pubkey")
    proof = decode_b64(body.proof, "proof")
    if not crypto.verify(spk, "keys", crypto.keys_payload(str(user.id), spk, xpk, ppk), proof):
        raise HTTPException(400, "Invalid key proof")
    user = await session.merge(user)
    user.signing_pubkey, user.exchange_pubkey, user.profile_enc_key = spk, xpk, ppk
    await session.commit()
    return {"ok": True}


@router.get("/api/users/{user_id}/keys")
async def public_keys(user_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(404)
    return {
        "user_id": str(target.id),
        "handle": target.handle,
        "signing_pubkey": crypto.b64e(target.signing_pubkey) if target.signing_pubkey else None,
        "exchange_pubkey": crypto.b64e(target.exchange_pubkey) if target.exchange_pubkey else None,
    }


@router.post("/settings/vendor", dependencies=[Depends(csrf_protect)])
async def become_vendor(
    request: Request,
    bio: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    if not user.is_verified and not get_settings().is_dev:
        return done(request, "/settings", {"error": "verify email"}, "verify_required")
    user = await session.merge(user)
    user.is_vendor = True
    user.vendor_since = user.vendor_since or now()
    user.vendor_bio_ct = crypto.seal_json({"bio": bio.strip()[:1000]})
    await session.commit()
    return done(request, "/listings/new", code="vendor_ok")


@router.get("/vendor")
async def vendor_dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    listings = (
        await session.scalars(
            select(Listing)
            .where(Listing.seller_id == user.id, Listing.status != "removed")
            .order_by(Listing.created_at.desc())
        )
    ).unique()
    sales = [
        offer_row(o)
        for o in (
            await session.scalars(
                select(Offer)
                .join(Listing)
                .where(
                    Listing.seller_id == user.id,
                    Offer.status.in_(["paid", "completed", "disputed"]),
                )
                .order_by(Offer.updated_at.desc())
            )
        ).unique()
    ]
    owed: dict[str, int] = {}
    for row in sales:
        if row["plain"] and row["offer"].status == "completed":
            owed[row["plain"].currency] = (
                owed.get(row["plain"].currency, 0) + row["plain"].amount_cents
            )
    return render(
        request,
        "pages/vendor_dashboard.html",
        {"listings": [listing_view(lst) for lst in listings], "sales": sales, "owed": owed},
        user=user,
    )


@router.get("/purchases")
async def purchases_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(page_user),
):
    """Buyer's purchase history page."""
    offers = (
        await session.scalars(
            select(Offer)
            .where(Offer.buyer_id == user.id, Offer.status.in_(["paid", "completed", "disputed"]))
            .order_by(Offer.updated_at.desc())
            .limit(100)
        )
    ).unique()
    rows = [offer_row(o) for o in offers]
    return render(
        request,
        "pages/purchases.html",
        {"rows": rows},
        user=user,
    )


@router.get("/partials/badges")
async def badges(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(optional_user),
):
    """Navbar counters, polled by HTMX every 30 s (and rendered inline for no-JS)."""
    if user is None:
        return render(request, "partials/badges.html", {"unread": 0, "notes": 0})
    unread = sum((await unread_counts(session, user.id)).values())
    try:
        notes = int(await (await queue.connect()).get(f"notif_unread:{user.id}") or 0)
    except Exception:  # noqa: BLE001
        notes = 0
    return render(request, "partials/badges.html", {"unread": unread, "notes": notes}, user=user)
