"""Moderator tools. Every action needs a reason and writes a row to the audit log."""

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    current_admin,
    current_moderator,
    done,
    page_admin,
    page_moderator,
    render,
)
from app.api.routes.messages import message_out
from app.api.routes.offers import offer_row
from app.core import crypto
from app.core.market import InvalidBlob, listing_view, notify, now
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Listing, Message, ModerationAction, Offer, Report, User, UserRole

router = APIRouter()


async def record(
    session: AsyncSession,
    moderator: User,
    action: str,
    target_type: str,
    target_id,
    reason: str,
) -> None:
    reason = reason.strip()
    if not reason:
        raise HTTPException(422, "A reason is required for every moderation action")
    session.add(
        ModerationAction(
            moderator_id=moderator.id,
            action_type=action,
            target_type=target_type,
            target_id=str(target_id),
            reason=reason[:1000],
        )
    )
    # Close every open report on the target: the action answers all of them.
    open_reports = select(Report).where(
        Report.target_type == target_type,
        Report.target_id == str(target_id),
        Report.status == "open",
    )
    for report in (await session.scalars(open_reports)).unique():
        report.status, report.moderator_id, report.resolved_at = "actioned", moderator.id, now()
    await session.commit()


async def _listing(session, listing_id: uuid.UUID) -> Listing:
    listing = await session.get(Listing, listing_id)
    if listing is None:
        raise HTTPException(404)
    return listing


async def _target_user(session, user_id: uuid.UUID, moderator: User) -> User:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(404)
    if target.is_superuser or target.id == moderator.id:
        raise HTTPException(403, "Moderators cannot act on moderator accounts")
    return target


@router.post("/moderation/listings/{listing_id}/hide", dependencies=[Depends(csrf_protect)])
async def hide_listing(
    request: Request,
    listing_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    listing = await _listing(session, listing_id)
    listing.status = "hidden"
    await record(session, moderator, "hide_listing", "listing", listing.id, reason)
    await notify(listing.seller_id, "A moderator hid one of your listings.", "/vendor")
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/listings/{listing_id}/unhide", dependencies=[Depends(csrf_protect)])
async def unhide_listing(
    request: Request,
    listing_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    listing = await _listing(session, listing_id)
    if listing.status != "hidden":
        raise HTTPException(409, "Listing is not hidden")
    listing.status = "active"
    await record(session, moderator, "unhide_listing", "listing", listing.id, reason)
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/users/{user_id}/suspend", dependencies=[Depends(csrf_protect)])
async def suspend_user(
    request: Request,
    user_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    target = await _target_user(session, user_id, moderator)
    target.is_active = False  # fastapi-users rejects inactive users on every request
    await record(session, moderator, "suspend_user", "user", target.id, reason)
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/users/{user_id}/unsuspend", dependencies=[Depends(csrf_protect)])
async def unsuspend_user(
    request: Request,
    user_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    target = await _target_user(session, user_id, moderator)
    target.is_active = True
    await record(session, moderator, "unsuspend_user", "user", target.id, reason)
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/users/{user_id}/warn", dependencies=[Depends(csrf_protect)])
async def warn_user(
    request: Request,
    user_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    target = await _target_user(session, user_id, moderator)
    await record(session, moderator, "warn_user", "user", target.id, reason)
    await notify(target.id, "You received a warning from a moderator.", "/settings")
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/messages/{message_id}/delete", dependencies=[Depends(csrf_protect)])
async def delete_message(
    request: Request,
    message_id: int,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    msg = await session.get(Message, message_id)
    if msg is None:
        raise HTTPException(404)
    await session.delete(msg)
    await record(session, moderator, "delete_message", "message", message_id, reason)
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/offers/{offer_id}/resolve", dependencies=[Depends(csrf_protect)])
async def resolve_dispute(
    request: Request,
    offer_id: uuid.UUID,
    outcome: str = Form(),  # "release" -> completed, "refund" -> rejected
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    offer = await session.get(Offer, offer_id)
    if offer is None or offer.status != "disputed":
        raise HTTPException(409, "Offer is not in dispute")
    if outcome not in ("release", "refund"):
        raise HTTPException(422, "outcome must be release or refund")
    offer.status = "completed" if outcome == "release" else "rejected"
    if outcome == "refund":
        offer.listing.status = "active"
    await record(session, moderator, "resolve_dispute", "offer", offer.id, f"{outcome}: {reason}")
    for uid in (offer.buyer_id, offer.listing.seller_id):
        await notify(uid, f"A moderator resolved your dispute ({outcome}).")
    return done(request, "/moderation", code="mod_done")


@router.post("/moderation/reports/{report_id}/dismiss", dependencies=[Depends(csrf_protect)])
async def dismiss_report(
    request: Request,
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(current_moderator),
):
    report = await session.get(Report, report_id)
    if report is None:
        raise HTTPException(404)
    report.status, report.moderator_id, report.resolved_at = "dismissed", moderator.id, now()
    await session.commit()
    return done(request, "/moderation", code="mod_done")


# --- Views ------------------------------------------------------------------------------


@router.get("/api/moderation/audit")
async def api_audit_log(
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(current_moderator),
):
    rows = (
        await session.scalars(
            select(ModerationAction)
            .order_by(ModerationAction.created_at.desc())
            .limit(min(limit, 500))
        )
    ).unique()
    return {
        "actions": [
            {
                "id": str(a.id),
                "moderator": a.moderator.handle,
                "action_type": a.action_type,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "reason": a.reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
    }


async def _report_target(session: AsyncSession, r: Report) -> dict:
    """Server-side preview of what was reported, for the moderation queue."""
    try:
        if r.target_type == "listing":
            listing = await session.get(Listing, uuid.UUID(r.target_id))
            return {"listing": listing_view(listing) if listing else None}
        if r.target_type == "user":
            return {"target_user": await session.get(User, uuid.UUID(r.target_id))}
        msg = await session.get(Message, int(r.target_id))
        return {"message": message_out(msg) if msg else None}
    except (ValueError, InvalidBlob):
        return {}


@router.get("/moderation")
async def moderation_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(page_moderator),
):
    reports = (
        await session.scalars(
            select(Report).where(Report.status == "open").order_by(Report.created_at).limit(100)
        )
    ).unique()
    queue_rows = []
    for r in reports:
        details = None
        if r.details_ct:
            try:
                details = crypto.open_json(r.details_ct)
            except crypto.CryptoError:
                details = {"text": "(unreadable)"}
        queue_rows.append({"report": r, "details": details, **await _report_target(session, r)})

    hidden = (
        await session.scalars(
            select(Listing).where(Listing.status == "hidden").order_by(Listing.updated_at.desc())
        )
    ).unique()
    disputes = (await session.scalars(select(Offer).where(Offer.status == "disputed"))).unique()
    suspended = (await session.scalars(select(User).where(User.is_active.is_(False)))).all()
    audit = (
        await session.scalars(
            select(ModerationAction).order_by(ModerationAction.created_at.desc()).limit(50)
        )
    ).unique()
    return render(
        request,
        "pages/moderation.html",
        {
            "queue": queue_rows,
            "hidden": [listing_view(h) for h in hidden],
            "disputes": [offer_row(o) for o in disputes],
            "suspended": suspended,
            "audit": list(audit),
        },
        user=moderator,
    )


# --- Vendor Application Review (Admin/Superadmin only) -------------------------------------


@router.get("/moderation/vendors/pending")
async def pending_vendors_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(page_admin),
):
    pending = (
        await session.scalars(
            select(User)
            .where(User.vendor_application_submitted.is_(True))
            .where(User.vendor_application_reviewed.is_(False))
            .order_by(User.created_at.desc())
        )
    ).all()
    return render(
        request,
        "pages/moderation_vendors.html",
        {"pending": pending},
        user=admin,
    )


@router.post("/moderation/vendors/{user_id}/approve", dependencies=[Depends(csrf_protect)])
async def approve_vendor(
    request: Request,
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(current_admin),
):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if not target.vendor_application_submitted or target.vendor_application_reviewed:
        raise HTTPException(409, "No pending vendor application")

    target.role = UserRole.VENDOR
    target.is_vendor = True
    target.vendor_since = now()
    target.vendor_application_reviewed = True
    # Move bio from application notes to vendor_bio_ct
    if target.vendor_application_notes:
        target.vendor_bio_ct = crypto.seal_json({"bio": target.vendor_application_notes})
    await session.commit()
    await record(session, admin, "approve_vendor", "user", target.id, "Vendor application approved")
    await notify(
        target.id, "Your vendor application was approved! You can now create listings.", "/vendor"
    )
    return done(request, "/moderation/vendors/pending", code="mod_done")


@router.post("/moderation/vendors/{user_id}/reject", dependencies=[Depends(csrf_protect)])
async def reject_vendor(
    request: Request,
    user_id: uuid.UUID,
    reason: str = Form(),
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(current_admin),
):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if not target.vendor_application_submitted or target.vendor_application_reviewed:
        raise HTTPException(409, "No pending vendor application")

    target.vendor_application_reviewed = True
    target.vendor_application_notes = f"Rejected: {reason.strip()}"
    await session.commit()
    await record(session, admin, "reject_vendor", "user", target.id, f"Rejected: {reason.strip()}")
    await notify(target.id, f"Your vendor application was rejected: {reason.strip()}", "/settings")
    return done(request, "/moderation/vendors/pending", code="mod_done")
