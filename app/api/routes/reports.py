"""User reports -> moderation queue.

Listings that collect AUTO_HIDE_REPORT_THRESHOLD open reports are hidden automatically
until a moderator reviews them. Message reports carry the plaintext the reporter chooses to
disclose: the server cannot read E2E messages, so this is the only way moderators see them.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, decode_b64, done, moderator_user, require_user_sig
from app.config import get_settings
from app.core import crypto
from app.core.market import now
from app.core.security import csrf_protect
from app.db.session import get_session
from app.models import Conversation, Listing, Message, Report, User
from app.schemas.report import ReportCreate, ReportResolve

router = APIRouter()
log = structlog.get_logger()


async def _validate_target(session: AsyncSession, body: ReportCreate, reporter: User) -> None:
    try:
        if body.target_type == "listing":
            target = await session.get(Listing, uuid.UUID(body.target_id))
            ok = target is not None and target.seller_id != reporter.id
        elif body.target_type == "user":
            target = await session.get(User, uuid.UUID(body.target_id))
            ok = target is not None and target.id != reporter.id
        else:
            msg = await session.get(Message, int(body.target_id))
            conv = msg and await session.get(Conversation, msg.conversation_id)
            # Only a participant can report a message, and not their own.
            ok = bool(conv and conv.has(reporter.id) and msg.sender_id != reporter.id)
    except ValueError:
        ok = False
    if not ok:
        raise HTTPException(422, "Invalid report target")


async def create_report(
    session: AsyncSession, body: ReportCreate, reporter: User, details_ct: bytes | None
) -> tuple[Report | None, bool]:
    """Returns (report, created). Duplicate open reports from one user are ignored."""
    await _validate_target(session, body, reporter)
    dup = await session.scalar(
        select(Report).where(
            Report.reporter_id == reporter.id,
            Report.target_type == body.target_type,
            Report.target_id == body.target_id,
            Report.status == "open",
        )
    )
    if dup:
        return dup, False
    report = Report(
        reporter_id=reporter.id,
        target_type=body.target_type,
        target_id=body.target_id,
        reason=body.reason,
        details_ct=details_ct,
    )
    session.add(report)
    if body.target_type == "listing":
        listing = await session.get(Listing, uuid.UUID(body.target_id))
        listing.report_count += 1
        await session.flush()
        open_reports = await session.scalar(
            select(func.count(func.distinct(Report.reporter_id))).where(
                Report.target_type == "listing",
                Report.target_id == body.target_id,
                Report.status == "open",
            )
        )
        if open_reports >= get_settings().auto_hide_report_threshold and listing.status == "active":
            listing.status = "hidden"
            log.warning("listing_auto_hidden", listing_id=body.target_id, reports=open_reports)
    await session.commit()
    return report, True


@router.post("/reports", dependencies=[Depends(csrf_protect)])
async def report_form(
    request: Request,
    target_type: str = Form(),
    target_id: str = Form(),
    reason: str = Form(),
    details: str = Form(""),
    back: str = Form("/"),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    try:
        body = ReportCreate(target_type=target_type, target_id=target_id, reason=reason)
    except ValidationError as e:
        raise HTTPException(422, "Invalid report") from e
    details_ct = crypto.seal_json({"text": details.strip()[:4000]}) if details.strip() else None
    _, created = await create_report(session, body, user, details_ct)
    back = back if back.startswith("/") and not back.startswith("//") else "/"
    return done(request, back, code="reported" if created else "already_reported")


@router.post("/api/reports", status_code=201, dependencies=[Depends(csrf_protect)])
async def api_report(
    body: ReportCreate,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    details_ct = decode_b64(body.details_ct, "details_ct") if body.details_ct else b""
    if details_ct:
        try:
            crypto.open_json(details_ct)
        except crypto.CryptoError as e:
            raise HTTPException(422, "details_ct must be sealed with the market key") from e
    require_user_sig(
        user,
        "report",
        crypto.report_payload(body.target_type, body.target_id, body.reason, details_ct),
        body.sig or "",
    )
    report, created = await create_report(session, body, user, details_ct or None)
    return {"id": str(report.id), "created": created}


@router.get("/api/reports")
async def api_list_reports(
    status: str = "open",
    session: AsyncSession = Depends(get_session),
    _: User = Depends(moderator_user),
):
    reports = (
        await session.scalars(
            select(Report).where(Report.status == status).order_by(Report.created_at).limit(200)
        )
    ).unique()
    return {
        "reports": [
            {
                "id": str(r.id),
                "target_type": r.target_type,
                "target_id": r.target_id,
                "reason": r.reason,
                "details": crypto.open_json(r.details_ct) if r.details_ct else None,
                "reporter": r.reporter.handle,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ]
    }


def resolve_report(report: Report, status: str, moderator: User) -> None:
    report.status = status
    report.moderator_id = moderator.id
    report.resolved_at = now()


@router.post("/api/reports/{report_id}/resolve", dependencies=[Depends(csrf_protect)])
async def api_resolve_report(
    report_id: uuid.UUID,
    body: ReportResolve,
    session: AsyncSession = Depends(get_session),
    moderator: User = Depends(moderator_user),
):
    report = await session.get(Report, report_id)
    if report is None:
        raise HTTPException(404)
    resolve_report(report, body.status, moderator)
    await session.commit()
    return {"ok": True}
