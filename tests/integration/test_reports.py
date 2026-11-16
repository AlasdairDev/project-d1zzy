import uuid

from sqlalchemy import select

from app.core import crypto
from app.models import Listing, Report


def _signed_report(user, target_type, target_id, reason="scam", details=None):
    details_ct = crypto.seal_json({"text": details}) if details else b""
    payload = crypto.report_payload(target_type, target_id, reason, details_ct)
    return {
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
        "details_ct": crypto.b64e(details_ct) if details_ct else None,
        "sig": crypto.b64e(user.identity.sign("report", payload)),
    }


async def test_report_then_moderator_hides_listing(make_user, helpers, db):
    seller = await make_user(vendor=True)
    reporter = await make_user()
    mod = await make_user(moderator=True)
    listing_id = await helpers.create_listing(seller, title="Totally real designer bag")

    r = await reporter.api(
        "POST",
        "/api/reports",
        _signed_report(reporter, "listing", listing_id, "counterfeit", "fake logo"),
    )
    assert r.status_code == 201 and r.json()["created"] is True

    queue = await mod.client.get("/moderation")
    assert "Totally real designer bag" in queue.text and "fake logo" in queue.text

    r = await mod.form(f"/moderation/listings/{listing_id}/hide", {"reason": "counterfeit goods"})
    assert r.status_code == 303

    # Hidden from everyone but the seller and moderators.
    assert (await reporter.client.get(f"/listings/{listing_id}")).status_code == 404
    browse = await reporter.client.get("/api/listings")
    assert listing_id not in {x["id"] for x in browse.json()["listings"]}
    assert (await seller.client.get(f"/listings/{listing_id}")).status_code == 200
    report = await db.scalar(select(Report).where(Report.target_id == listing_id))
    assert report.status == "actioned" and report.moderator_id == mod.id


async def test_reports_require_valid_signature(make_user, helpers):
    seller = await make_user(vendor=True)
    reporter = await make_user()
    listing_id = await helpers.create_listing(seller)
    body = _signed_report(reporter, "listing", listing_id)
    body["reason"] = "spam"  # signature no longer covers the payload
    assert (await reporter.api("POST", "/api/reports", body)).status_code == 400


async def test_duplicate_and_self_reports(make_user, helpers):
    seller = await make_user(vendor=True)
    reporter = await make_user()
    listing_id = await helpers.create_listing(seller)
    first = await reporter.form(
        "/reports",
        {"target_type": "listing", "target_id": listing_id, "reason": "spam", "back": "/"},
    )
    assert first.headers["location"].endswith("m=reported")
    again = await reporter.form(
        "/reports",
        {"target_type": "listing", "target_id": listing_id, "reason": "spam", "back": "/"},
    )
    assert again.headers["location"].endswith("m=already_reported")
    own = await seller.form(
        "/reports", {"target_type": "listing", "target_id": listing_id, "reason": "spam"}
    )
    assert own.status_code == 422


async def test_auto_hide_after_threshold(make_user, helpers, db):
    """AUTO_HIDE_REPORT_THRESHOLD=3 in tests: three distinct reporters hide a listing."""
    seller = await make_user(vendor=True)
    listing_id = await helpers.create_listing(seller)
    for _ in range(3):
        reporter = await make_user(keys=False)
        await reporter.form(
            "/reports",
            {"target_type": "listing", "target_id": listing_id, "reason": "prohibited_item"},
        )
    listing = await db.get(Listing, uuid.UUID(listing_id))
    await db.refresh(listing)
    assert listing.status == "hidden" and listing.report_count == 3


async def test_message_report_discloses_plaintext_to_moderators(make_user, helpers, db):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    mod = await make_user(moderator=True)
    listing_id = await helpers.create_listing(seller)
    conv = (await buyer.form(f"/listings/{listing_id}/contact")).headers["location"]
    conv_id = conv.rsplit("/", 1)[1]
    await seller.form(f"/messages/{conv_id}/send", {"text": "send money to my other account"})
    msg_id = (await buyer.api("GET", f"/api/conversations/{conv_id}/messages")).json()["messages"][
        0
    ]["id"]

    r = await buyer.api(
        "POST",
        "/api/reports",
        _signed_report(
            buyer,
            "message",
            str(msg_id),
            "scam",
            "Reported message: send money to my other account",
        ),
    )
    assert r.status_code == 201
    # A participant cannot report their own message; outsiders cannot report at all.
    assert (
        await seller.api("POST", "/api/reports", _signed_report(seller, "message", str(msg_id)))
    ).status_code == 422
    page = await mod.client.get("/moderation")
    assert "send money to my other account" in page.text
