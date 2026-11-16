import uuid

from sqlalchemy import select

from app.models import Message, ModerationAction, Offer


async def test_suspend_blocks_access_and_unsuspend_restores(make_user, make_client, helpers):
    mod = await make_user(moderator=True)
    seller = await make_user(vendor=True)
    listing_id = await helpers.create_listing(seller)

    r = await mod.form(f"/moderation/users/{seller.id}/suspend", {"reason": "scam reports"})
    assert r.status_code == 303
    # Existing session stops working, new logins fail, listings disappear from browse.
    assert (await seller.api("GET", "/api/users/me")).status_code == 401
    fresh = await make_client()
    r = await fresh.post(
        "/login",
        data={
            "csrf_token": fresh.cookies["d1zzy_csrf"],
            "email": seller.email,
            "password": seller.password,
        },
    )
    assert r.status_code == 400
    assert listing_id not in {
        x["id"] for x in (await fresh.get("/api/listings")).json()["listings"]
    }

    r = await mod.form(f"/moderation/users/{seller.id}/unsuspend", {"reason": "appeal accepted"})
    assert r.status_code == 303
    r = await fresh.post(
        "/auth/jwt/login", data={"username": seller.email, "password": seller.password}
    )
    assert r.status_code == 204


async def test_delete_message_and_audit_log(make_user, helpers, db):
    mod = await make_user(moderator=True)
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    conv_id = (
        (await buyer.form(f"/listings/{listing_id}/contact")).headers["location"].rsplit("/", 1)[1]
    )
    await buyer.form(f"/messages/{conv_id}/send", {"text": "abusive text"})
    msg_id = (await buyer.api("GET", f"/api/conversations/{conv_id}/messages")).json()["messages"][
        0
    ]["id"]

    r = await mod.form(f"/moderation/messages/{msg_id}/delete", {"reason": "harassment"})
    assert r.status_code == 303
    assert await db.get(Message, msg_id) is None

    audit = (await mod.api("GET", "/api/moderation/audit")).json()["actions"]
    entry = next(a for a in audit if a["target_id"] == str(msg_id))
    assert entry["action_type"] == "delete_message" and entry["reason"] == "harassment"
    assert entry["moderator"] == mod.handle


async def test_every_action_needs_a_reason(make_user, helpers):
    mod = await make_user(moderator=True)
    seller = await make_user(vendor=True)
    listing_id = await helpers.create_listing(seller)
    r = await mod.form(f"/moderation/listings/{listing_id}/hide", {"reason": "   "})
    assert r.status_code == 422


async def test_non_moderators_are_refused(make_user, helpers):
    user = await make_user(vendor=True)
    victim = await make_user()
    listing_id = await helpers.create_listing(user)
    assert (await user.client.get("/moderation")).status_code == 403
    assert (
        await user.form(f"/moderation/users/{victim.id}/suspend", {"reason": "x"})
    ).status_code == 403
    assert (
        await user.form(f"/moderation/listings/{listing_id}/hide", {"reason": "x"})
    ).status_code == 403
    assert (await user.api("GET", "/api/moderation/audit")).status_code == 403


async def test_moderators_cannot_suspend_moderators(make_user):
    mod1, mod2 = await make_user(moderator=True), await make_user(moderator=True)
    r = await mod1.form(f"/moderation/users/{mod2.id}/suspend", {"reason": "power grab"})
    assert r.status_code == 403


async def test_warn_user_shows_in_settings(make_user):
    mod = await make_user(moderator=True)
    user = await make_user()
    await mod.form(f"/moderation/users/{user.id}/warn", {"reason": "Please keep it civil"})
    page = await user.client.get("/settings")
    assert "Please keep it civil" in page.text


async def test_resolve_dispute_records_action(make_user, helpers, db):
    mod = await make_user(moderator=True)
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    offer_id = await helpers.create_offer(buyer, listing_id)
    await helpers.set_offer_status(db, offer_id, "disputed")

    page = await mod.client.get("/moderation")
    assert f"@{buyer.handle} vs @{seller.handle}" in page.text
    r = await mod.form(
        f"/moderation/offers/{offer_id}/resolve",
        {"outcome": "refund", "reason": "item never shipped"},
    )
    assert r.status_code == 303
    status = await db.scalar(select(Offer.status).where(Offer.id == uuid.UUID(offer_id)))
    assert status == "rejected"
    action = await db.scalar(select(ModerationAction).where(ModerationAction.target_id == offer_id))
    assert action.action_type == "resolve_dispute" and "never shipped" in action.reason
