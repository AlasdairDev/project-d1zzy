import uuid

from app.core import crypto


async def _completed_offer(make_user, helpers, db):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    offer_id = await helpers.create_offer(buyer, listing_id)
    await helpers.set_offer_status(db, offer_id, "completed")
    return seller, buyer, listing_id, offer_id


def _signed_rating(user, listing_id, offer_id, score=5, note="smooth trade"):
    plain = {"score": score, "note": note, "listing_id": listing_id, "offer_id": offer_id}
    ct = crypto.seal_json(plain)
    return {
        "offer_id": offer_id,
        "rating_ct": crypto.b64e(ct),
        "sig": crypto.b64e(user.identity.sign("rating", ct)),
    }


async def test_submit_verify_fetch(make_user, helpers, db):
    seller, buyer, listing_id, offer_id = await _completed_offer(make_user, helpers, db)
    r = await buyer.api("POST", "/api/ratings", _signed_rating(buyer, listing_id, offer_id, 4))
    assert r.status_code == 201, r.text

    ratings = (await buyer.client.get(f"/api/users/{seller.id}/ratings")).json()["ratings"]
    assert len(ratings) == 1
    r0 = ratings[0]
    ct, sig, pk = (crypto.b64d(r0[k]) for k in ("rating_ct", "sig", "rater_signing_pubkey"))
    assert crypto.verify(pk, "rating", ct, sig) and r0["signed_by"] == "user"
    assert crypto.open_json(ct)["score"] == 4

    profile = await buyer.client.get(f"/u/{seller.handle}")
    assert "smooth trade" in profile.text and f"Signed by @{buyer.handle}" in profile.text

    # The seller can rate the buyer back, via the no-JS form (server-signed).
    r = await seller.form(f"/offers/{offer_id}/rate", {"score": "5", "note": "paid fast"})
    assert r.status_code == 303
    back = (await seller.client.get(f"/api/users/{buyer.id}/ratings")).json()["ratings"]
    assert back[0]["signed_by"] == "server"


async def test_only_once_and_only_after_completion(make_user, helpers, db):
    seller, buyer, listing_id, offer_id = await _completed_offer(make_user, helpers, db)
    body = _signed_rating(buyer, listing_id, offer_id)
    assert (await buyer.api("POST", "/api/ratings", body)).status_code == 201
    assert (
        await buyer.api("POST", "/api/ratings", _signed_rating(buyer, listing_id, offer_id))
    ).status_code == 409

    stranger = await make_user()
    r = await stranger.api("POST", "/api/ratings", _signed_rating(stranger, listing_id, offer_id))
    assert r.status_code == 403

    other_listing = await helpers.create_listing(seller)
    pending = await helpers.create_offer(buyer, other_listing)
    r = await buyer.api("POST", "/api/ratings", _signed_rating(buyer, other_listing, pending))
    assert r.status_code == 409


async def test_rating_must_match_offer_and_be_signed(make_user, helpers, db):
    seller, buyer, listing_id, offer_id = await _completed_offer(make_user, helpers, db)
    wrong = _signed_rating(buyer, str(uuid.uuid4()), offer_id)
    assert (await buyer.api("POST", "/api/ratings", wrong)).status_code == 422
    forged = _signed_rating(buyer, listing_id, offer_id)
    forged["sig"] = crypto.b64e(seller.identity.sign("rating", crypto.b64d(forged["rating_ct"])))
    assert (await buyer.api("POST", "/api/ratings", forged)).status_code == 400
