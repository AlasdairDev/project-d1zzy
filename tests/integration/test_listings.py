import uuid

from app.core import crypto


async def test_create_verify_decrypt_roundtrip(make_user, helpers):
    """create -> server verifies sig -> client fetches blob -> verifies sig -> decrypts."""
    seller = await make_user(vendor=True)
    title = "Signed walkman " + uuid.uuid4().hex[:6]
    listing_id = await helpers.create_listing(seller, title=title, price_cents=4500)

    r = await seller.client.get(f"/api/listings/{listing_id}")
    assert r.status_code == 200
    blob = r.json()
    ct, sig = crypto.b64d(blob["listing_ct"]), crypto.b64d(blob["sig"])
    pk = crypto.b64d(blob["seller_signing_pubkey"])
    assert pk == seller.identity.signing_pk
    assert crypto.verify(pk, "listing", ct, sig)
    plain = crypto.open_json(ct)
    assert plain["title"] == title and plain["price_cents"] == 4500

    page = await seller.client.get(f"/listings/{listing_id}")
    assert title in page.text and f"Signed by @{seller.handle}" in page.text


async def test_rejects_signature_from_wrong_key(make_user):
    seller = await make_user(vendor=True)
    import os

    attacker = crypto.identity_from_seed(os.urandom(32))
    from tests.conftest import listing_plain

    ct = crypto.seal_json(listing_plain())
    r = await seller.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(attacker.sign("listing", ct))},
    )
    assert r.status_code == 400 and "signature" in r.json()["detail"].lower()


async def test_signature_is_domain_separated(make_user):
    """A signature made for an offer cannot be replayed as a listing signature."""
    seller = await make_user(vendor=True)
    from tests.conftest import listing_plain

    ct = crypto.seal_json(listing_plain())
    r = await seller.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(seller.identity.sign("offer", ct))},
    )
    assert r.status_code == 400


async def test_rejects_invalid_plaintext(make_user):
    seller = await make_user(vendor=True)
    for bad in [
        crypto.seal_json({"title": "x"}),  # schema violation
        crypto.seal(b"not json", crypto.market_key()),
        b"\x00" * 64,  # not decryptable
    ]:
        sig = seller.identity.sign("listing", bad)
        r = await seller.api(
            "POST", "/api/listings", {"ct": crypto.b64e(bad), "sig": crypto.b64e(sig)}
        )
        assert r.status_code == 422, r.text


async def test_only_vendors_can_list(make_user, helpers):
    buyer = await make_user()
    from tests.conftest import listing_plain

    ct = crypto.seal_json(listing_plain())
    r = await buyer.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(buyer.identity.sign("listing", ct))},
    )
    assert r.status_code == 403
    assert (await buyer.client.get("/listings/new")).status_code == 403


async def test_encrypted_index_and_server_search(make_user, helpers):
    seller = await make_user(vendor=True)
    marker = uuid.uuid4().hex[:8]
    await helpers.create_listing(seller, title=f"Zebra lamp {marker}", category="home")
    await helpers.create_listing(seller, title=f"Other thing {marker}", category="books")

    # Encrypted index for client-side Fuse.js search: decryptable with the market key.
    r = await seller.client.get("/api/listings?category=home")
    titles = [crypto.open_json(crypto.b64d(x["listing_ct"]))["title"] for x in r.json()["listings"]]
    assert f"Zebra lamp {marker}" in titles and f"Other thing {marker}" not in titles

    # No-JS fallback: server-side search.
    r = await seller.client.get(f"/listings?q=zebra+lamp+{marker}")
    assert f"Zebra lamp {marker}" in r.text and f"Other thing {marker}" not in r.text


async def test_pagination_and_htmx_partial(make_user, helpers, db):
    from sqlalchemy import update

    from app.models import Listing

    # Isolate from other tests' listings with a category nobody else uses.
    seller = await make_user(vendor=True)
    for i in range(26):
        await helpers.create_listing(seller, title=f"Bulk {i:02d}", category="collectibles")
    first = await seller.client.get("/listings?category=collectibles")
    assert 'hx-trigger="revealed"' in first.text and "page=2" in first.text

    second = await seller.client.get(
        "/listings?category=collectibles&page=2", headers={"HX-Request": "true"}
    )
    assert second.status_code == 200
    assert "<html" not in second.text  # fragment, not a full page
    assert "Bulk" in second.text
    await db.execute(update(Listing).where(Listing.seller_id == seller.id).values(status="removed"))
    await db.commit()


async def test_update_and_remove(make_user, helpers):
    seller = await make_user(vendor=True)
    other = await make_user(vendor=True)
    listing_id = await helpers.create_listing(seller)
    from tests.conftest import listing_plain

    ct = crypto.seal_json(listing_plain(title="Renamed item"))
    r = await seller.api(
        "PUT",
        f"/api/listings/{listing_id}",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(seller.identity.sign("listing", ct))},
    )
    assert r.status_code == 200
    assert "Renamed item" in (await seller.client.get(f"/listings/{listing_id}")).text

    ct2 = crypto.seal_json(listing_plain(title="Hijacked"))
    r = await other.api(
        "PUT",
        f"/api/listings/{listing_id}",
        {"ct": crypto.b64e(ct2), "sig": crypto.b64e(other.identity.sign("listing", ct2))},
    )
    assert r.status_code == 403

    r = await seller.form(f"/listings/{listing_id}/delete")
    assert r.status_code == 303
    anon = await other.client.get(f"/listings/{listing_id}")
    assert anon.status_code == 404
