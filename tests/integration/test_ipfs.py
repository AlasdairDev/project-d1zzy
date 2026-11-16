import os

from app.cli import _png
from app.core import crypto
from app.core.ipfs import IPFSClient


async def test_encrypt_add_pin_cat_decrypt_roundtrip(app):
    image = _png((10, 200, 30))
    key = os.urandom(32)
    blob = crypto.seal(image, key)
    async with IPFSClient() as ipfs:
        cid = await ipfs.add(blob, pin=False)
        assert cid.startswith("b")  # CIDv1
        assert not await ipfs.is_pinned(cid)
        await ipfs.pin(cid)
        assert await ipfs.is_pinned(cid)
        stored = await ipfs.cat(cid)
    assert stored == blob and image not in stored  # IPFS only ever holds ciphertext
    assert crypto.open_sealed(stored, key) == image


async def test_pin_cids_worker_task(app):
    from app.workers.tasks import pin_cids

    async with IPFSClient() as ipfs:
        cids = [
            await ipfs.add(crypto.seal(os.urandom(100), os.urandom(32)), pin=False)
            for _ in range(2)
        ]
        assert await pin_cids({}, cids) == 2
        assert all([await ipfs.is_pinned(c) for c in cids])


async def test_client_upload_then_media_proxy_decrypts(make_user, helpers):
    """JS path: the browser encrypts the image, uploads ciphertext, and puts the key in the
    signed listing. The media endpoint decrypts for display."""
    seller = await make_user(vendor=True)
    image, key = _png((200, 10, 10)), os.urandom(32)
    r = await seller.client.post(
        "/api/ipfs/upload",
        files={"file": ("blob", crypto.seal(image, key), "application/octet-stream")},
        headers={"X-CSRF-Token": seller.csrf},
    )
    assert r.status_code == 200, r.text
    cid = r.json()["cid"]
    listing_id = await helpers.create_listing(
        seller, images=[{"cid": cid, "key": crypto.b64e(key), "mime": "image/png"}]
    )
    media = await seller.client.get(f"/media/{listing_id}/0")
    assert media.status_code == 200 and media.headers["content-type"] == "image/png"
    assert media.content == image
    assert (await seller.client.get(f"/media/{listing_id}/1")).status_code == 404


async def test_upload_size_limit(make_user):
    seller = await make_user(vendor=True)
    too_big = os.urandom(5 * 1024 * 1024 + 1024)
    r = await seller.client.post(
        "/api/ipfs/upload",
        files={"file": ("blob", too_big, "application/octet-stream")},
        headers={"X-CSRF-Token": seller.csrf},
    )
    assert r.status_code == 413
