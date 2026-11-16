import asyncio
import json
import re
import uuid

import httpx
import pytest
from httpx_ws import aconnect_ws
from httpx_ws.transport import ASGIWebSocketTransport
from sqlalchemy import select

from app.core import crypto, ratchet
from app.models import Message


async def _conversation(make_user, helpers):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    r = await buyer.form(f"/listings/{listing_id}/contact")
    assert r.status_code == 303
    conv_id = r.headers["location"].rsplit("/", 1)[1]
    return seller, buyer, conv_id


async def _session(user, conv_id):
    """What the browser does: fetch conversation info and initialise its ratchet."""
    info = (await user.api("GET", f"/api/conversations/{conv_id}")).json()
    return ratchet.init(
        conv_id=conv_id,
        is_alice=info["is_alice"],
        my_exchange_sk=user.identity.exchange_sk,
        my_exchange_pk=user.identity.exchange_pk,
        their_exchange_pk=crypto.b64d(info["other"]["exchange_pubkey"]),
    )


async def test_double_ratchet_handshake_relay_and_history(make_user, helpers, db):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    s_buyer, s_seller = await _session(buyer, conv_id), await _session(seller, conv_id)

    # Both may speak first (no prekey server): exchange a few messages each way.
    script = [
        (buyer, "hi, is it available?"),
        (seller, "yes!"),
        (seller, "still boxed"),
        (buyer, "great, offer coming"),
        (buyer, "🔒 unicode ok"),
    ]
    sent_ids = []
    for sender, text in script:
        if sender is buyer:
            s_buyer, h, ct = ratchet.encrypt(s_buyer, text.encode())
        else:
            s_seller, h, ct = ratchet.encrypt(s_seller, text.encode())
        r = await sender.api(
            "POST",
            f"/api/conversations/{conv_id}/messages",
            {"header": crypto.b64e(h), "ciphertext": crypto.b64e(ct)},
        )
        assert r.status_code == 201, r.text
        assert r.json()["mode"] == "ratchet" and r.json()["plaintext"] is None
        sent_ids.append(r.json()["id"])

    # The server stored opaque bytes only.
    rows = (await db.scalars(select(Message).where(Message.id.in_(sent_ids)))).all()
    assert all(b"available" not in m.ciphertext for m in rows)

    # Each side reads the history and decrypts the other side's messages.
    history = (await seller.api("GET", f"/api/conversations/{conv_id}/messages")).json()["messages"]
    got = []
    for m in history:
        if m["sender_id"] == str(buyer.id):
            s_seller, pt = ratchet.decrypt(
                s_seller, crypto.b64d(m["header"]), crypto.b64d(m["ciphertext"])
            )
            got.append(pt.decode())
    assert got == ["hi, is it available?", "great, offer coming", "🔒 unicode ok"]

    after = (
        await buyer.api("GET", f"/api/conversations/{conv_id}/messages?after_id={sent_ids[2]}")
    ).json()
    assert [m["id"] for m in after["messages"]] == sent_ids[3:]


async def test_tampered_message_fails_to_decrypt(make_user, helpers):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    s_buyer, s_seller = await _session(buyer, conv_id), await _session(seller, conv_id)
    s_buyer, h, ct = ratchet.encrypt(s_buyer, b"pay me")
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    with pytest.raises(crypto.CryptoError):
        ratchet.decrypt(s_seller, h, tampered)
    _, pt = ratchet.decrypt(s_seller, h, ct)  # state was not corrupted by the failure
    assert pt == b"pay me"


async def test_relay_validates_shape_and_membership(make_user, helpers):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    outsider = await make_user()
    good_header = crypto.b64e(json.dumps({"dh": "x", "pn": 0, "n": 0}).encode())
    r = await outsider.api(
        "POST",
        f"/api/conversations/{conv_id}/messages",
        {"header": good_header, "ciphertext": crypto.b64e(b"\0" * 64)},
    )
    assert r.status_code == 404
    r = await buyer.api(
        "POST",
        f"/api/conversations/{conv_id}/messages",
        {"header": crypto.b64e(b"not json"), "ciphertext": crypto.b64e(b"\0" * 64)},
    )
    assert r.status_code == 422
    r = await buyer.api(
        "POST",
        f"/api/conversations/{conv_id}/messages",
        {"header": good_header, "ciphertext": crypto.b64e(b"\0" * 5)},
    )
    assert r.status_code == 422


async def test_websocket_relay_between_participants(app, make_user, helpers):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    s_buyer, s_seller = await _session(buyer, conv_id), await _session(seller, conv_id)

    def ws_client(user):
        return httpx.AsyncClient(
            transport=ASGIWebSocketTransport(app),
            base_url="http://test",
            cookies=user.client.cookies,
        )

    async with ws_client(buyer) as bc, ws_client(seller) as sc:
        async with (
            aconnect_ws(f"/ws/conversations/{conv_id}", bc) as bws,
            aconnect_ws(f"/ws/conversations/{conv_id}", sc) as sws,
        ):
            await asyncio.sleep(0.2)  # let both subscriptions settle
            s_buyer, h, ct = ratchet.encrypt(s_buyer, b"over the socket")
            await bws.send_text(
                json.dumps({"header": crypto.b64e(h), "ciphertext": crypto.b64e(ct)})
            )
            relayed = json.loads(await asyncio.wait_for(sws.receive_text(), 5))
            echo = json.loads(await asyncio.wait_for(bws.receive_text(), 5))
            assert relayed["id"] == echo["id"] and relayed["sender_id"] == str(buyer.id)
            _, pt = ratchet.decrypt(
                s_seller, crypto.b64d(relayed["header"]), crypto.b64d(relayed["ciphertext"])
            )
            assert pt == b"over the socket"


async def test_websocket_rejects_outsiders_and_foreign_origins(app, make_user, helpers):
    from httpx_ws import WebSocketDisconnect, WebSocketUpgradeError

    _, buyer, conv_id = await _conversation(make_user, helpers)
    outsider = await make_user()
    for user, headers in [(outsider, {}), (buyer, {"origin": "http://evil.example"})]:
        async with httpx.AsyncClient(
            transport=ASGIWebSocketTransport(app),
            base_url="http://test",
            cookies=user.client.cookies,
        ) as c:
            with pytest.raises((WebSocketDisconnect, WebSocketUpgradeError)):
                async with aconnect_ws(f"/ws/conversations/{conv_id}", c, headers=headers) as ws:
                    await ws.receive_text()


async def test_noscript_messages_are_server_mode_and_labelled(make_user, helpers):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    r = await buyer.form(f"/messages/{conv_id}/send", {"text": "sent without javascript"})
    assert r.status_code == 303
    page = await seller.client.get(f"/messages/{conv_id}")
    assert "sent without javascript" in page.text
    assert "not end-to-end encrypted" in page.text
    assert '<meta http-equiv="refresh" content="15">' in page.text  # inside <noscript>

    # The seller sees it as unread in the conversation list before opening it.
    other_conv = await buyer.form(f"/messages/{conv_id}/send", {"text": "second"})
    assert other_conv.status_code == 303
    listing = await seller.client.get("/messages")
    assert "1 new" in listing.text


async def test_conversation_ids_are_per_listing_and_pair(make_user, helpers):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    l1, l2 = await helpers.create_listing(seller), await helpers.create_listing(seller)
    c1 = (await buyer.form(f"/listings/{l1}/contact")).headers["location"]
    c1_again = (await buyer.form(f"/listings/{l1}/contact")).headers["location"]
    c2 = (await buyer.form(f"/listings/{l2}/contact")).headers["location"]
    assert c1 == c1_again and c1 != c2
    assert uuid.UUID(c1.rsplit("/", 1)[1])


async def test_conversation_shows_matching_safety_numbers(make_user, helpers):
    seller, buyer, conv_id = await _conversation(make_user, helpers)
    pattern = re.compile(r"data-safety-number>([0-9 ]+)<")
    buyer_page = await buyer.client.get(f"/messages/{conv_id}")
    seller_page = await seller.client.get(f"/messages/{conv_id}")
    buyer_match = pattern.search(buyer_page.text)
    seller_match = pattern.search(seller_page.text)
    assert buyer_match and seller_match
    assert buyer_match.group(1) == seller_match.group(1)
    assert len(buyer_match.group(1).split()) == 12
