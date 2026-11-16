"""The browser code (vendored libsodium + app/static/js/*.js) and the Python server must
agree byte for byte. Runs the real JS under Node via tests/js/harness.js."""

import json
import os
import shutil
import subprocess

import pytest

from app.core import crypto, ratchet

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def js(job: dict) -> dict:
    p = subprocess.run(
        ["node", "tests/js/harness.js"],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_passphrase_derivation_matches():
    out = js({"identity": {"email": " Alice@Example.COM", "passphrase": "correct horse battery"}})
    py = crypto.identity_from_passphrase("alice@example.com", "correct horse battery")
    assert out["identity"]["seed"] == crypto.b64e(py.seed)
    assert out["identity"]["signing_pk"] == crypto.b64e(py.signing_pk)
    assert out["identity"]["exchange_pk"] == crypto.b64e(py.exchange_pk)
    assert out["identity"]["profile_pk"] == crypto.b64e(py.profile_pk)


def test_sealed_signed_blobs_interoperate():
    alice = crypto.identity_from_seed(os.urandom(32))
    key = os.urandom(32)
    obj = {"title": "Ünïcode ✓", "price_cents": 1, "images": [], "expires_at": None}

    blob = crypto.seal_json(obj, key)
    out = js(
        {
            "open": {
                "blob": crypto.b64e(blob),
                "key": crypto.b64e(key),
                "context": "listing",
                "sig": crypto.b64e(alice.sign("listing", blob)),
                "pk": crypto.b64e(alice.signing_pk),
            }
        }
    )
    assert out["opened"] == obj and out["verified"] is True

    out = js(
        {
            "seal": {
                "seed": crypto.b64e(alice.seed),
                "obj": obj,
                "key": crypto.b64e(key),
                "context": "offer",
            }
        }
    )
    jblob, jsig = crypto.b64d(out["sealed"]["blob"]), crypto.b64d(out["sealed"]["sig"])
    assert crypto.open_json(jblob, key) == obj
    assert crypto.verify(alice.signing_pk, "offer", jblob, jsig)
    assert not crypto.verify(alice.signing_pk, "listing", jblob, jsig)  # domain separation


def test_double_ratchet_python_alice_js_bob():
    a_id, b_id = (
        crypto.identity_from_seed(os.urandom(32)),
        crypto.identity_from_seed(os.urandom(32)),
    )
    conv = "0f0e0d0c-0000-4000-8000-000000000042"
    alice = ratchet.init(
        conv_id=conv,
        is_alice=True,
        my_exchange_sk=a_id.exchange_sk,
        my_exchange_pk=a_id.exchange_pk,
        their_exchange_pk=b_id.exchange_pk,
    )
    incoming = []
    for text in ["one", "two", "three"]:
        alice, h, ct = ratchet.encrypt(alice, text.encode())
        incoming.append({"header": crypto.b64e(h), "ct": crypto.b64e(ct)})
    incoming = [incoming[1], incoming[2], incoming[0]]  # out of order

    out = js(
        {
            "ratchet": {
                "seed": crypto.b64e(b_id.seed),
                "conv": conv,
                "is_alice": False,
                "their_pk": crypto.b64e(a_id.exchange_pk),
                "incoming": incoming,
                "send": ["reply A", "reply B"],
            }
        }
    )
    assert out["received"] == ["two", "three", "one"]
    replies = []
    for m in out["replies"]:
        alice, pt = ratchet.decrypt(alice, crypto.b64d(m["header"]), crypto.b64d(m["ct"]))
        replies.append(pt.decode())
    assert replies == ["reply A", "reply B"]
