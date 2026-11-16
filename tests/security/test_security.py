"""Security regression tests.

Each test maps to a control in docs/security/CONTROLS-MATRIX.md. They cover the browser
controls (headers, CSRF, RBAC), the crypto primitives (AEAD, Ed25519, base64 parsing) and
the request-size guard. The rest of the suite covers behaviour; this file covers the
properties the security write-up claims are enforced.
"""

import os
import time

import jwt
import pytest

import app.core.security as security
from app.config import Settings, get_settings
from app.core import crypto
from app.core.security import (
    ACCESS_AUDIENCE,
    RequestSizeMiddleware,
    csrf_token_valid,
    new_csrf_token,
)
from app.models import User

# --- Security headers (ASVS 14.4 / NIST PR.PS) -------------------------------------------


async def test_security_headers_are_strict(make_client):
    client = await make_client()
    r = await client.get("/login")
    h = r.headers

    csp = h["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    # No inline script or eval. `wasm-unsafe-eval` is required for libsodium and is allowed.
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp

    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cross-origin-opener-policy"] == "same-origin"
    assert h["cross-origin-resource-policy"] == "same-origin"
    assert "camera=()" in h["permissions-policy"]
    assert h["x-request-id"]


async def test_no_hsts_in_development(make_client):
    client = await make_client()
    r = await client.get("/login")
    assert "strict-transport-security" not in r.headers


async def test_api_responses_also_get_headers(make_client):
    client = await make_client()
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers


# --- CSRF (ASVS 4.2.2) --------------------------------------------------------------------


async def test_post_without_csrf_is_rejected(make_client):
    client = await make_client()
    r = await client.post("/login", data={"email": "a@b.test", "password": "x"})
    assert r.status_code == 403


async def test_post_with_mismatched_csrf_is_rejected(make_client):
    client = await make_client()
    r = await client.post(
        "/login",
        data={"csrf_token": "forged.token.value", "email": "a@b.test", "password": "x"},
    )
    assert r.status_code == 403


def test_csrf_token_roundtrip():
    token = new_csrf_token()
    assert token.count(".") == 2
    assert csrf_token_valid(token)


def test_csrf_token_tamper_is_rejected():
    nonce, ts, mac = new_csrf_token().split(".")
    assert not csrf_token_valid(f"{nonce}x.{ts}.{mac}")
    assert not csrf_token_valid(f"{nonce}.{ts}.{mac[:-1]}0")
    assert not csrf_token_valid("nope")


def test_csrf_token_expires(monkeypatch):
    token = new_csrf_token()
    future = time.time() + get_settings().csrf_max_age_seconds + 60
    monkeypatch.setattr(security.time, "time", lambda: future)
    assert not csrf_token_valid(token)


# --- Signature enforcement on writes (ASVS 6.2 / tamper-evidence) -------------------------


async def test_api_write_rejects_foreign_signature(make_user, helpers):
    user = await make_user(vendor=True)
    ct = crypto.seal_json(helpers.listing_plain())
    attacker = crypto.identity_from_seed(os.urandom(32))
    forged = attacker.sign("listing", ct)

    r = await user.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(forged)},
    )
    assert r.status_code == 400
    assert "signature" in r.text.lower()

    good = user.identity.sign("listing", ct)
    r = await user.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(good)},
    )
    assert r.status_code == 201


async def test_api_write_requires_keys(make_user, helpers):
    user = await make_user(vendor=True, keys=False)
    ct = crypto.seal_json(helpers.listing_plain())
    r = await user.api(
        "POST",
        "/api/listings",
        {"ct": crypto.b64e(ct), "sig": crypto.b64e(b"\x00" * 64)},
    )
    assert r.status_code == 400


# --- Role-based access control (ASVS 4.1 / NIST PR.AA) ------------------------------------


async def test_admin_management_requires_superadmin(make_user):
    regular = await make_user()
    r = await regular.api("GET", "/api/admins")
    assert r.status_code == 403

    vendor = await make_user(vendor=True)
    r = await vendor.api("GET", "/api/admins")
    assert r.status_code == 403

    superadmin = await make_user(moderator=True)
    r = await superadmin.api("GET", "/api/admins")
    assert r.status_code == 200


async def test_cannot_promote_to_superadmin(make_user):
    superadmin = await make_user(moderator=True)
    regular = await make_user()
    r = await superadmin.api(
        "PUT",
        f"/api/admins/{regular.id}",
        {"role": "superadmin"},
    )
    assert r.status_code == 403


# --- Session cookies (ASVS 3.3) -----------------------------------------------------------


async def test_session_cookies_are_httponly_and_samesite(make_user):
    user = await make_user()
    r = await user.client.post(
        "/auth/jwt/login",
        data={"username": user.email, "password": user.password},
    )
    assert r.status_code == 204
    cookies = " ".join(r.headers.get_list("set-cookie")).lower()
    assert "httponly" in cookies
    assert "samesite=lax" in cookies


async def test_password_is_hashed_at_rest(make_user, db):
    from sqlalchemy import select

    user = await make_user()
    hashed = await db.scalar(select(User.hashed_password).where(User.id == user.id))
    assert hashed and hashed != user.password
    assert hashed.startswith("$")  # argon2id or bcrypt, never plaintext


# --- JWT handling (ASVS 3.5 / algorithm confusion) ----------------------------------------


def test_jwt_rejects_wrong_secret():
    bogus = jwt.encode(
        {"sub": "1", "aud": ACCESS_AUDIENCE, "exp": int(time.time()) + 60},
        "attacker-secret",
        algorithm="HS256",
    )
    assert security._jwt_sub(bogus, [ACCESS_AUDIENCE]) is None


def test_jwt_rejects_wrong_audience():
    settings = get_settings()
    token = jwt.encode(
        {"sub": "1", "aud": "someone:else", "exp": int(time.time()) + 60},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    assert security._jwt_sub(token, [ACCESS_AUDIENCE]) is None


# --- Request size limiting (ASVS 5.1 / DoS) -----------------------------------------------


async def test_oversized_request_is_rejected():
    async def ok_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = RequestSizeMiddleware(ok_app, max_size=10)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/listings",
        "headers": [(b"content-length", b"1000")],
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"x" * 1000}

    async def send(message):
        sent.append(message)

    await middleware(scope, receive, send)
    assert sent[0]["status"] == 413


# --- Cryptographic primitives (ASVS 6.2 / 6.3) --------------------------------------------


def test_aead_roundtrip_and_tamper_detection():
    key = os.urandom(32)
    blob = crypto.seal(b"top secret", key)
    assert crypto.open_sealed(blob, key) == b"top secret"

    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(bytes(tampered), key)

    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(blob, os.urandom(32))


def test_ed25519_tamper_detection():
    ident = crypto.identity_from_seed(os.urandom(32))
    data = b"listing payload"
    sig = ident.sign("listing", data)

    assert crypto.verify(ident.signing_pk, "listing", data, sig) is True
    assert crypto.verify(ident.signing_pk, "listing", data + b"!", sig) is False
    # Domain separation: a listing signature must not verify as an offer.
    assert crypto.verify(ident.signing_pk, "offer", data, sig) is False


def test_passphrase_derivation_is_deterministic():
    a = crypto.identity_from_passphrase("user@d1zzy.local", "correct horse battery staple")
    b = crypto.identity_from_passphrase("user@d1zzy.local", "correct horse battery staple")
    assert a.signing_pk == b.signing_pk
    c = crypto.identity_from_passphrase("user@d1zzy.local", "wrong passphrase")
    assert a.signing_pk != c.signing_pk


def test_base64_rejects_garbage():
    with pytest.raises(crypto.CryptoError):
        crypto.b64d("not*base64!!")
    with pytest.raises(crypto.CryptoError):
        crypto.b64d("abc")


def test_safety_number_is_stable_and_key_bound():
    import uuid

    conv = str(uuid.uuid4())
    alice = (str(uuid.uuid4()), b"a" * 32, b"b" * 32)
    bob = (str(uuid.uuid4()), b"c" * 32, b"d" * 32)

    number = crypto.safety_number(conv, [alice, bob])
    assert number == crypto.safety_number(conv, [bob, alice])
    assert len(number.split()) == 12
    assert all(len(group) == 5 for group in number.split())

    changed = (bob[0], b"e" * 32, bob[2])
    assert number != crypto.safety_number(conv, [alice, changed])
    assert number != crypto.safety_number(str(uuid.uuid4()), [alice, bob])


async def test_security_txt_is_served(make_client):
    client = await make_client()
    response = await client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert response.text.startswith("Contact: ")
    assert "Expires:" in response.text


def test_production_config_rejects_defaults():
    settings = Settings(
        mode="production",
        secret_key="change-me",
        market_key="",
        server_signing_seed="",
        database_url="postgresql+asyncpg://d1zzy:d1zzy@db:5432/market",
        seed_demo_data=True,
        cookie_secure=False,
    )
    with pytest.raises(RuntimeError):
        settings.assert_production_safe()
