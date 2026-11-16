import re

from sqlalchemy import select

from app.core.security import ACCESS_COOKIE, REFRESH_COOKIE
from app.models import User


async def test_register_and_login_with_plain_forms(make_client):
    """The no-JS path: HTML forms with a CSRF hidden field."""
    client = await make_client()
    csrf = client.cookies.get("d1zzy_csrf")
    r = await client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "email": "formuser@d1zzy-test.net",
            "handle": "formuser",
            "password": "a-long-password-123",
            "password2": "a-long-password-123",
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/login?m=registered"

    r = await client.post(
        "/login",
        data={
            "csrf_token": csrf,
            "email": "formuser@d1zzy-test.net",
            "password": "a-long-password-123",
            "next": "/settings",
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/settings"
    assert client.cookies.get(ACCESS_COOKIE) and client.cookies.get(REFRESH_COOKIE)
    r = await client.get("/settings")
    assert r.status_code == 200 and "@formuser" in r.text


async def test_login_rejects_bad_password(make_user, make_client):
    user = await make_user()
    client = await make_client()
    r = await client.post(
        "/login",
        data={"csrf_token": client.cookies["d1zzy_csrf"], "email": user.email, "password": "nope"},
    )
    assert r.status_code == 400 and "Wrong email or password" in r.text


async def test_form_post_without_csrf_is_rejected(make_client):
    client = await make_client()
    r = await client.post("/login", data={"email": "x@d1zzy-test.net", "password": "y"})
    assert r.status_code == 403


async def test_register_validation(make_client):
    client = await make_client()
    csrf = client.cookies["d1zzy_csrf"]
    base = {"csrf_token": csrf, "email": "short@d1zzy-test.net", "handle": "shorty"}
    r = await client.post("/register", data=base | {"password": "short", "password2": "short"})
    assert r.status_code == 400 and "at least 10 characters" in r.text
    r = await client.post(
        "/register",
        data=base
        | {
            "handle": "Bad Handle!",
            "password": "a-long-password-1",
            "password2": "a-long-password-1",
        },
    )
    assert r.status_code == 400 and "handle" in r.text


async def test_handle_must_be_unique(make_user, make_client):
    user = await make_user()
    client = await make_client()
    r = await client.post(
        "/auth/register",
        json={
            "email": "other@d1zzy-test.net",
            "password": "a-long-password-123",
            "handle": user.handle,
        },
    )
    assert r.status_code == 400 and r.json()["detail"] == "REGISTER_HANDLE_TAKEN"


async def test_silent_refresh_when_access_token_missing(make_user):
    """Access JWTs live 15 minutes; the refresh cookie keeps no-JS users logged in."""
    user = await make_user()
    user.client.cookies.delete(ACCESS_COOKIE)
    r = await user.client.get("/settings")
    assert r.status_code == 200
    assert ACCESS_COOKIE in r.headers.get("set-cookie", "")


async def test_explicit_refresh_endpoint(make_user):
    user = await make_user()
    r = await user.client.post("/auth/refresh")
    assert r.status_code == 200
    cookies = r.headers.get_list("set-cookie")
    assert any(c.startswith(ACCESS_COOKIE) for c in cookies)
    assert any(c.startswith(REFRESH_COOKIE) for c in cookies)


async def test_refresh_rejects_garbage(make_client):
    client = await make_client()
    client.cookies.set(REFRESH_COOKIE, "not-a-jwt")
    r = await client.post("/auth/refresh")
    assert r.status_code == 401


async def test_email_verification(make_user, db, monkeypatch):
    from app.core import queue as queue_module

    sent = []

    async def capture(function, *args, **kwargs):
        sent.append((function, args))

    monkeypatch.setattr(queue_module.queue, "enqueue", capture)
    user = await make_user()
    r = await user.form("/verify/resend")
    assert r.status_code == 303
    function, (to, subject, body) = sent[-1]
    assert function == "send_email" and to == user.email
    token = re.search(r"token=([\w.\-]+)", body).group(1)

    r = await user.client.get(f"/verify?token={token}")
    assert r.status_code == 303 and r.headers["location"] == "/settings?m=verified"
    verified = await db.scalar(select(User.is_verified).where(User.id == user.id))
    assert verified is True


async def test_logout_clears_cookies(make_user):
    user = await make_user()
    r = await user.form("/logout")
    assert r.status_code == 303
    cookies = " ".join(r.headers.get_list("set-cookie"))
    assert f'{ACCESS_COOKIE}=""' in cookies and f'{REFRESH_COOKIE}=""' in cookies


async def test_key_upload_requires_proof_of_possession(make_user):
    import os

    from app.core import crypto

    user = await make_user(keys=False)
    ident = crypto.identity_from_seed(os.urandom(32))
    other = crypto.identity_from_seed(os.urandom(32))
    payload = crypto.keys_payload(
        str(user.id), ident.signing_pk, ident.exchange_pk, ident.profile_pk
    )
    body = {
        "signing_pubkey": crypto.b64e(ident.signing_pk),
        "exchange_pubkey": crypto.b64e(ident.exchange_pk),
        "profile_enc_key": crypto.b64e(ident.profile_pk),
        "proof": crypto.b64e(other.sign("keys", payload)),  # signed by the wrong key
    }
    r = await user.api("PUT", "/api/users/me/keys", body)
    assert r.status_code == 400
    body["proof"] = crypto.b64e(ident.sign("keys", payload))
    r = await user.api("PUT", "/api/users/me/keys", body)
    assert r.status_code == 200
