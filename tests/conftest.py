"""Test fixtures. Tests run against real Postgres, Redis and IPFS (Kubo):

* default: throwaway containers started with testcontainers (rootless Podman works: `just
  test` points DOCKER_HOST at the Podman socket and disables Ryuk);
* or externally provided services via TEST_DATABASE_URL / TEST_REDIS_URL / TEST_IPFS_API_URL
  (used by deploy/compose/podman-compose.test.yml).

Containers start in pytest_sessionstart, before test modules are imported, because the
app reads its settings at import time.
"""

import asyncio
import os
import uuid
from dataclasses import dataclass

import httpx
import pytest

from app.config import clear_settings_cache
from app.models import UserRole

_containers: list = []


def _start_services() -> None:
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs
    from testcontainers.postgres import PostgresContainer
    from testcontainers.redis import RedisContainer

    if not os.environ.get("TEST_DATABASE_URL"):
        pg = PostgresContainer("docker.io/library/postgres:16-alpine", driver="asyncpg")
        pg.start()
        _containers.append(pg)
        os.environ["TEST_DATABASE_URL"] = pg.get_connection_url()

    if not os.environ.get("TEST_REDIS_URL"):
        redis = RedisContainer("docker.io/library/redis:7-alpine")
        redis.start()
        _containers.append(redis)
        host, port = redis.get_container_host_ip(), redis.get_exposed_port(6379)
        os.environ["TEST_REDIS_URL"] = f"redis://{host}:{port}/0"

    if not os.environ.get("TEST_IPFS_API_URL"):
        ipfs = (
            DockerContainer("docker.io/ipfs/kubo:v0.33.0")
            .with_command("daemon --migrate=true --offline")
            .with_exposed_ports(5001)
        )
        ipfs.start()
        _containers.append(ipfs)
        wait_for_logs(ipfs, "Daemon is ready", timeout=90)
        host, port = ipfs.get_container_host_ip(), ipfs.get_exposed_port(5001)
        os.environ["TEST_IPFS_API_URL"] = f"http://{host}:{port}/api/v0"


def pytest_sessionstart(session) -> None:
    _start_services()
    os.environ.update(
        {
            "MODE": "development",
            "DATABASE_URL": os.environ["TEST_DATABASE_URL"],
            "REDIS_URL": os.environ["TEST_REDIS_URL"],
            "IPFS_API_URL": os.environ["TEST_IPFS_API_URL"],
            "SECRET_KEY": "test-secret-key-0123456789",
            "RATE_LIMIT_PER_MINUTE": "0",
            "AUTO_HIDE_REPORT_THRESHOLD": "3",
            "STRIPE_SECRET_KEY": "sk_test_dummy",
            "STRIPE_WEBHOOK_SECRET": "whsec_test_secret",
            "BTCPAY_URL": "http://btcpay.test",
            "BTCPAY_API_KEY": "btcpay-test-key",
            "BTCPAY_STORE_ID": "store1",
            "BTCPAY_WEBHOOK_SECRET": "btcpay-webhook-secret",
            "MONERO_RPC_URL": "",
            "PUBLIC_BASE_URL": "http://test",
            "TOR_HOSTNAME_FILE": "/nonexistent",
            "LOG_LEVEL": "WARNING",
        }
    )
    os.environ.pop("MARKET_KEY", None)
    os.environ.pop("SERVER_SIGNING_SEED", None)
    # Clear cached settings so test environment variables take effect
    clear_settings_cache()


def pytest_sessionfinish(session, exitstatus) -> None:
    for c in reversed(_containers):
        try:
            c.stop()
        except Exception:  # noqa: BLE001
            pass


# --- App + DB ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
async def app():
    from alembic.config import Config

    from alembic import command

    cfg = Config("alembic.ini")
    await asyncio.to_thread(command.upgrade, cfg, "head")  # env.py runs its own event loop

    from app.core.queue import queue
    from app.main import app as fastapi_app

    await queue.connect()
    yield fastapi_app
    await queue.close()


@pytest.fixture
async def db(app):
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as session:
        yield session


# --- Clients & users --------------------------------------------------------------------


@dataclass
class TestUser:
    id: uuid.UUID
    email: str
    handle: str
    password: str
    client: httpx.AsyncClient
    identity: object | None = None

    @property
    def csrf(self) -> str:
        return self.client.cookies.get("d1zzy_csrf")

    async def form(self, url: str, data: dict | None = None, files=None, **kw) -> httpx.Response:
        """No-JS style form POST (CSRF token as a hidden field)."""
        return await self.client.post(
            url, data={"csrf_token": self.csrf, **(data or {})}, files=files, **kw
        )

    async def api(self, method: str, url: str, json=None, **kw) -> httpx.Response:
        """JS style JSON call (CSRF token in the X-CSRF-Token header)."""
        headers = {"X-CSRF-Token": self.csrf, "Accept": "application/json"}
        return await self.client.request(method, url, json=json, headers=headers, **kw)


@pytest.fixture
async def make_client(app):
    clients: list[httpx.AsyncClient] = []

    async def factory() -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        )
        await client.get("/login")  # obtain the CSRF cookie
        clients.append(client)
        return client

    yield factory
    for c in clients:
        await c.aclose()


@pytest.fixture
def make_user(app, make_client, db):
    """Registers + logs in a user via the fastapi-users JSON API. Options: vendor, moderator,
    keys (upload a fresh Ed25519/X25519 identity)."""
    from sqlalchemy import update

    from app.core import crypto
    from app.models import User

    async def factory(*, vendor=False, moderator=False, keys=True, verified=False) -> TestUser:
        client = await make_client()
        handle = "u" + uuid.uuid4().hex[:10]
        email, password = f"{handle}@d1zzy-test.net", "a-long-password-123"
        r = await client.post(
            "/auth/register", json={"email": email, "password": password, "handle": handle}
        )
        assert r.status_code == 201, r.text
        uid = uuid.UUID(r.json()["id"])
        values = {"is_vendor": vendor, "is_superuser": moderator, "is_verified": verified}
        if moderator:
            values["role"] = UserRole.SUPERADMIN
        elif vendor:
            values["role"] = UserRole.VENDOR
        await db.execute(update(User).where(User.id == uid).values(**values))
        await db.commit()
        r = await client.post("/auth/jwt/login", data={"username": email, "password": password})
        assert r.status_code == 204, r.text
        user = TestUser(uid, email, handle, password, client)
        if keys:
            user.identity = crypto.identity_from_seed(os.urandom(32))
            await upload_keys(user)
        return user

    return factory


async def upload_keys(user: TestUser) -> None:
    from app.core import crypto

    ident = user.identity
    proof = ident.sign(
        "keys",
        crypto.keys_payload(str(user.id), ident.signing_pk, ident.exchange_pk, ident.profile_pk),
    )
    r = await user.api(
        "PUT",
        "/api/users/me/keys",
        {
            "signing_pubkey": crypto.b64e(ident.signing_pk),
            "exchange_pubkey": crypto.b64e(ident.exchange_pk),
            "profile_enc_key": crypto.b64e(ident.profile_pk),
            "proof": crypto.b64e(proof),
        },
    )
    assert r.status_code == 200, r.text


# --- Domain helpers ---------------------------------------------------------------------


def listing_plain(**overrides) -> dict:
    base = {
        "title": "Test item " + uuid.uuid4().hex[:6],
        "desc": "A thing for sale",
        "price_cents": 2500,
        "currency": "usd",
        "category": "electronics",
        "condition": "good",
        "images": [],
        "location_approx": "Somewhere",
        "expires_at": None,
    }
    return base | overrides


async def create_listing(seller: TestUser, **overrides) -> str:
    """Client-side path: seal with the market key, sign with the seller's own key."""
    from app.core import crypto

    ct = crypto.seal_json(listing_plain(**overrides))
    sig = seller.identity.sign("listing", ct)
    r = await seller.api("POST", "/api/listings", {"ct": crypto.b64e(ct), "sig": crypto.b64e(sig)})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def create_offer(buyer: TestUser, listing_id: str, **overrides) -> str:
    from app.core import crypto

    plain = {
        "amount_cents": 2000,
        "currency": "usd",
        "message": "would you take 20?",
        "expires_at": None,
        "payment_method": "stripe",
    } | overrides
    ct = crypto.seal_json(plain)
    sig = buyer.identity.sign("offer", ct)
    r = await buyer.api(
        "POST",
        "/api/offers",
        {"listing_id": listing_id, "offer_ct": crypto.b64e(ct), "sig": crypto.b64e(sig)},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def set_offer_status(db, offer_id: str, status: str) -> None:
    from sqlalchemy import update

    from app.models import Offer

    await db.execute(update(Offer).where(Offer.id == uuid.UUID(offer_id)).values(status=status))
    await db.commit()


@pytest.fixture
def helpers():
    class H:
        create_listing = staticmethod(create_listing)
        create_offer = staticmethod(create_offer)
        set_offer_status = staticmethod(set_offer_status)
        listing_plain = staticmethod(listing_plain)
        upload_keys = staticmethod(upload_keys)

    return H
