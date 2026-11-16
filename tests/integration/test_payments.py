"""Payment provider integration: Stripe webhook signatures, BTCPay invoices + webhooks,
worker polling, and a real Monero 2-of-3 multisig escrow on regtest (~40 s; set
SKIP_MONERO_TESTS=1 or use `just test-fast` to skip it)."""

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.core import btcpay
from app.models import Offer


def stripe_signature(payload: bytes, secret: str, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def btcpay_signature(payload: bytes, secret: str = "btcpay-webhook-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def test_stripe_webhook_rejects_bad_signatures(make_client):
    client = await make_client()
    payload = json.dumps(
        {"id": "evt", "type": "checkout.session.completed", "data": {"object": {}}}
    ).encode()
    for header in ["", "t=1,v1=deadbeef", stripe_signature(payload, "whsec_wrong")]:
        r = await client.post(
            "/webhooks/stripe", content=payload, headers={"stripe-signature": header}
        )
        assert r.status_code == 400
    # Stale timestamp (replay) is rejected too.
    old = stripe_signature(payload, "whsec_test_secret", ts=int(time.time()) - 3600)
    r = await client.post("/webhooks/stripe", content=payload, headers={"stripe-signature": old})
    assert r.status_code == 400
    ok = stripe_signature(payload, "whsec_test_secret")
    r = await client.post("/webhooks/stripe", content=payload, headers={"stripe-signature": ok})
    assert r.status_code == 200


async def test_btcpay_webhook_hmac(make_client):
    client = await make_client()
    payload = b'{"type":"InvoiceSettled","invoiceId":"nope"}'
    assert btcpay.verify_webhook(payload, btcpay_signature(payload))
    assert not btcpay.verify_webhook(payload, btcpay_signature(payload, "wrong"))
    assert not btcpay.verify_webhook(payload, None)
    r = await client.post("/webhooks/btcpay", content=payload, headers={"btcpay-sig": "sha256=00"})
    assert r.status_code == 400
    r = await client.post(
        "/webhooks/btcpay", content=payload, headers={"btcpay-sig": btcpay_signature(payload)}
    )
    assert r.status_code == 200


async def test_poll_btcpay_marks_settled_invoices_paid(make_user, helpers, db, monkeypatch):
    from app.workers import tasks

    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    offer_id = await helpers.create_offer(buyer, listing_id, payment_method="lightning")
    offer = await db.get(Offer, uuid.UUID(offer_id))
    offer.status, offer.payment_ref = "accepted", "inv_poll_" + offer_id
    await db.commit()

    def handler(request):
        status = "Settled" if request.url.path.endswith(offer.payment_ref) else "New"
        return httpx.Response(200, json={"id": "x", "status": status})

    original = btcpay.BTCPayClient.__init__
    monkeypatch.setattr(
        btcpay.BTCPayClient,
        "__init__",
        lambda self, *a, **kw: original(self, *a, transport=httpx.MockTransport(handler), **kw),
    )
    assert await tasks.poll_btcpay({}) >= 1
    status = await db.scalar(select(Offer.status).where(Offer.id == offer.id))
    assert status == "paid"


# --- Monero (regtest, real daemon + wallet-rpc) -----------------------------------------

monero = pytest.mark.skipif(
    bool(os.environ.get("SKIP_MONERO_TESTS")), reason="SKIP_MONERO_TESTS is set"
)


ROLES = ("buyer", "seller", "market")


@pytest.fixture(scope="module")
def monero_stack():
    """monerod (regtest) + one wallet-rpc per escrow party, as in real life: each party runs
    their own wallet. (Multisig's experimental flag only lives in an open wallet, so one
    wallet-rpc switching between wallets would not work anyway.)"""
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.network import Network
    from testcontainers.core.waiting_utils import wait_for_logs

    network = Network().create()
    started = []
    daemon = (
        DockerContainer("docker.io/sethsimmons/simple-monerod:v0.18.3.4")
        .with_network(network)
        .with_network_aliases("monerod")
        .with_command(
            "--regtest --offline --fixed-difficulty=1 --no-igd --rpc-bind-ip=0.0.0.0 "
            "--rpc-bind-port=18081 --confirm-external-bind --disable-rpc-ban"
        )
        .with_exposed_ports(18081)
    )
    daemon.start()
    started.append(daemon)
    wait_for_logs(daemon, "RPC server initialized OK", timeout=120)
    urls = {
        "daemon": f"http://{daemon.get_container_host_ip()}:{daemon.get_exposed_port(18081)}/json_rpc"
    }
    for role in ROLES:
        wallet = (
            DockerContainer("docker.io/sethsimmons/simple-monero-wallet-rpc:v0.18.3.4")
            .with_network(network)
            .with_command(
                "--daemon-address=monerod:18081 --trusted-daemon --allow-mismatched-daemon-version "
                "--rpc-bind-port=18083 --disable-rpc-login --wallet-dir=/home/monero/wallet"
            )
            .with_exposed_ports(18083)
        )
        wallet.start()
        started.append(wallet)
        wait_for_logs(wallet, "Starting wallet RPC server", timeout=120)
        urls[role] = (
            f"http://{wallet.get_container_host_ip()}:{wallet.get_exposed_port(18083)}/json_rpc"
        )
    yield urls
    for c in reversed(started):
        c.stop()
    network.remove()


@monero
@pytest.mark.monero
async def test_monero_multisig_escrow_create_fund_release(monero_stack):
    """2-of-3 escrow (buyer, seller, market): create, fund, detect funding, then release to
    the seller with two of three signatures (market + seller)."""
    from contextlib import AsyncExitStack

    from app.core.monero import DaemonRPC, WalletRPC, xmr_to_atomic

    async with AsyncExitStack() as stack:
        w = {r: await stack.enter_async_context(WalletRPC(monero_stack[r], "", "")) for r in ROLES}
        d = await stack.enter_async_context(DaemonRPC(monero_stack["daemon"]))
        for role, wallet in w.items():
            await wallet.call(
                "create_wallet",
                {"filename": f"{role}-escrow", "password": "", "language": "English"},
            )

        # Key setup: prepare -> make -> exchange rounds until every wallet is ready.
        infos = {r: await w[r].prepare_multisig() for r in ROLES}
        rounds = {
            r: (await w[r].make_multisig([infos[o] for o in ROLES if o != r], threshold=2))[
                "multisig_info"
            ]
            for r in ROLES
        }
        for _ in range(4):
            pending = [r for r in ROLES if not (await w[r].is_multisig()).get("ready")]
            if not pending:
                break
            nxt = {}
            for r in pending:
                res = await w[r].exchange_multisig_keys([rounds[o] for o in ROLES if o != r])
                nxt[r] = res.get("multisig_info", "")
            rounds |= nxt
        statuses = [await w[r].is_multisig() for r in ROLES]
        assert all(s["multisig"] and s["ready"] and s["threshold"] == 2 for s in statuses)
        addresses = {await w[r].get_address() for r in ROLES}
        assert len(addresses) == 1
        escrow = addresses.pop()

        # Fund: mine coinbase outputs straight to the escrow address, then let them unlock.
        await d.generate_blocks(escrow, 80)
        for _ in range(30):
            await w["market"].call("refresh")
            balance, unlocked = await w["market"].get_balance()
            if unlocked > 0:
                break
            await asyncio.sleep(1)
        assert unlocked >= xmr_to_atomic("1")

        # Release: every party syncs, then they swap multisig info (partial key images), the
        # market drafts the payout and the seller co-signs and submits it.
        for r in ROLES:
            await w[r].call("refresh")
        exported = {r: await w[r].export_multisig_info() for r in ROLES}
        for r in ROLES:
            await w[r].import_multisig_info([exported[o] for o in ROLES if o != r])
        payout = (await w["seller"].call("create_address", {"account_index": 0}))["address"]
        draft = await w["market"].call(
            "transfer", {"destinations": [{"amount": xmr_to_atomic("1"), "address": payout}]}
        )
        signed = await w["seller"].sign_multisig(draft["multisig_txset"])
        tx_hashes = await w["seller"].submit_multisig(signed["tx_data_hex"])
        assert len(tx_hashes) == 1
