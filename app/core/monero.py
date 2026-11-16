"""monero-wallet-rpc client (testnet/regtest only).

Marketplace flow: each Monero offer gets its own subaddress in the market wallet; the worker
watches it for an incoming transfer of at least the offer amount. The multisig helpers below
implement 2-of-3 escrow setup (buyer, seller, market) over wallet-rpc; wiring them into the
UI needs buyer/seller-operated wallets and is not done yet.

Docs: https://docs.getmonero.org/rpc-library/wallet-rpc/
"""

from decimal import Decimal
from typing import Any

import httpx

from app.config import get_settings

PICONERO = Decimal("1e12")


class MoneroError(RuntimeError):
    pass


def xmr_to_atomic(xmr: Decimal | str) -> int:
    return int(Decimal(xmr) * PICONERO)


def atomic_to_xmr(atomic: int) -> Decimal:
    return Decimal(atomic) / PICONERO


class _JsonRpc:
    def __init__(self, url: str, user: str = "", password: str = "", timeout: float = 60.0):
        auth = httpx.DigestAuth(user, password) if user else None
        self._client = httpx.AsyncClient(timeout=timeout, auth=auth)
        self.url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def call(self, method: str, params: dict | None = None) -> Any:
        try:
            r = await self._client.post(
                self.url,
                json={"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}},
            )
        except httpx.HTTPError as e:
            raise MoneroError(f"monero rpc unreachable: {e}") from e
        if r.status_code != 200:
            raise MoneroError(f"{method}: HTTP {r.status_code}")
        body = r.json()
        if "error" in body:
            raise MoneroError(f"{method}: {body['error'].get('message')}")
        return body["result"]


class WalletRPC(_JsonRpc):
    def __init__(
        self, url: str | None = None, user: str | None = None, password: str | None = None
    ):
        s = get_settings()
        super().__init__(
            url or s.monero_rpc_url,
            s.monero_rpc_user if user is None else user,
            s.monero_rpc_password if password is None else password,
        )

    async def ensure_wallet(self, name: str | None = None, password: str | None = None) -> None:
        s = get_settings()
        name = name or s.monero_wallet_name
        password = s.monero_wallet_password if password is None else password
        try:
            await self.call("open_wallet", {"filename": name, "password": password})
        except MoneroError:
            await self.call(
                "create_wallet", {"filename": name, "password": password, "language": "English"}
            )

    async def get_address(self) -> str:
        return (await self.call("get_address", {"account_index": 0}))["address"]

    async def create_subaddress(self, label: str) -> tuple[str, int]:
        r = await self.call("create_address", {"account_index": 0, "label": label})
        return r["address"], r["address_index"]

    async def get_address_index(self, address: str) -> int:
        return (await self.call("get_address_index", {"address": address}))["index"]["minor"]

    async def received_atomic(self, subaddr_index: int, min_confirmations: int = 0) -> int:
        """Total received on a subaddress (including the pool when min_confirmations == 0)."""
        await self.call("refresh")
        r = await self.call(
            "get_transfers",
            {
                "in": True,
                "pool": min_confirmations == 0,
                "account_index": 0,
                "subaddr_indices": [subaddr_index],
            },
        )
        txs = r.get("in", []) + r.get("pool", [])
        return sum(t["amount"] for t in txs if t.get("confirmations", 0) >= min_confirmations)

    async def get_balance(self) -> tuple[int, int]:
        r = await self.call("get_balance", {"account_index": 0})
        return r["balance"], r["unlocked_balance"]

    async def transfer(self, address: str, atomic: int) -> str:
        r = await self.call("transfer", {"destinations": [{"amount": atomic, "address": address}]})
        return r["tx_hash"]

    # --- 2-of-3 multisig escrow ---------------------------------------------------------

    async def prepare_multisig(self) -> str:
        return (await self.call("prepare_multisig", {"enable_multisig_experimental": True}))[
            "multisig_info"
        ]

    async def make_multisig(self, infos: list[str], threshold: int = 2, password: str = "") -> dict:
        return await self.call(
            "make_multisig",
            {"multisig_info": infos, "threshold": threshold, "password": password},
        )

    async def exchange_multisig_keys(self, infos: list[str], password: str = "") -> dict:
        return await self.call(
            "exchange_multisig_keys", {"multisig_info": infos, "password": password}
        )

    async def is_multisig(self) -> dict:
        return await self.call("is_multisig")

    async def export_multisig_info(self) -> str:
        return (await self.call("export_multisig_info"))["info"]

    async def import_multisig_info(self, infos: list[str]) -> int:
        return (await self.call("import_multisig_info", {"info": infos}))["n_outputs"]

    async def sign_multisig(self, tx_data_hex: str) -> dict:
        return await self.call("sign_multisig", {"tx_data_hex": tx_data_hex})

    async def submit_multisig(self, tx_data_hex: str) -> list[str]:
        return (await self.call("submit_multisig", {"tx_data_hex": tx_data_hex}))["tx_hash_list"]


class DaemonRPC(_JsonRpc):
    """monerod JSON-RPC; used for regtest block generation in tests."""

    async def generate_blocks(self, address: str, n: int) -> int:
        r = await self.call("generateblocks", {"amount_of_blocks": n, "wallet_address": address})
        return r["height"]

    async def get_height(self) -> int:
        return (await self.call("get_block_count"))["count"]
