"""Kubo RPC client (https://docs.ipfs.tech/reference/kubo/rpc/).

Uses httpx directly: ipfshttpclient is unmaintained and refuses to talk to Kubo >= 0.8.
Every RPC call is a POST. Only ciphertext is ever added; keys live inside listing blobs.
"""

import httpx

from app.config import get_settings


class IPFSError(RuntimeError):
    pass


class IPFSClient:
    def __init__(self, api_url: str | None = None, timeout: float = 30.0):
        self.api_url = (api_url or get_settings().ipfs_api_url).rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.api_url, timeout=timeout)

    async def __aenter__(self) -> "IPFSClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, **kwargs) -> httpx.Response:
        try:
            r = await self._client.post(path, **kwargs)
        except httpx.HTTPError as e:
            raise IPFSError(f"IPFS unreachable: {e}") from e
        if r.status_code != 200:
            raise IPFSError(f"IPFS {path} failed: {r.status_code} {r.text[:200]}")
        return r

    async def id(self) -> dict:
        return (await self._post("/id")).json()

    async def add(self, data: bytes, *, pin: bool = True) -> str:
        r = await self._post(
            "/add",
            params={"pin": str(pin).lower(), "cid-version": "1", "quieter": "true"},
            files={"file": ("blob", data, "application/octet-stream")},
        )
        return r.json()["Hash"]

    async def pin(self, cid: str) -> None:
        await self._post("/pin/add", params={"arg": cid})

    async def unpin(self, cid: str) -> None:
        await self._post("/pin/rm", params={"arg": cid})

    async def is_pinned(self, cid: str) -> bool:
        try:
            r = await self._post("/pin/ls", params={"arg": cid, "type": "recursive"})
        except IPFSError:
            return False
        return cid in r.json().get("Keys", {})

    async def cat(self, cid: str, max_bytes: int | None = None) -> bytes:
        params = {"arg": cid}
        if max_bytes:
            params["length"] = str(max_bytes)
        return (await self._post("/cat", params=params)).content

    async def ls(self, cid: str) -> list[dict]:
        r = await self._post("/ls", params={"arg": cid})
        return [link for obj in r.json().get("Objects", []) for link in obj.get("Links", [])]
