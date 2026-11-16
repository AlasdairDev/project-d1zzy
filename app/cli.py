"""Demo and admin commands.

python -m app.cli seed
python -m app.cli create-moderator EMAIL PASSWORD [--handle NAME]
python -m app.cli create-vendor EMAIL PASSWORD [--handle NAME]
"""

import argparse
import asyncio
import os
import struct
import sys
import zlib

from fastapi_users.password import PasswordHelper
from sqlalchemy import select

from app.core import crypto
from app.core.ipfs import IPFSClient, IPFSError
from app.core.market import now, seal_model
from app.db.session import dispose_engine, get_sessionmaker
from app.models import Listing, User, UserRole
from app.schemas.listing import ListingPlain

DEMO_PASSWORD = "demo-password-123"
DEMO_PASSPHRASE = "correct horse battery staple"

DEMO_VENDORS = [
    ("alice@d1zzy.local", "alice", "Vintage electronics, tested and working."),
    ("bob@d1zzy.local", "bob", "Books and board games from my shelves."),
    ("carol@d1zzy.local", "carol", "Handmade clothes and accessories."),
]

DEMO_LISTINGS = [
    (
        "alice",
        "electronics",
        "Sony Walkman WM-EX194",
        "Cassette player, new belt, plays well.",
        250000,
        "php",
        "good",
        (48, 96, 160),
    ),
    (
        "alice",
        "electronics",
        "Raspberry Pi 4 (4GB) kit",
        "With case, PSU and 32GB card.",
        320000,
        "php",
        "like_new",
        (40, 140, 90),
    ),
    (
        "alice",
        "electronics",
        "Mechanical keyboard, brown switches",
        "TKL, PBT keycaps.",
        290000,
        "php",
        "good",
        (90, 90, 90),
    ),
    (
        "alice",
        "collectibles",
        "Game Boy Color, teal",
        "Original shell, minor scratches.",
        380000,
        "php",
        "fair",
        (20, 160, 160),
    ),
    (
        "bob",
        "books",
        "SICP, 2nd edition",
        "Hardcover, notes in pencil.",
        140000,
        "php",
        "good",
        (160, 40, 40),
    ),
    (
        "bob",
        "books",
        "The Cryptopals challenges, printed",
        "Spiral-bound printout.",
        45000,
        "php",
        "new",
        (200, 160, 40),
    ),
    (
        "bob",
        "sports",
        "Climbing shoes EU 42",
        "Resoled once.",
        180000,
        "php",
        "good",
        (120, 60, 160),
    ),
    (
        "bob",
        "home",
        "Moka pot, 6 cup",
        "Aluminium, new gasket.",
        90000,
        "php",
        "like_new",
        (100, 100, 110),
    ),
    (
        "carol",
        "fashion",
        "Hand-knit wool scarf",
        "Merino, 180 cm.",
        120000,
        "php",
        "new",
        (180, 80, 120),
    ),
    (
        "carol",
        "fashion",
        "Linen shirt, size M",
        "Natural dye, worn twice.",
        95000,
        "php",
        "like_new",
        (200, 190, 150),
    ),
    (
        "carol",
        "services",
        "Clothing repair, per item",
        "Hems, zips, patches. Ships back tracked.",
        35000,
        "php",
        "new",
        (60, 120, 60),
    ),
    (
        "carol",
        "other",
        "Sticker pack, 10 vinyl",
        "Weatherproof vinyl stickers.",
        25000,
        "php",
        "new",
        (240, 100, 20),
    ),
]


def _png(rgb: tuple[int, int, int], size: int = 64) -> bytes:
    """Solid-colour PNG, so the demo exercises the encrypted-image path without assets."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    raw = b"".join(b"\x00" + bytes(rgb) * size for _ in range(size))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


async def _get_or_create_user(
    session, email: str, handle: str, password: str, *, vendor=False, moderator=False
) -> tuple[User, bool]:
    user = await session.scalar(select(User).where(User.email == email))
    created = user is None
    if created:
        user = User(
            email=email,
            handle=handle,
            hashed_password=PasswordHelper().hash(password),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
    if vendor:
        if not user.is_vendor:
            user.is_vendor, user.vendor_since = True, now()
        if user.role in (None, UserRole.USER):
            user.role = UserRole.VENDOR
    if moderator:
        if user.role in (None, UserRole.USER):
            user.role = UserRole.MODERATOR
        user.is_superuser = True
    await session.flush()
    return user, created


async def seed() -> None:
    async with get_sessionmaker()() as session:
        await _get_or_create_user(
            session, "mod@d1zzy.local", "moderator", DEMO_PASSWORD, moderator=True
        )
        users: dict[str, User] = {}
        identities: dict[str, crypto.Identity] = {}
        for email, handle, bio in DEMO_VENDORS:
            user, _ = await _get_or_create_user(session, email, handle, DEMO_PASSWORD, vendor=True)
            ident = crypto.identity_from_passphrase(email, DEMO_PASSPHRASE)
            user.signing_pubkey, user.exchange_pubkey = ident.signing_pk, ident.exchange_pk
            user.profile_enc_key = ident.profile_pk
            user.vendor_bio_ct = crypto.seal_json({"bio": bio})
            users[handle], identities[handle] = user, ident
        await _get_or_create_user(session, "dave@d1zzy.local", "dave", DEMO_PASSWORD)
        await session.flush()

        existing = await session.scalar(
            select(Listing.id).where(Listing.seller_id.in_([u.id for u in users.values()]))
        )
        if existing:
            await session.commit()
            print("seed: demo data already present")
            return

        try:
            ipfs = IPFSClient()
            await ipfs.id()
        except IPFSError:
            ipfs = None
            print("seed: IPFS unreachable, listings will have no images", file=sys.stderr)

        for handle, cat, title, desc, price, cur, cond, rgb in DEMO_LISTINGS:
            images = []
            if ipfs:
                key = os.urandom(32)
                cid = await ipfs.add(crypto.seal(_png(rgb), key))
                images = [{"cid": cid, "key": crypto.b64e(key), "mime": "image/png"}]
            plain = ListingPlain(
                title=title,
                desc=desc,
                price_cents=price,
                currency=cur,
                category=cat,
                condition=cond,
                images=images,
                location_approx="Ships worldwide",
            )
            ct = seal_model(plain)
            session.add(
                Listing(
                    seller_id=users[handle].id,
                    listing_ct=ct,
                    sig=identities[handle].sign("listing", ct),  # signed by the seller's key
                    category=cat,
                )
            )
        if ipfs:
            await ipfs.aclose()
        await session.commit()
    print(
        f"seed: created moderator mod@d1zzy.local, vendors alice/bob/carol, buyer dave "
        f"(password '{DEMO_PASSWORD}', E2E passphrase '{DEMO_PASSPHRASE}') "
        f"and {len(DEMO_LISTINGS)} listings"
    )


async def create(email: str, password: str, handle: str | None, *, moderator: bool) -> None:
    async with get_sessionmaker()() as session:
        handle = handle or email.split("@")[0].lower()[:32]
        user, created = await _get_or_create_user(
            session, email, handle, password, vendor=not moderator, moderator=moderator
        )
        await session.commit()
    role = "moderator" if moderator else "vendor"
    print(f"{'created' if created else 'updated'} {role} {email} (@{user.handle})")


async def xmr_mine(blocks: int) -> None:
    from app.config import get_settings
    from app.core.monero import DaemonRPC, WalletRPC

    async with WalletRPC() as wallet:
        await wallet.ensure_wallet()
        address = await wallet.get_address()
    async with DaemonRPC(get_settings().monero_daemon_url) as daemon:
        height = await daemon.generate_blocks(address, blocks)
    print(f"mined {blocks} blocks to {address[:12]}..., height {height}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="load demo vendors, buyer, moderator and listings")
    for name in ("create-moderator", "create-vendor"):
        p = sub.add_parser(name)
        p.add_argument("email")
        p.add_argument("password")
        p.add_argument("--handle")
    mine = sub.add_parser("xmr-mine", help="regtest only: mine blocks to the market wallet")
    mine.add_argument("blocks", type=int, nargs="?", default=70)
    args = parser.parse_args(argv)

    async def run():
        try:
            if args.cmd == "seed":
                await seed()
            elif args.cmd == "xmr-mine":
                await xmr_mine(args.blocks)
            else:
                await create(
                    args.email, args.password, args.handle, moderator=args.cmd == "create-moderator"
                )
        finally:
            await dispose_engine()

    asyncio.run(run())


if __name__ == "__main__":
    main()
