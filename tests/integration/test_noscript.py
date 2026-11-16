"""Tor Browser at "Safest" disables JavaScript. Everything must still work through plain
HTML forms, and pages must never reach out to third-party hosts."""

import re
from pathlib import Path

from sqlalchemy import select

from app.cli import _png
from app.core import crypto
from app.models import Listing

ICON_SUBSET = set(Path("app/static/vendor/fonts/icons.txt").read_text().split())
EXTERNAL = re.compile(r"""(?:src|href|action)\s*=\s*["'](?:https?:)?//""", re.I)


async def test_create_listing_with_image_via_plain_form(make_user, db):
    seller = await make_user(vendor=True, keys=False)
    image = _png((1, 2, 3))
    r = await seller.form(
        "/listings/new",
        {
            "title": "No-JS lamp",
            "desc": "posted from Tor Browser",
            "price": "12.50",
            "currency": "eur",
            "category": "home",
            "condition": "good",
            "location_approx": "",
            "expires_at": "",
        },
        files={"images": ("lamp.png", image, "image/png")},
    )
    assert r.status_code == 303, r.text
    listing_id = r.headers["location"].split("/")[2].split("?")[0]
    listing = await db.scalar(select(Listing).where(Listing.seller_id == seller.id))
    assert str(listing.id) == listing_id
    assert crypto.sig_origin("listing", listing.listing_ct, listing.sig, None) == "server"
    plain = crypto.open_json(listing.listing_ct)
    assert plain["price_cents"] == 1250 and len(plain["images"]) == 1

    page = await seller.client.get(f"/listings/{listing_id}")
    assert "No-JS lamp" in page.text and "Server-signed" in page.text
    img = await seller.client.get(f"/media/{listing_id}/0")
    assert img.content == image  # image loads without JS (server decrypts)


async def test_edit_listing_via_plain_form_removes_image(make_user, db):
    seller = await make_user(vendor=True, keys=False)
    r = await seller.form(
        "/listings/new",
        {
            "title": "Two photos",
            "price": "1",
            "currency": "usd",
            "category": "other",
            "condition": "new",
        },
        files=[
            ("images", ("a.png", _png((9, 9, 9)), "image/png")),
            ("images", ("b.png", _png((8, 8, 8)), "image/png")),
        ],
    )
    listing_id = r.headers["location"].split("/")[2].split("?")[0]
    r = await seller.form(
        f"/listings/{listing_id}/edit",
        {
            "title": "One photo",
            "price": "2",
            "currency": "usd",
            "category": "other",
            "condition": "new",
            "remove_images": "0",
        },
    )
    assert r.status_code == 303
    listing = await db.scalar(select(Listing).where(Listing.seller_id == seller.id))
    await db.refresh(listing)
    plain = crypto.open_json(listing.listing_ct)
    assert plain["title"] == "One photo" and len(plain["images"]) == 1


async def test_every_form_has_method_action_and_csrf(make_user, helpers):
    seller = await make_user(vendor=True)
    buyer = await make_user()
    listing_id = await helpers.create_listing(seller)
    conv = (await buyer.form(f"/listings/{listing_id}/contact")).headers["location"]
    pages = [
        "/",
        "/listings",
        f"/listings/{listing_id}",
        "/settings",
        "/offers",
        conv,
        f"/u/{seller.handle}",
    ]
    for path in pages:
        html = (await buyer.client.get(path)).text
        for form in re.findall(r"<form\b[^>]*>.*?</form>", html, re.S):
            head = form[: form.index(">")]
            if 'method="dialog"' in head:  # the JS-only unlock dialog
                continue
            assert "action=" in head, (path, head)
            if 'method="post"' in head:
                assert 'name="csrf_token"' in form, (path, head)


async def test_chat_meta_refresh_and_noscript_notice(make_user, helpers):
    seller = await make_user(vendor=True)
    buyer = await make_user(keys=False)
    listing_id = await helpers.create_listing(seller)
    conv = (await buyer.form(f"/listings/{listing_id}/contact")).headers["location"]
    html = (await buyer.client.get(conv)).text
    assert re.search(r'<noscript><meta http-equiv="refresh" content="15"></noscript>', html)
    assert "not end-to-end encrypted" in html.lower()


async def test_no_third_party_requests_and_strict_csp(make_user, helpers):
    seller = await make_user(vendor=True)
    listing_id = await helpers.create_listing(seller)
    for path in ["/", "/listings", f"/listings/{listing_id}", "/login", "/register", "/settings"]:
        r = await seller.client.get(path)
        external = [m for m in EXTERNAL.findall(r.text)]
        assert not external, (path, external)
        assert "<script>" not in r.text and " onclick=" not in r.text  # nothing inline
        csp = r.headers["content-security-policy"]
        assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp


async def test_vendor_libraries_are_served_locally(make_client):
    client = await make_client()
    for f in ["htmx.min.js", "alpine.min.js", "fuse.min.js", "libsodium.wasm.js"]:
        r = await client.get(f"/static/vendor/{f}")
        assert r.status_code == 200 and len(r.content) > 10_000, f
    # main.css pulls the design system in with @import; follow it like a browser would.
    css = (await client.get("/static/css/main.css")).text
    for name in re.findall(r'@import\s+"([^"]+)"', css):
        r = await client.get(f"/static/css/{name}")
        assert r.status_code == 200, name
        css += r.text
    assert ".btn-primary" in css and "@font-face" in css
    font = await client.get("/static/vendor/fonts/MaterialSymbolsRounded.woff2")
    # Subset by `just icons`; the full font is ~5.4 MB, far too heavy over Tor.
    assert font.status_code == 200 and len(font.content) < 200_000


async def test_every_rendered_icon_is_in_the_font_subset(make_user, make_client, helpers):
    """Icons are font ligatures: a name missing from the subset renders as letters. Render
    real pages (with every nav item a vendor-moderator sees) and check each icon name."""
    user = await make_user(vendor=True, moderator=True)
    other = await make_user(vendor=True)
    listing_id = await helpers.create_listing(other)
    conv = (await user.form(f"/listings/{listing_id}/contact")).headers["location"]
    pages = [
        "/",
        "/listings",
        f"/listings/{listing_id}",
        "/listings/new",
        "/settings",
        "/offers",
        "/messages",
        conv,
        "/vendor",
        "/moderation",
        f"/u/{other.handle}",
        "/listings?m=listing_created",
        "/nonexistent",
    ]
    span = re.compile(r'class="[^"]*material-symbols-rounded[^"]*"[^>]*>\s*([^<]*?)\s*</span>')
    seen = set()
    for path in pages:
        seen |= set(span.findall((await user.client.get(path)).text))
    anon = await make_client()
    for path in ["/", "/login", "/register", "/reset-password"]:
        seen |= set(span.findall((await anon.get(path)).text))
    seen.discard("")
    assert seen, "no icons found; did the markup change?"
    assert seen <= ICON_SUBSET, (
        f"run `just icons`; missing from the font subset: {seen - ICON_SUBSET}"
    )


async def test_logs_contain_no_client_ips(make_client, capsys):
    client = await make_client()
    await client.get("/listings", headers={"x-forwarded-for": "203.0.113.7"})
    out = capsys.readouterr()
    assert "203.0.113.7" not in out.out + out.err and "127.0.0.1" not in out.out + out.err


def test_alpine_directives_are_csp_build_compatible():
    """The Alpine CSP build only evaluates property paths: no x-model (an assignment), no
    operators or call arguments. Violations fail silently in the browser, so check here."""
    from pathlib import Path

    directive = re.compile(r'\s(x-(?:model|show|text|bind:\w+|on:[\w.]+|data|init))="([^"]*)"')
    for path in Path("app/templates").rglob("*.html"):
        for name, expr in directive.findall(path.read_text()):
            assert name != "x-model", f"{path}: x-model is unsupported by the Alpine CSP build"
            assert re.fullmatch(r"[A-Za-z_$][\w$.]*", expr), f"{path}: {name}={expr!r}"


def test_js_class_selectors_exist_in_markup():
    """app.js finds elements by class; a template refactor that renames a class silently
    breaks the browser side (this happened to chat decryption). Check every $(".x") hook."""
    js = Path("app/static/js/app.js").read_text()
    markup = "\n".join(p.read_text() for p in Path("app/templates").rglob("*.html"))
    used = set(re.findall(r'\$\("[#.]?([\w-]+)[^"]*"', js)) | set(
        re.findall(r'querySelector(?:All)?\("[^"]*?\.([\w-]+)', js)
    )
    missing = {
        c
        for c in used
        if not re.search(
            rf'(class="[^"]*\b{re.escape(c)}\b|id="{re.escape(c)}"|<{re.escape(c)}\b)', markup
        )
    }
    assert not missing, f"app.js selects classes/ids not present in any template: {missing}"
