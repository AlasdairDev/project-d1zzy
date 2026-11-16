"""Subset Material Symbols Rounded to the icons the site actually uses.

The full variable font is ~5.4 MB, which is painful over Tor. Icon names are ligatures
made of ordinary letters, so a plain `pyftsubset --text` keeps every ligature; instead we
prune the ligature table to the names we use, then subset glyphs to match.

    uv run python scripts/subset_icons.py        (or `just icons`)

Source:  scripts/assets/fonts/MaterialSymbolsRounded.woff2   (full font, not served)
Output:  app/static/vendor/fonts/MaterialSymbolsRounded.woff2 + icons.txt
"""

import re
import string
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "scripts" / "assets" / "fonts" / "MaterialSymbolsRounded.woff2"
OUT = ROOT / "app" / "static" / "vendor" / "fonts" / "MaterialSymbolsRounded.woff2"
LIST = OUT.with_name("icons.txt")

ICON_SPAN = re.compile(r'class="[^"]*material-symbols-rounded[^"]*"[^>]*>(.*?)</span>', re.S)
# Inside a Jinja expression, names appear as dict values or default arguments:
#   {{ {"ok": "check_circle"}[kind] }}   {{ icons.get(c, 'category') }}
EXPR_NAME = re.compile(r"""[:,]\s*["']([a-z][a-z0-9_]*)["'](?!\s*:)""")
JS_ICON_MAP = re.compile(r"_ICON\s*=\s*\{([^}]*)\}")
QUOTED = re.compile(r'"([a-z][a-z0-9_]*)"')
ICON_ARG = re.compile(r'\bicon\s*=\s*["\']([a-z0-9_]+)["\']')
# base.html: nav_link(href, icon, label, ...) takes the icon as its second argument.
NAV_LINK = re.compile(r'nav_link\(\s*"[^"]*"\s*,\s*"([a-z0-9_]+)"')
JS_ICON = re.compile(r'icon\(\s*["\']([a-z0-9_]+)["\']')
PY_ICONS = re.compile(r'"[a-z_]+":\s*"([a-z0-9_]+)"')


def used_icons() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "app" / "templates").rglob("*.html"):
        text = path.read_text()
        for inner in ICON_SPAN.findall(text):
            # {% if %}a{% else %}b{% endif %}: drop the tags, keep the bare names.
            bare = re.sub(r"\{%.*?%\}|\{\{.*?\}\}", " ", inner, flags=re.S)
            names |= {t for t in bare.split() if re.fullmatch(r"[a-z0-9_]+", t)}
            if "{{" in inner:
                names |= set(EXPR_NAME.findall(inner))
        names |= set(ICON_ARG.findall(text)) | set(NAV_LINK.findall(text))
    for path in (ROOT / "app" / "static" / "js").glob("*.js"):
        text = path.read_text()
        names |= set(JS_ICON.findall(text))
        for body in JS_ICON_MAP.findall(text):
            names |= set(QUOTED.findall(body))
    icons_py = (ROOT / "app" / "models" / "listing.py").read_text()
    block = icons_py.split("CATEGORY_ICONS", 1)[1].split("}", 1)[0]
    names |= set(PY_ICONS.findall(block))
    return names


def ligature_name(glyph_names: list[str], cmap_rev: dict[str, str]) -> str:
    return "".join(cmap_rev.get(g, "?") for g in glyph_names)


def main() -> None:
    wanted = used_icons()
    font = TTFont(SRC)
    cmap_rev = {glyph: chr(code) for code, glyph in font.getBestCmap().items()}
    found: set[str] = set()

    for lookup in font["GSUB"].table.LookupList.Lookup:
        for sub in lookup.SubTable:
            real = sub.ExtSubTable if lookup.LookupType == 7 else sub
            if getattr(real, "LookupType", None) != 4 and not hasattr(real, "ligatures"):
                continue
            for first, ligs in list(real.ligatures.items()):
                keep = []
                for lig in ligs:
                    name = ligature_name([first, *lig.Component], cmap_rev)
                    if name in wanted:
                        keep.append(lig)
                        found.add(name)
                if keep:
                    real.ligatures[first] = keep
                else:
                    del real.ligatures[first]

    missing = sorted(wanted - found)
    if missing:
        sys.exit(f"unknown icon names (not in Material Symbols): {', '.join(missing)}")

    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = ["rlig", "rclt", "liga"]
    opts.notdef_outline = True
    sub = subset.Subsetter(opts)
    sub.populate(text=string.ascii_lowercase + string.digits + "_")
    sub.subset(font)
    font.flavor = "woff2"
    font.save(OUT)
    LIST.write_text("\n".join(sorted(found)) + "\n")
    print(f"{len(found)} icons -> {OUT.relative_to(ROOT)} ({OUT.stat().st_size / 1024:.0f} KiB)")


if __name__ == "__main__":
    main()
