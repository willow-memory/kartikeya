"""G2-vendor-pins-kartikeya — the vendored changelog tool is pinned to its
canonical body.

`tools/changelog_dedup.py` is vendored; its canonical home is
forge-play/Forge `tools/changelog_dedup.py`. Measured on 2026-09-12: the code
body — from the `from __future__ import annotations` line to EOF, 284 lines —
is byte-identical to Forge's. The module docstring above that line is local
and stays local: it describes *this* repo's release history, and Forge's
describes Forge's, so the two files differ there by design and agree
everywhere else.

This pins the body's SHA-256 against Forge's as measured that day. It catches
**this copy moving without a decision** — a fix landed here and not upstream,
a hand edit to a comment, a partial re-sync — not Forge moving: when Forge
changes, this test keeps passing until someone re-syncs, and the re-sync is
the moment to bump the constant with a commit that says why. A pin that
tracked Forge live would turn every upstream commit into a red build here
with no decision behind it.

The fleet's other copies are not twins of this one: willow-mcp's and jeles'
bodies are older snapshots missing fixes landed here (measured in #55). Their
re-sync is separate work with its own tests, because for them it is a
behaviour change.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_TOOL = _REPO / "tools" / "changelog_dedup.py"

#: The body starts at this line; everything above it is the local docstring.
_BODY_STARTS_AT = "from __future__ import annotations"

#: SHA-256 of the body of forge-play/Forge tools/changelog_dedup.py, from the
#: `from __future__` line to EOF, as measured 2026-09-12 (284 lines).
_FORGE_BODY_SHA256 = "e3f31ef11105ae37c495c1745a94c6992ceb587c549cd016f24e83c778fd1320"

_RESYNC = (
    "re-sync from forge-play/Forge tools/changelog_dedup.py (body from "
    "`from __future__` to EOF), or record a named local override here"
)


def _body(source: str) -> str:
    """The code body: from the `from __future__` line to EOF. The docstring
    above it is local and is not part of the pin."""
    start = source.find(_BODY_STARTS_AT)
    assert start >= 0, (
        f"no {_BODY_STARTS_AT!r} line — the body has no start to pin from"
    )
    assert source.find(_BODY_STARTS_AT, start + 1) < 0, (
        f"{_BODY_STARTS_AT!r} appears more than once — the body's start is ambiguous"
    )
    return source[start:]


def _body_sha256(source: str) -> str:
    return hashlib.sha256(_body(source).encode("utf-8")).hexdigest()


def test_the_vendored_body_is_byte_identical_to_forges():
    """The pin itself. Fails only when this copy's body differs from Forge's
    as measured; the docstring above the body may say anything."""
    assert _body_sha256(_TOOL.read_text(encoding="utf-8")) == _FORGE_BODY_SHA256, (
        _RESYNC
    )


def test_the_pin_catches_a_one_byte_change_and_ignores_the_docstring():
    """Planted: the real file with one byte of its body changed — `def main`
    becomes `def nain` — must hash differently, and the real body under a
    different docstring must hash the same. The first is the thing the pin is
    for; the second is the boundary that keeps a local docstring edit from
    reading as a vendor drift."""
    source = _TOOL.read_text(encoding="utf-8")
    body = _body(source)
    docstring = source[: len(source) - len(body)]

    at = body.index("def main()")
    flipped = body[: at + 4] + "n" + body[at + 5 :]
    assert flipped != body and len(flipped) == len(body)
    assert _body_sha256(docstring + flipped) != _FORGE_BODY_SHA256, (
        "a one-byte change to the body must move the hash"
    )

    assert (
        _body_sha256('"""A different local docstring."""\n' + body)
        == _FORGE_BODY_SHA256
    ), "the docstring is local; changing it must not read as vendor drift"
