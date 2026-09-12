"""The README must not name a version number it cannot keep current.

README.md used to say kartikeya was "released on PyPI as `kartikeya` (0.0.9)"
and that willow-mcp "floors it at `>=0.0.9,<1.0.0`" long after the manifest had
moved to 0.2.4 and willow-mcp's own floor had moved to `>=0.0.12,<1.0.0` — a
typed number that drifted the moment either project tagged again. The fix was
to stop naming a number in that sentence at all (the version on PyPI is
whatever `.release-please-manifest.json` says; willow-mcp's floor lives in its
own `pyproject.toml`), rather than replace one stale digit with another that
will just as surely go stale.

This test is the guard against that regressing: it reads the "released ...
as `kartikeya`" sentence and refuses any `x.y.z` version literal there, then
plants one to prove the check actually fires rather than passing by
construction.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_README = _REPO / "README.md"

# Matches the sentence this repo's README uses to describe its own PyPI
# release, wherever it falls in the file.
_RELEASED_SENTENCE_RE = re.compile(
    r"released on\s+PyPI as `kartikeya`.*?\.(?=\s|$)", re.DOTALL
)
_VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+\b")


def _released_sentence(text: str) -> str:
    m = _RELEASED_SENTENCE_RE.search(text)
    assert m, "README no longer has a 'released on PyPI as `kartikeya`' sentence to check"
    return m.group(0)


def test_the_released_sentence_names_no_version_number():
    """A version literal here is exactly the thing that goes stale — see the
    module docstring. The sentence should point at the manifest instead of
    quoting a copy of its content."""
    sentence = _released_sentence(_README.read_text())
    assert not _VERSION_RE.search(sentence), (
        f"README's PyPI sentence names a version number that will drift: {sentence!r}"
    )


def test_the_check_actually_catches_a_stale_version_literal():
    """Planted: a README that regressed to naming a number would be caught by
    the assertion above. Proven here against a synthetic stale sentence rather
    than by editing the real file, so this test never itself goes stale."""
    stale = "tested, and released on PyPI as `kartikeya` (0.0.9) — `pip install kartikeya`."
    sentence = _released_sentence(stale)
    assert _VERSION_RE.search(sentence), "the planted sentence should have tripped the guard"
