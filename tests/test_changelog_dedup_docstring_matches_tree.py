"""tools/changelog_dedup.py's docstring must describe *this* tree, not the one
that was true the day it was written.

Its status paragraph used to say "This repository has no CHANGELOG.md ... no
`chore(master): release` commit exists anywhere in its history" for over a
month after both became false: CHANGELOG.md was backfilled the same day the
file was written, and the first `chore(master): release` landed the next day.
A comment that goes stale is invisible until something reads it — this test
reads the actual docstring and checks its central factual claim against the
tree it describes, then plants a false claim to prove the check can actually
fail rather than passing by construction (a scan that has never fired has not
been shown to check anything).
"""
from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_TOOL = _REPO / "tools" / "changelog_dedup.py"

# The literal claim the stale docstring made, word for word. Matching on the
# exact phrase (not e.g. "no CHANGELOG.md" alone) keeps this from firing on
# unrelated prose elsewhere in the docstring that merely mentions the file.
_STALE_CLAIM = "This repository has no\nCHANGELOG.md"


def _module_docstring(path: Path) -> str:
    doc = ast.get_docstring(ast.parse(path.read_text()))
    assert doc, f"{path} has no module docstring to check"
    return doc


def test_the_docstring_no_longer_claims_the_tree_has_no_changelog():
    """The tree now has one (CHANGELOG.md, manifest at 0.2.4, real
    `chore(master): release` commits in `git log`) — the docstring must not
    still claim otherwise."""
    docstring = _module_docstring(_TOOL)
    assert _STALE_CLAIM not in docstring, (
        "tools/changelog_dedup.py's docstring still claims this repository has "
        "no CHANGELOG.md, but CHANGELOG.md exists in the tree"
    )
    assert (_REPO / "CHANGELOG.md").exists(), (
        "this test assumes CHANGELOG.md exists; if it was removed, the "
        "docstring's original claim would need reinstating instead"
    )


def test_the_stale_claim_check_actually_catches_a_stale_docstring():
    """Planted: a docstring reverted to the old wording would be caught by the
    assertion above. Proven against a synthetic snippet, not by editing the
    real file, so this guard test never itself goes stale."""
    stale_docstring = (
        "Rebuild the newest CHANGELOG section from the commits.\n\n"
        "**IT HAS NOT HAPPENED HERE, AND CANNOT YET.** This repository has no\n"
        "CHANGELOG.md. It carries tags v0.0.3 through v0.0.9, but no "
        "`chore(master): release` commit exists anywhere in its history."
    )
    assert _STALE_CLAIM in stale_docstring, "planted claim should trip the guard"
