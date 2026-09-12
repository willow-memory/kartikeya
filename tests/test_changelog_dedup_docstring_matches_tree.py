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

import pytest

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


def test_the_stale_claim_check_actually_catches_a_stale_docstring(tmp_path):
    """Planted: a module whose docstring is reverted to the old wording, read
    through the same `_module_docstring` the real check uses — so the parser
    is exercised, not just the substring. The first version of this test
    asserted the phrase against a string it had built, which proved the `in`
    and nothing about the helper that reads the real file. Proven against a
    synthetic module, not by editing the real file, so this guard test never
    itself goes stale."""
    stale = tmp_path / "changelog_dedup.py"
    stale.write_text(
        '"""Rebuild the newest CHANGELOG section from the commits.\n'
        "\n"
        "**IT HAS NOT HAPPENED HERE, AND CANNOT YET.** This repository has no\n"
        "CHANGELOG.md. It carries tags v0.0.3 through v0.0.9, but no\n"
        '`chore(master): release` commit exists anywhere in its history.\n"""\n'
        "from __future__ import annotations\n"
    )
    assert _STALE_CLAIM in _module_docstring(stale), "planted claim should trip the guard"

    bare = tmp_path / "no_docstring.py"
    bare.write_text("from __future__ import annotations\n")
    with pytest.raises(AssertionError):
        _module_docstring(bare)
