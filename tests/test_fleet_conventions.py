"""G2-conventions-kartikeya — this tree is held to the fleet's published
conventions.

Fleet plan decision 4: every repo carries a `tests/test_fleet_conventions.py`
whose rules are READ from the published document, never restated. The document
is what `reconciler conventions --json` prints (willow-reconciler), schema
`willow-fleet-conventions/1`; each rule carries its own `sources` entry naming
the incident that made it a rule.

**How the document reaches this test: vendored and pinned, not imported.**
The reconciler's own consumer test does `from reconciler.conventions import
conventions`. Doing that here would make willow-reconciler a test dependency
of kartikeya: CI's install line (`pip install -e . pytest pyyaml`) would grow
a fleet tool, CONTRIBUTING would have to say so, and a reconciler release
that changed the document would turn this suite red with no commit here to
point at. This repo has no dev/test extra to hang it on either. So the
document is vendored as `tests/fleet_conventions.json` — the CLI's output,
byte for byte — and pinned by SHA-256, the same shape as the vendored
changelog tool's pin: a change to the vendored copy without a re-vendor is
what goes red, and a re-vendor is a commit that names the new source
version. When the reconciler *is* importable (a developer's environment, not
CI), the vendored copy is also compared to the live document, so drift
between the two is caught where someone can act on it.

**What the rules find here (measured 2026-09-12).** The hidden set and the
two reasoning comments match — the comments sit at the config file's root
rather than in its package block, which the rule's source ("in the config
file itself") allows and the reconciler's own consumer test happened not to
look for; auto-merge is armed and `pr-title.yml` is present. This repo kept no numbered
pile when this file was written, so the pile rule — a repo with a pile must
run `reconciler verify` via `trailers.yml` — was vacuous, and the test said
so and was written to trip the day a pile appeared. It did: `docs/ideas.md`
landed with E3-piles, `trailers.yml` with E3-trailers, and the test is now
the positive form. CONTRIBUTING.md did not exist; it does now, and names the
test command CI runs verbatim.

Five real-tree checks and five plants: one per real-tree helper the meta-scan
(`tests/test_scans_fire.py`) would otherwise report as never having fired,
plus the pin's own.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The published document, vendored: `reconciler conventions --json` from
#: willow-reconciler 0.6.0, captured 2026-09-12, saved exactly as printed
#: (two-space indent, trailing newline).
VENDORED = REPO_ROOT / "tests" / "fleet_conventions.json"
VENDORED_SOURCE = "willow-reconciler 0.6.0, `reconciler conventions --json`, 2026-09-12"
VENDORED_SHA256 = "8c2ba122a7100141200d8c76ad086339f984446ab7e90dd9c27a092dbf7f5335"
SCHEMA = "willow-fleet-conventions/1"

RULES = json.loads(VENDORED.read_text(encoding="utf-8"))

RELEASE_PLEASE = ".github/workflows/release-please.yml"
RELEASE_CONFIG = "release-please-config.json"
CONTRIBUTING = "CONTRIBUTING.md"
#: This repo's numbered pile, in the reconciler's form (E3-piles).
PILE = "docs/ideas.md"
ARMS_AUTOMERGE = "gh pr merge --auto"
#: The exact command CONTRIBUTING.md and `.github/workflows/tests.yml` name.
TEST_COMMAND = "python -m pytest tests/ -q"


# ── the document itself ──────────────────────────────────────────────────────


def test_the_vendored_document_is_the_one_measured():
    """The pin. A change to `tests/fleet_conventions.json` that is not a
    re-vendor from the reconciler goes red here; a re-vendor bumps the hash
    and names the new source version above."""
    digest = hashlib.sha256(VENDORED.read_bytes()).hexdigest()
    assert digest == VENDORED_SHA256, (
        f"tests/fleet_conventions.json is not the copy pinned from "
        f"{VENDORED_SOURCE}: re-vendor with `reconciler conventions --json > "
        f"tests/fleet_conventions.json` and update VENDORED_SHA256/VENDORED_SOURCE, "
        f"or restore the pinned copy"
    )
    assert RULES["schema"] == SCHEMA


def test_the_vendored_document_matches_the_live_reconciler_when_it_is_installed():
    """Optional, and honest about it: when willow-reconciler is importable the
    vendored copy must equal what it publishes now. CI does not install the
    reconciler (that coupling is the reason for vendoring), so this runs in a
    developer environment and skips elsewhere."""
    live = pytest.importorskip(
        "reconciler.conventions",
        reason="willow-reconciler is not installed; the vendored copy is pinned instead",
    )
    assert live.conventions() == RULES, (
        "the live reconciler publishes a different document than the vendored "
        "copy: re-vendor and bump the pin, naming the reconciler version"
    )


def test_the_pin_catches_a_planted_one_byte_change():
    """Planted: the vendored bytes with one byte changed must hash differently,
    and the pinned hash must be the hash of the file as saved — not of a
    re-serialisation, which would let a reformat pass as the same document."""
    data = VENDORED.read_bytes()
    flipped = data[:-2] + (b"#" if data[-2:-1] != b"#" else b"%") + data[-1:]
    assert flipped != data and len(flipped) == len(data)
    assert hashlib.sha256(flipped).hexdigest() != VENDORED_SHA256
    reserialised = json.dumps(RULES, indent=2).encode("utf-8")
    assert reserialised != data, "the saved copy carries the CLI's trailing newline"
    assert hashlib.sha256(reserialised).hexdigest() != VENDORED_SHA256


# ── the rules, read from the document and held against the tree ─────────────


def _arms_automerge(root: Path) -> bool:
    workflow = root / RELEASE_PLEASE
    return workflow.exists() and ARMS_AUTOMERGE in workflow.read_text(encoding="utf-8")


def _missing_when_armed(root: Path, required: list[str]) -> list[str]:
    if not _arms_automerge(root):
        return []
    return [f for f in required if not (root / f).exists()]


def _config_hidden_types(config_text: str) -> set[str]:
    sections = json.loads(config_text)["packages"]["."]["changelog-sections"]
    return {s["type"] for s in sections if s.get("hidden")}


def _config_visible_types(config_text: str) -> set[str]:
    sections = json.loads(config_text)["packages"]["."]["changelog-sections"]
    return {s["type"] for s in sections if not s.get("hidden")}


def _config_missing_comments(config_text: str, required: list[str]) -> list[str]:
    """The required `$comment-*` keys absent from the config file.

    The rule's own source says the reasoning lives "in the config file
    itself, beside the setting it explains". The reconciler's consumer test
    reads only the package block, because that is where its repo keeps them;
    this repo has kept all four of its `$comment-*` keys at the file's root,
    beside `$schema`, since the config was written (d47e4af), and
    release-please has cut every release since with them there. Both
    placements are in the file; either satisfies the rule. Absent from both
    is what this reports."""
    config = json.loads(config_text)
    package = config["packages"]["."]
    return [c for c in required if c not in config and c not in package]


def _missing_when_pile_exists(root: Path, required: list[str]) -> list[str]:
    if not (root / PILE).exists():
        return []
    return [f for f in required if not (root / f).exists()]


def _names_test_command(contributing_text: str) -> bool:
    return TEST_COMMAND in contributing_text


def test_pr_title_guard_is_present_wherever_automerge_is_armed():
    """willow-mcp v2.1.1: a `fix(ci):` title cut a release because the merge
    commit carried it and auto-merge took it. This repo arms auto-merge, so
    the guard the document names must be present."""
    assert _arms_automerge(REPO_ROOT), f"{RELEASE_PLEASE} no longer arms auto-merge"
    assert (
        _missing_when_armed(
            REPO_ROOT, RULES["required_when_release_please_arms_automerge"]
        )
        == []
    )


def test_the_configs_hidden_and_visible_sets_equal_the_published_sets():
    """jeles v0.4.1 shipped for a `ci:` commit; willow-mcp 2.1.5 for a
    `fix(ci):` touching nothing packaged. Both sets are read from the
    document, not restated here."""
    text = (REPO_ROOT / RELEASE_CONFIG).read_text(encoding="utf-8")
    assert _config_hidden_types(text) == set(RULES["hidden_types"])
    assert _config_visible_types(text) == set(RULES["release_cutting_types"])


def test_the_config_carries_every_required_reasoning_comment():
    """Decision 4: the reasoning lives beside the setting it explains."""
    text = (REPO_ROOT / RELEASE_CONFIG).read_text(encoding="utf-8")
    assert _config_missing_comments(text, RULES["required_config_comments"]) == []


def test_contributing_names_the_test_command():
    """'Receipts, not claims': a CONTRIBUTING that does not name the command
    leaves nothing for a PR to quote. The command named must be the one CI
    runs, so it is checked against the workflow too."""
    assert RULES["contributing_must_name_test_command"] is True
    contributing = REPO_ROOT / CONTRIBUTING
    assert contributing.exists(), (
        f"{CONTRIBUTING} is required by the fleet's conventions"
    )
    assert _names_test_command(contributing.read_text(encoding="utf-8"))
    workflow = (REPO_ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert _names_test_command(workflow), "CONTRIBUTING names a command CI does not run"


def test_trailers_workflow_is_present_because_a_pile_exists():
    """A repo with a numbered pile must run `reconciler verify` in CI
    (`trailers.yml`): rule 2a asserts LANDED from a trailer ahead of every
    other signal, so a dangling one must be caught where it is written.

    Until E3-piles this test was the vacuous form — it asserted that no pile
    existed, so that the day one appeared it would trip rather than pass on
    an empty list. It tripped as designed when `docs/ideas.md` landed, and is
    now the positive form the reconciler's own consumer test carries."""
    assert (REPO_ROOT / PILE).exists(), f"{PILE} is this repo's numbered pile"
    assert (
        _missing_when_pile_exists(REPO_ROOT, RULES["required_when_pile_exists"]) == []
    )


# ── the plants: every check above shown to fire ─────────────────────────────


def _tree(
    tmp_path: Path, label: str, *, arms: bool, files: tuple[str, ...] = ()
) -> Path:
    root = tmp_path / label
    (root / ".github" / "workflows").mkdir(parents=True)
    body = "jobs:\n  release-please:\n    steps:\n      - run: |\n"
    body += f'          {ARMS_AUTOMERGE} "$pr"\n' if arms else "          gh pr list\n"
    (root / RELEASE_PLEASE).write_text(body, encoding="utf-8")
    for f in files:
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        (root / f).write_text("# planted\n", encoding="utf-8")
    return root


def test_the_armed_tree_check_fires_on_a_planted_tree_missing_the_guard(tmp_path):
    required = RULES["required_when_release_please_arms_automerge"]
    assert _missing_when_armed(_tree(tmp_path, "bare", arms=True), required) == required
    assert (
        _missing_when_armed(
            _tree(tmp_path, "guarded", arms=True, files=tuple(required)), required
        )
        == []
    )
    assert _missing_when_armed(_tree(tmp_path, "manual", arms=False), required) == []


def test_the_hidden_set_check_catches_a_planted_config_that_unhides_ci():
    planted = json.dumps(
        {
            "packages": {
                ".": {
                    "changelog-sections": [
                        {"type": "feat", "section": "Added"},
                        {"type": "docs", "section": "Docs", "hidden": True},
                        {"type": "test", "section": "Tests", "hidden": True},
                        {"type": "ci", "section": "CI"},
                        {"type": "chore", "section": "Chores", "hidden": True},
                    ],
                    "$comment-what-cuts-a-release": "kept",
                }
            }
        }
    )
    assert _config_hidden_types(planted) == {"chore", "docs", "test"}
    assert _config_visible_types(planted) == {"feat", "ci"}
    assert _config_missing_comments(planted, RULES["required_config_comments"]) == [
        "$comment-hidden-rule"
    ]
    # Either placement is "in the config file itself"; neither is what fires.
    at_root = json.dumps(
        {
            "$comment-hidden-rule": "kept",
            "packages": {
                ".": {"changelog-sections": [], "$comment-what-cuts-a-release": "kept"}
            },
        }
    )
    assert _config_missing_comments(at_root, RULES["required_config_comments"]) == []
    nowhere = json.dumps({"packages": {".": {"changelog-sections": []}}})
    assert _config_missing_comments(
        nowhere, RULES["required_config_comments"]
    ) == sorted(RULES["required_config_comments"])


def test_the_pile_check_fires_on_a_planted_tree_with_a_pile_and_no_verify_gate(
    tmp_path,
):
    required = RULES["required_when_pile_exists"]
    with_pile = _tree(tmp_path, "pile", arms=False, files=(PILE,))
    assert _missing_when_pile_exists(with_pile, required) == required
    gated = _tree(tmp_path, "gated", arms=False, files=(PILE, *required))
    assert _missing_when_pile_exists(gated, required) == []
    assert (
        _missing_when_pile_exists(_tree(tmp_path, "no-pile", arms=False), required)
        == []
    )


def test_the_contributing_check_catches_a_planted_contributing_without_the_command():
    assert not _names_test_command("# Contributing\n\nRun the tests before pushing.\n")
    assert not _names_test_command("```sh\npytest\n```\n"), (
        "a different command is not the command"
    )
    assert _names_test_command(f"```sh\n{TEST_COMMAND}\n```\n")
