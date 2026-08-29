"""The release chain is three files that must agree, and every disagreement is silent.

    release-please-config.json     decides the tag name and what cuts a release
    .release-please-manifest.json  is the version it bumps from
    .github/workflows/release.yml  fires on a tag pattern and publishes

Nothing joins them up at runtime. A mismatch does not raise — it means a release
quietly does not happen, and this repo already has the scar: **v0.0.8 is tagged
but has never existed on PyPI.** The tag was cut on a commit whose version was
still 0.0.7, the build produced 0.0.7, and the only thing that noticed was PyPI
refusing a duplicate upload.

Ported from willow-mcp, where a config mistake would have tagged
`willow-mcp-v2.2.0` while the publish workflow listened for `v*`. Three checks
there do not apply here and are deliberately absent rather than copied:
kartikeya has no second version file to keep in step and no aggregate CI job to
name.
"""
from __future__ import annotations

import fnmatch
import json
import re
import tomllib  # stdlib from 3.11; this package requires >=3.11
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML needed to read the workflows")

_REPO = Path(__file__).resolve().parents[1]
_CONFIG = _REPO / "release-please-config.json"
_MANIFEST = _REPO / ".release-please-manifest.json"
_RELEASE_WF = _REPO / ".github" / "workflows" / "release.yml"
_RP_WF = _REPO / ".github" / "workflows" / "release-please.yml"


def _json(p: Path) -> dict:
    return json.loads(p.read_text())


def _yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text())


def _package_config() -> dict:
    return _json(_CONFIG)["packages"]["."]


def test_the_tag_release_please_creates_matches_what_release_yml_listens_for():
    """With `include-component-in-tag` unset it defaults to *true* and the tag
    becomes `kartikeya-vX.Y.Z`, which `v*` does not match — so the tag is created
    and nothing publishes, with no error anywhere. Observed on willow-mcp#256."""
    cfg = _package_config()
    version = _json(_MANIFEST)["."]
    tag = (f"{cfg['package-name']}-v{version}"
           if cfg.get("include-component-in-tag", True) else f"v{version}")

    # `on:` parses as the boolean True — PyYAML applies the YAML 1.1 rule.
    patterns = list(_yaml(_RELEASE_WF)[True]["push"]["tags"])
    assert any(fnmatch.fnmatch(tag, p) for p in patterns), (
        f"release-please would create the tag {tag!r}, which matches none of "
        f"release.yml's trigger patterns {patterns!r}. Nothing would publish, "
        f"and nothing would report an error."
    )


def test_the_version_has_exactly_one_source():
    """v0.0.8's direct cause: pyproject carried a hardcoded version that the tag
    disagreed with. It is `dynamic` now, and this keeps it that way — a literal
    here is a second copy, and a second copy is what drifts."""
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text())
    assert "version" in (pyproject["project"].get("dynamic") or [])
    assert "version" not in pyproject["project"], \
        "a literal project.version is exactly what broke v0.0.8"
    assert pyproject["tool"]["hatch"]["version"]["source"] == "vcs"
    assert not _package_config().get("extra-files"), \
        "nothing in this repo stores a version, so nothing needs bumping"


# A credential whose events actually trigger workflows. Either form is
# acceptable; what is NOT acceptable is GITHUB_TOKEN, whose events GitHub
# suppresses — the release PR merges, no tag workflow fires, nothing publishes.
#
# Originally this pinned the literal RELEASE_PLEASE_TOKEN, which named the
# mechanism rather than the property. The willow-ci GitHub App satisfies the
# same property (an installation token is not GITHUB_TOKEN) and adds hourly
# expiry, so the assertion now accepts either and the prohibition below is
# unchanged. Widening this to accept GITHUB_TOKEN would give back the three
# releases jeles lost.
NON_SUPPRESSED_CREDENTIALS = (
    "RELEASE_PLEASE_TOKEN",              # fine-grained PAT (being retired)
    "steps.app-token.outputs.token",     # willow-ci App installation token
)


def _names_a_non_suppressed_credential(value: object) -> bool:
    text = str(value)
    return any(c in text for c in NON_SUPPRESSED_CREDENTIALS)


def test_release_automation_uses_a_non_suppressed_credential_everywhere():
    """A bot token silently produces no workflow runs: the release PR merges, no
    tag workflow fires, nothing publishes. jeles lost three releases to it."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    used: set[str] = set()
    values: list[str] = []
    for step in steps:
        for value in list((step.get("env") or {}).values()) + \
                     list((step.get("with") or {}).values()):
            values.append(str(value))
            used.update(re.findall(r"secrets\.([A-Z_]+)", str(value)))
    assert any(_names_a_non_suppressed_credential(v) for v in values), \
        f"no non-suppressed credential anywhere in the job; secrets seen: {used}"
    assert "GITHUB_TOKEN" not in used, \
        f"GITHUB_TOKEN's events do not trigger workflows; found {used}"


def test_auto_merge_waits_for_ci_rather_than_merging_directly():
    """`--auto` is what makes the merge wait for the required checks. Falling
    back to a plain merge would publish off an unverified commit."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    arming = [s for s in steps if "gh pr merge" in str(s.get("run", ""))]
    assert arming, "no step arms auto-merge on the release PR"
    for step in arming:
        for line in step["run"].splitlines():
            if "gh pr merge" in line and not line.strip().startswith("#"):
                assert "--auto" in line, f"merge without --auto: {line.strip()}"
                assert "--squash" not in line


def test_the_changelog_is_rebuilt_before_auto_merge_is_armed():
    """Order is the point: the correction must land on the release PR *before*
    auto-merge can take it, or the release ships wrong and is fixed afterwards.

    **Not yet exercised here.** This repo has no CHANGELOG.md and no
    `chore(master): release` commit in its history, so release-please has never
    cut a release and the tool no-ops. The wiring is asserted; the correction is
    not, because there is nothing here to correct yet."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    names = [s.get("name") or str(s.get("uses", "")) for s in steps]

    def index_of(needle: str) -> int:
        hits = [i for i, n in enumerate(names) if needle in n]
        assert hits, f"no step matching {needle!r} in {names}"
        return hits[0]

    assert (index_of("actions/checkout") < index_of("release-please-action")
            < index_of("Rebuild the changelog") < index_of("Arm auto-merge")), names

    checkout = next(s for s in steps
                    if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0, "needs full history for the range"
    assert checkout["with"]["fetch-tags"] is True, "needs tags to find the previous release"


def test_a_changelog_bail_does_not_block_the_release():
    """The bug willow-mcp shipped, carried here as a guard rather than repeated.
    Under `set -e`, exit 2 — the tool refusing a section it cannot model —
    skipped the auto-merge arming and stopped the release entirely. Trading a
    wrong changelog for no release at all is a bad deal."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    step = next(s for s in steps if "Rebuild the changelog" in (s.get("name") or ""))
    assert "::warning::" in step["run"], "a bail must warn"
    assert 'status" = "2"' in step["run"], "exit 2 must be handled, not left to set -e"
    assert _names_a_non_suppressed_credential(step.get("env"))
    assert "GITHUB_TOKEN" not in str(step.get("env"))
    assert (_REPO / "tools" / "changelog_dedup.py").exists(), \
        "the workflow calls a script this repo does not ship"


def test_the_pr_title_check_guards_both_directions():
    """One direction stops a title inventing a release; the other stops a commit
    releasing something nobody installs. willow-mcp shipped 2.1.5 that way and
    jeles published v0.4.1 for a single `ci:` commit.

    The packaged path is the one thing in that workflow that must NOT be shared
    between repos — willow-mcp uses `src/willow_mcp/`, jeles a top-level
    `jeles/`. Read the *assigned value* out of the AST rather than searching the
    text: the comments there name the other repos' paths deliberately, and a
    substring check would flag its own explanation."""
    import ast

    wf = _REPO / ".github" / "workflows" / "pr-title.yml"
    body = _yaml(wf)["jobs"]["title"]["steps"][-1]["run"].split("<<'PY'")[1].rsplit("PY", 1)[0]
    tree = ast.parse(body)
    packaged = next(ast.literal_eval(n.value) for n in ast.walk(tree)
                    if isinstance(n, ast.Assign)
                    and getattr(n.targets[0], "id", "") == "PACKAGED")

    assert packaged == ("src/kartikeya/", "pyproject.toml"), packaged
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text())
    wheel = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert wheel == ["src/kartikeya"], \
        f"packaged path disagrees with what the wheel ships: {wheel}"


def test_the_release_body_is_synced_after_the_release_is_created():
    """release-please writes the GitHub Release body from its own parse, not
    from CHANGELOG.md, so fixing the file leaves the release *page* wrong.
    willow-mcp's v2.1.4 page and jeles' v0.5.0 page both kept their duplicate
    after the file had been corrected.

    Like the changelog step, this has never run here — there is no CHANGELOG.md
    to publish from. The wiring is what is asserted."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    names = [s.get("name") or str(s.get("uses", "")) for s in steps]

    def index_of(needle: str) -> int:
        hits = [i for i, n in enumerate(names) if needle in n]
        assert hits, f"no step matching {needle!r} in {names}"
        return hits[0]

    assert (index_of("release-please-action") < index_of("Make the GitHub Release body")
            < index_of("Arm auto-merge")), names

    step = steps[index_of("Make the GitHub Release body")]
    run = step["run"]
    assert "--print-section" in run
    assert "gh release edit" in run
    assert "$GITHUB_SHA" in run, "must not depend on which branch the previous step left"
    assert "rstrip()" in run, "comparison must ignore trailing whitespace"
    assert _names_a_non_suppressed_credential(step.get("env"))
    assert "GITHUB_TOKEN" not in str(step.get("env"))


def test_print_section_refuses_when_there_is_no_changelog():
    """The ordering trap this repo uniquely has. `--print-section`'s stdout
    becomes a GitHub Release body, so falling through the "no CHANGELOG.md yet —
    nothing to rebuild" early return would publish that sentence as the release
    notes. It must exit non-zero instead, and the workflow then warns and leaves
    the release alone."""
    import subprocess
    import sys

    tool = _REPO / "tools" / "changelog_dedup.py"
    if (_REPO / "CHANGELOG.md").exists():
        pytest.skip("a changelog exists now — this guards the no-changelog state")
    r = subprocess.run([sys.executable, str(tool), "--print-section", "0.0.9"],
                       capture_output=True, text=True, cwd=str(_REPO))
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.strip() == "", f"printed something usable as a body: {r.stdout!r}"


def test_print_section_refuses_while_only_hand_written_history_exists():
    """The live successor to the no-CHANGELOG guard, and the same hazard.

    CHANGELOG.md now exists but contains only the hand-written v0.0.1-v0.0.9
    history, backfilled because those tags predate release-please. Those
    sections deliberately carry no `(…/compare/…)` link, which is how the tool
    tells generated sections from written ones.

    `--print-section`'s stdout becomes a GitHub Release body, so this must exit
    non-zero with an empty stdout rather than printing an explanatory sentence
    that would be published as release notes."""
    import subprocess
    import sys

    changelog = _REPO / "CHANGELOG.md"
    if not changelog.exists():
        pytest.skip("no changelog — the earlier guard covers that state")
    generated = [ln for ln in changelog.read_text().splitlines()
                 if ln.startswith("## [")]
    if generated:
        pytest.skip("release-please has written a section — this guard is spent")

    r = subprocess.run([sys.executable, str(_REPO / "tools" / "changelog_dedup.py"),
                        "--print-section", "0.0.9"],
                       capture_output=True, text=True, cwd=str(_REPO))
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.strip() == "", f"printed something publishable: {r.stdout!r}"


def test_a_rebuild_leaves_the_hand_written_history_alone():
    """The claim the changelog header makes about this tool, checked rather than
    asserted: with no generated section present there is nothing to rebuild, and
    that is a clean no-op — not an error, and not a rewrite of the history."""
    import subprocess
    import sys

    changelog = _REPO / "CHANGELOG.md"
    if not changelog.exists() or [ln for ln in changelog.read_text().splitlines()
                                  if ln.startswith("## [")]:
        pytest.skip("only meaningful while the file is hand-written history alone")

    before = changelog.read_text()
    r = subprocess.run([sys.executable, str(_REPO / "tools" / "changelog_dedup.py")],
                       capture_output=True, text=True, cwd=str(_REPO))
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert changelog.read_text() == before, "the hand-written history was modified"


def test_only_types_that_change_the_installed_package_cut_a_release():
    """Every un-hidden type releases on its own. jeles shipped v0.4.1 to PyPI
    for a `ci:` commit touching a workflow file — survivable when a human merges
    the release PR, not once auto-merge does."""
    sections = _package_config()["changelog-sections"]
    visible = {s["type"] for s in sections if not s.get("hidden")}
    assert visible == {"feat", "fix", "security", "perf", "refactor",
                       "build", "deps"}, visible
    for t in ("docs", "test", "ci", "chore"):
        assert next(s for s in sections if s["type"] == t).get("hidden") is True


def test_a_breaking_change_below_1_0_cuts_1_0_0_rather_than_a_minor():
    """`bump-minor-pre-major` was true here and is now false — a policy change,
    so this test flipped with it.

    True kept a breaking change at a minor, so that reaching 1.0 stayed a
    decision someone makes. Dependents paid for it: a `<1.0.0` cap accepted
    every version this config could produce and therefore promised nothing.
    willow-mcp tried `kartikeya>=0.0.9,<0.1.0` to close that downstream and
    withdrew it — that cap would have expired on the very next `feat:`, which
    this config already documents as taking 0.0.9 to 0.1.0.

    The visible consequence: `feat:` still goes 0.0.9 -> 0.1.0, and a breaking
    change goes straight to 1.0.0. That jump is the point — the number then says
    what happened.
    """
    cfg = _package_config()
    assert cfg.get("bump-minor-pre-major") is False, (
        "true caps a breaking change at a minor, which makes a downstream "
        "`<1.0.0` cap meaningless. See willow-mcp docs/design/fleet-versioning.md")
    assert cfg.get("bump-patch-for-minor-pre-major") is False, \
        "with this true, a feat would bump the patch instead of the minor"
    assert _json(_MANIFEST)["."].startswith("0."), \
        "past 1.0 both flags are dead weight — `isPreMajor` gates them. Remove."


def test_the_publish_job_uses_oidc_with_attestations():
    """Trusted Publishing (OIDC) with PEP 740 attestations enabled. No stored
    token, and attestations default to true — an explicit `false` or a leftover
    `password:` means the migration is incomplete."""
    job = _yaml(_RELEASE_WF)["jobs"]["publish"]
    perms = job.get("permissions") or {}
    assert perms.get("id-token") == "write", (
        "the publish job must request id-token: write for Trusted Publishing")
    publish = job["steps"]
    step = next(s for s in publish if "pypi-publish" in str(s.get("uses", "")))
    with_ = step.get("with") or {}
    assert "password" not in with_, (
        "a stored token is not needed with Trusted Publishing — drop the "
        "password line")
    assert with_.get("attestations") is not False, (
        "attestations are available with OIDC — do not disable them")


def test_the_checkout_uses_a_non_suppressed_credential_so_pushes_are_not_gated():
    """`actions/checkout` persists whatever credential it used, and the changelog
    step's `git push` then uses it. `env: GH_TOKEN` only reaches the `gh` CLI.

    With the default GITHUB_TOKEN the commit is pushed as github-actions[bot],
    and the release PR's CI run comes back `action_required` — created, but held
    awaiting manual approval — so auto-merge waits on a check that never
    reports. Observed on the 2.2.0 release PR, which needed CI started by hand;
    release-please's own commit on the same branch was not gated, because it
    pushes with the PAT.

    This is the fourth way this fleet has been bitten by token attribution, so
    it gets a test rather than a comment."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    checkout = next(s for s in steps
                    if str(s.get("uses", "")).startswith("actions/checkout"))
    token = str((checkout.get("with") or {}).get("token", ""))
    assert _names_a_non_suppressed_credential(token), (
        "checkout must carry a credential whose events trigger workflows — its "
        "credential is what the changelog step pushes with. "
        f"Got: {token!r}")
    assert "GITHUB_TOKEN" not in token
