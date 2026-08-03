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
kartikeya has no second version file to keep in step, no aggregate CI job to
name, and no OIDC publisher — it publishes with an API token, which is the one
place this repo still diverges from the rest of the fleet.
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


def test_release_automation_uses_the_pat_everywhere():
    """A bot token silently produces no workflow runs: the release PR merges, no
    tag workflow fires, nothing publishes. jeles lost three releases to it."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    used: set[str] = set()
    for step in steps:
        for value in list((step.get("env") or {}).values()) + \
                     list((step.get("with") or {}).values()):
            used.update(re.findall(r"secrets\.([A-Z_]+)", str(value)))
    assert "RELEASE_PLEASE_TOKEN" in used, used
    assert "GITHUB_TOKEN" not in used, f"must use the PAT; found {used}"


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


def test_below_1_0_so_it_keeps_the_pre_major_flags():
    """Inverted from willow-mcp, which must NOT have these (2.x needs to reach
    3.0.0). Here they are right, and the visible consequence is that the next
    `feat:` goes 0.0.9 -> 0.1.0 rather than 0.0.10."""
    cfg = _package_config()
    assert cfg.get("bump-minor-pre-major") is True
    assert cfg.get("bump-patch-for-minor-pre-major") is False, \
        "with this true, a fix would bump the minor instead of the patch"
    assert _json(_MANIFEST)["."].startswith("0."), \
        "at 1.0 these flags stop being correct and should be removed"


def test_the_publish_step_is_honest_about_not_having_attestations():
    """This repo publishes with an API token, so PEP 740 attestations are not
    available and the workflow says `attestations: false`. If it ever moves to
    OIDC that line must go, or provenance is silently switched off on a setup
    that could have had it. This is the one place the fleet still diverges."""
    publish = _yaml(_RELEASE_WF)["jobs"]["publish"]["steps"]
    step = next(s for s in publish if "pypi-publish" in str(s.get("uses", "")))
    with_ = step.get("with") or {}
    token_auth = "password" in with_
    assert token_auth == (with_.get("attestations") is False), (
        "token auth and `attestations: false` go together; OIDC and attestations "
        "go together. Found password=%r attestations=%r"
        % ("password" in with_, with_.get("attestations"))
    )
