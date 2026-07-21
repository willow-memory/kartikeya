"""Tests for the decoupled sandbox seams.

Not the full bwrap execution suite (carried next) — these pin the parts the
decoupling touched: config resolution order, and the network-directive contract
that willow-mcp's B-21 strip depends on.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import sandbox  # noqa: E402


# ── repo root resolution (willow-mcp vs fleet) ───────────────────────────────

def test_willow_mcp_repo_detected_by_src_layout(tmp_path):
    mcp = tmp_path / "willow-mcp"
    (mcp / "src" / "willow_mcp").mkdir(parents=True)
    assert sandbox._is_willow_mcp_repo(mcp) is True
    assert sandbox._is_fleet_repo(mcp) is False


def test_fleet_repo_detected(tmp_path):
    fleet = tmp_path / "willow-2.0"
    (fleet / "core").mkdir(parents=True)
    (fleet / "core" / "kart_sandbox.py").write_text("# stub")
    assert sandbox._is_fleet_repo(fleet) is True


def test_willow_repo_root_prefers_willow_mcp_over_fleet(tmp_path, monkeypatch):
    fleet = tmp_path / "willow-2.0"
    mcp = tmp_path / "willow-mcp"
    (fleet / "core").mkdir(parents=True)
    (fleet / "core" / "kart_sandbox.py").write_text("# stub")
    (mcp / "src" / "willow_mcp").mkdir(parents=True)

    monkeypatch.delenv("WILLOW_ROOT", raising=False)
    monkeypatch.setenv("WILLOW_MCP_REPO", str(mcp))
    monkeypatch.setattr(sandbox, "_installed_willow_mcp_root", lambda: None)

    assert sandbox.willow_repo_root() == mcp.resolve()


def test_willow_repo_root_honors_explicit_willow_root(tmp_path, monkeypatch):
    mcp = tmp_path / "willow-mcp"
    fleet = tmp_path / "willow-2.0"
    (mcp / "src" / "willow_mcp").mkdir(parents=True)
    (fleet / "core").mkdir(parents=True)
    (fleet / "core" / "kart_sandbox.py").write_text("# stub")

    monkeypatch.setenv("WILLOW_ROOT", str(mcp))
    assert sandbox.willow_repo_root() == mcp.resolve()


def test_trust_overlay_skips_operator_alias_when_willow_home_set(tmp_path, monkeypatch):
    sandbox_home = tmp_path / "sandbox-home"
    (sandbox_home / "mcp_apps").mkdir(parents=True)
    operator = tmp_path / "operator-willow"
    (operator / "mcp_apps").mkdir(parents=True)

    monkeypatch.setenv("WILLOW_HOME", str(sandbox_home))
    monkeypatch.setattr("kartikeya.home.willow_home", lambda package_root=None: sandbox_home)
    monkeypatch.setattr("kartikeya.home.willow_home_alias", lambda: operator)

    overlays = sandbox.collect_mcp_trust_ro_overlays()
    assert overlays == [sandbox_home / "mcp_apps"]


def test_trust_overlay_includes_consent_policy_files(tmp_path, monkeypatch):
    home = tmp_path / "willow-home"
    (home / "mcp_apps").mkdir(parents=True)
    (home / "config").mkdir(parents=True)
    (home / "config" / "settings.global.json").write_text('{"consent": {"internet": false}}')
    (home / "config" / "consent.json").write_text('{"internet": false}')
    (home / "consent.json").write_text('{"internet": false}')

    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setattr("kartikeya.home.willow_home", lambda package_root=None: home)

    overlays = {p.resolve() for p in sandbox.collect_mcp_trust_ro_overlays()}
    assert {
        (home / "mcp_apps").resolve(),
        (home / "config" / "settings.global.json").resolve(),
        (home / "config" / "consent.json").resolve(),
        (home / "consent.json").resolve(),
    } <= overlays


# ── config resolution (spec §5) ────────────────────────────────────────────

def test_vendored_default_config_loads():
    cfg = sandbox.load_sandbox_config()
    # the product-neutral default always resolves and carries a mount policy
    assert cfg["env_prefixes"]
    assert "/usr" in cfg["bind_read_only"]
    # fleet-only prefixes are gone from the shipped default
    assert "GROVE_" not in cfg["env_prefixes"]
    assert "SAFE_" not in cfg["env_prefixes"]


def test_kart_sandbox_config_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom.json"
    custom.write_text('{"env_prefixes": ["CUSTOM_"], "bind_read_only": []}')
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(custom))
    cfg = sandbox.load_sandbox_config()
    assert cfg["env_prefixes"] == ["CUSTOM_"]


def test_config_falls_back_to_default_when_override_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(tmp_path / "does-not-exist.json"))
    cfg = sandbox.load_sandbox_config()
    assert cfg["env_prefixes"]  # never empty — falls through to vendored default


# ── B-21 contract: the worker's network-directive matching (spec §4) ───────

def test_task_allows_network_exact_line_match():
    assert sandbox.task_allows_network("echo hi\n# allow_net") is True
    assert sandbox.task_allows_network("  # allow_net  \necho hi") is True


def test_task_allows_network_rejects_non_directive_forms():
    # willow-mcp's strip (B-21) keys on `line.strip() == "# allow_net"`; anything
    # else must NOT enable egress, or the strip and the worker disagree.
    assert sandbox.task_allows_network("echo hi") is False
    assert sandbox.task_allows_network("#allow_net") is False          # no space
    assert sandbox.task_allows_network("echo # allow_net") is False    # not its own line
    assert sandbox.task_allows_network("# allow_net now") is False     # trailing text


def test_task_allows_localhost_exact_line_match():
    assert sandbox.task_allows_localhost("echo hi\n# allow_localhost") is True
    assert sandbox.task_allows_localhost("echo hi") is False


def test_parse_task_network_strips_directives():
    body, net, local = sandbox.parse_task_network("curl x\n# allow_net")
    assert net is True
    assert "# allow_net" not in body
    assert body.strip() == "curl x"


def test_bwrap_available_returns_bool():
    assert isinstance(sandbox.bwrap_available(), bool)


# ── resource caps: memory + PID limits (live-audit L-DOS-02 residual) ───────

@pytest.mark.parametrize("text,expected", [
    ("2G", 2 * 1024 ** 3), ("512M", 512 * 1024 ** 2), ("1024", 1024),
    ("1.5G", int(1.5 * 1024 ** 3)), ("", None), ("garbage", None),
])
def test_parse_size(text, expected):
    assert sandbox._parse_size(text) == expected


def test_resource_limits_default_and_off_switch(monkeypatch):
    monkeypatch.delenv("KART_MEM_MAX", raising=False)
    monkeypatch.delenv("KART_PIDS_MAX", raising=False)
    monkeypatch.delenv("WILLOW_KART_NO_RLIMIT", raising=False)
    lim = sandbox._resource_limits()
    assert lim["mem"] == 2 * 1024 ** 3 and lim["pids"] == 512
    monkeypatch.setenv("WILLOW_KART_NO_RLIMIT", "1")
    assert sandbox._resource_limits() is None


def test_resource_limits_env_overrides(monkeypatch):
    monkeypatch.setenv("KART_MEM_MAX", "256M")
    monkeypatch.setenv("KART_PIDS_MAX", "64")
    lim = sandbox._resource_limits()
    assert lim["mem"] == 256 * 1024 ** 2 and lim["pids"] == 64


def test_limits_context_falls_back_to_rlimit_without_delegated_cgroup(monkeypatch):
    # No KART_CGROUP_PARENT → the cgroup path is unavailable, so we get rlimits.
    monkeypatch.delenv("KART_CGROUP_PARENT", raising=False)
    preexec, cleanup, mode = sandbox._limits_context({"mem": 256 * 1024 ** 2, "pids": 64})
    assert mode == "rlimit"
    assert callable(preexec) and cleanup is None


@pytest.mark.skipif(sandbox._resource is None, reason="POSIX rlimits unavailable")
def test_rlimit_actually_contains_a_memory_hog(monkeypatch):
    # End-to-end: with a low address-space cap, a task that allocates past it must
    # fail rather than eat host memory; a small task under the cap runs fine.
    # Plain mode (no bwrap) isolates the rlimit mechanism from sandbox bring-up.
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.setenv("KART_MEM_MAX", "512M")
    monkeypatch.delenv("KART_CGROUP_PARENT", raising=False)

    hog = sandbox.run_shell(
        "python3 -c 'x = bytearray(900*1024*1024); print(len(x))'", timeout=30)
    assert hog["returncode"] != 0, hog
    assert hog.get("resource_limit") == "rlimit"

    ok = sandbox.run_shell("echo under_the_cap", timeout=30)
    assert ok["returncode"] == 0 and "under_the_cap" in ok["stdout"]
    assert ok.get("resource_limit") == "rlimit"
