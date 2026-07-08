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
