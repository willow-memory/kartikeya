"""env_deny and the XDG_RUNTIME_DIR residual.

The allow list is by prefix, so a variable naming a file that is deliberately
NOT mounted rides into every task by accident. WILLOW_KEYRING is the measured
case (willow-mcp gaps 8a236e0e8f55, 4e1825878677, 4ef8dff33722). And a
variable that names a path only present when a bind supplies it must not be
emitted when the bind is gone (willow-mcp env-fs.write-3ea8d27806c2 removed
/run/user and {{XDG_RUNTIME_DIR}} from an operator's bind_try, leaving
XDG_RUNTIME_DIR pointing at nothing).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kartikeya import sandbox


def _vendored() -> dict:
    return json.loads(
        (Path(sandbox.__file__).parent / "data" / "kart-sandbox.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture
def vendored_default(monkeypatch):
    """Resolve to the shipped default, not this host's policy (same isolation
    test_sandbox.py's fixture of the same name provides)."""
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.delenv("WILLOW_HOME", raising=False)


@pytest.fixture
def custom_config(tmp_path, monkeypatch):
    """Write a config derived from the vendored default and point Kart at it."""
    monkeypatch.delenv("WILLOW_HOME", raising=False)

    def _make(**overrides):
        cfg = _vendored()
        cfg.update(overrides)
        path = tmp_path / "kart-sandbox.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        monkeypatch.setenv("KART_SANDBOX_CONFIG", str(path))
        return cfg

    return _make


def test_default_deny_strips_the_keyring_but_not_its_siblings(
    monkeypatch, vendored_default
):
    monkeypatch.setenv("WILLOW_KEYRING", "/box/config/verifiers.json")
    monkeypatch.setenv("WILLOW_HANDOFF_PROJECT", "github")
    env = sandbox.kart_env()
    assert "WILLOW_KEYRING" not in env, "keyring path reached the task by prefix"
    assert env["WILLOW_HANDOFF_PROJECT"] == "github"


def test_vendored_default_declares_the_deny():
    assert _vendored()["env_deny"] == ["WILLOW_KEYRING"]
    assert "env_deny" in _vendored()["_security_notes"]


def test_config_deny_list_is_honoured(monkeypatch, custom_config):
    custom_config(env_deny=["WILLOW_SECRET_THING"])
    monkeypatch.setenv("WILLOW_SECRET_THING", "x")
    monkeypatch.setenv("WILLOW_KEYRING", "/box/config/verifiers.json")
    env = sandbox.kart_env()
    assert "WILLOW_SECRET_THING" not in env
    # An explicit list replaces the default rather than extending it: the
    # operator's file is the policy.
    assert env["WILLOW_KEYRING"] == "/box/config/verifiers.json"


def test_deny_applies_after_the_fleet_env_file(monkeypatch, custom_config, tmp_path):
    """A denied name sourced from $WILLOW_HOME/env, not the shell, is still dropped."""
    custom_config()
    home = tmp_path / "box"
    home.mkdir()
    (home / "env").write_text(
        'WILLOW_KEYRING="/box/config/verifiers.json"\n', encoding="utf-8"
    )
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    env = sandbox.kart_env()
    assert "WILLOW_KEYRING" not in env


def test_xdg_runtime_dir_dropped_when_no_bind_makes_it_reachable(
    monkeypatch, custom_config, tmp_path
):
    runtime = tmp_path / "run" / "user" / "1000"
    runtime.mkdir(parents=True)
    cfg = _vendored()
    for key in ("bind_try", "bind_try_read_only", "bind_read_only", "bind_read_write"):
        cfg[key] = [
            p for p in cfg.get(key, []) if "run/user" not in p and "XDG" not in p
        ]
    custom_config(
        **{
            k: cfg[k]
            for k in (
                "bind_try",
                "bind_try_read_only",
                "bind_read_only",
                "bind_read_write",
            )
        }
    )
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    env = sandbox.kart_env()
    assert "XDG_RUNTIME_DIR" not in env


def test_xdg_runtime_dir_kept_when_a_bind_reaches_it(
    monkeypatch, custom_config, tmp_path
):
    runtime = tmp_path / "run" / "user" / "1000"
    runtime.mkdir(parents=True)
    custom_config(bind_try=["{{XDG_RUNTIME_DIR}}"])
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    env = sandbox.kart_env()
    assert env["XDG_RUNTIME_DIR"] == str(runtime)
