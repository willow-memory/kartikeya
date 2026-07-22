"""Tests for cgroup_setup — kart.slice provisioning and parent detection."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import cgroup_setup  # noqa: E402


def test_slice_unit_written_idempotently(tmp_path, monkeypatch):
    cfg = tmp_path / "systemd" / "user"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(
        cgroup_setup,
        "systemd_cgroup_path",
        lambda unit=cgroup_setup.KART_SLICE_UNIT: None,
    )

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["systemctl", "--user", "daemon-reload"]:
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if "start" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(cmd)

    monkeypatch.setattr(cgroup_setup.subprocess, "run", fake_run)

    first = cgroup_setup.setup_cgroup()
    second = cgroup_setup.setup_cgroup()
    assert first["changed"] is True
    assert second["changed"] is False
    assert (cfg / "kart.slice").exists()


def test_is_delegated_cgroup_parent_requires_empty_procs(tmp_path):
    parent = tmp_path / "slice"
    parent.mkdir()
    (parent / "cgroup.controllers").write_text("memory pids")
    (parent / "cgroup.procs").write_text("123\n")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is False
    (parent / "cgroup.procs").write_text("")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is True


def test_resolve_prefers_valid_env_over_systemd(tmp_path, monkeypatch):
    env_parent = tmp_path / "env"
    env_parent.mkdir()
    (env_parent / "cgroup.controllers").write_text("memory pids")
    (env_parent / "cgroup.procs").write_text("")
    monkeypatch.setenv("KART_CGROUP_PARENT", str(env_parent))
    monkeypatch.setattr(
        cgroup_setup,
        "systemd_cgroup_path",
        lambda: str(tmp_path / "other"),
    )
    assert cgroup_setup.resolve_cgroup_parent() == str(env_parent)


def test_cgroup_status_json_shape(monkeypatch):
    monkeypatch.delenv("KART_CGROUP_PARENT", raising=False)
    monkeypatch.setattr(cgroup_setup, "systemd_cgroup_path", lambda: None)
    status = cgroup_setup.cgroup_status()
    assert status["ready"] is False
    assert "slice_unit_path" in status
