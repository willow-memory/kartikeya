"""Tests for cgroup_setup — kart.slice provisioning and parent detection."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import cgroup_setup  # noqa: E402


def _delegated_parent(tmp_path, name="slice", *, procs="", subtree="memory pids"):
    parent = tmp_path / name
    parent.mkdir()
    (parent / "cgroup.controllers").write_text("cpu memory pids")
    (parent / "cgroup.subtree_control").write_text(subtree)
    (parent / "cgroup.procs").write_text(procs)
    return parent


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


def test_systemd_cgroup_path_queries_control_group_property(monkeypatch):
    captured: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": "/user.slice/user-1000.slice/kart.slice\n",
                "stderr": "",
            },
        )()

    monkeypatch.setattr(cgroup_setup.subprocess, "run", fake_run)
    monkeypatch.setattr(cgroup_setup.os.path, "isdir", lambda _p: True)

    path = cgroup_setup.systemd_cgroup_path()
    assert path == "/sys/fs/cgroup/user.slice/user-1000.slice/kart.slice"
    assert captured == [
        [
            "systemctl",
            "--user",
            "show",
            "-p",
            "ControlGroup",
            "--value",
            "kart.slice",
        ]
    ]


def test_is_delegated_cgroup_parent_requires_subtree_control(tmp_path):
    parent = _delegated_parent(tmp_path, subtree="")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is False
    (parent / "cgroup.subtree_control").write_text("memory pids")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is True


def test_is_delegated_cgroup_parent_requires_empty_procs(tmp_path):
    parent = _delegated_parent(tmp_path, procs="123\n")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is False
    (parent / "cgroup.procs").write_text("")
    assert cgroup_setup.is_delegated_cgroup_parent(str(parent)) is True


def test_enable_subtree_control_writes_controllers(tmp_path):
    parent = _delegated_parent(tmp_path, subtree="")
    assert cgroup_setup.enable_subtree_control(str(parent)) is None
    assert cgroup_setup.subtree_control_enabled(str(parent)) is True


def test_setup_hint_names_subtree_not_systemd_when_slice_exists(tmp_path, monkeypatch):
    parent = _delegated_parent(tmp_path, subtree="")
    monkeypatch.setattr(cgroup_setup, "systemd_cgroup_path", lambda: str(parent))
    status = cgroup_setup.cgroup_status()
    hint = cgroup_setup._failure_hint(status, [])
    assert "subtree_control" in hint
    assert "systemd --user running" not in hint


def test_resolve_prefers_valid_env_over_systemd(tmp_path, monkeypatch):
    env_parent = _delegated_parent(tmp_path, "env")
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
