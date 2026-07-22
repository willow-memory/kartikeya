"""Delegated cgroup parent provisioning for Kart resource caps (greenfield path)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

KART_SLICE_UNIT = "kart.slice"
# systemd honors Delegate= only on service/scope units, not slices — children need
# memory+pids enabled via cgroup.subtree_control after the slice is started.
SYSTEMD_CGROUP_PROPERTY = "ControlGroup"
_REQUIRED_CONTROLLERS = frozenset({"memory", "pids"})

SLICE_UNIT_CONTENT = """[Unit]
Description=Kart sandbox resource caps (delegated cgroup parent)

[Slice]
Delegate=memory pids
"""


def _user_config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user"


def slice_unit_path() -> Path:
    return _user_config_dir() / KART_SLICE_UNIT


def _read_space_file(path: str, name: str) -> set[str]:
    with open(os.path.join(path, name)) as f:
        return {part.lstrip("+") for part in f.read().split() if part}


def controllers_available(path: str) -> bool:
    """True when memory+pids appear in cgroup.controllers (available to enable)."""
    try:
        return _REQUIRED_CONTROLLERS <= _read_space_file(path, "cgroup.controllers")
    except OSError:
        return False


def subtree_control_enabled(path: str) -> bool:
    """True when memory+pids are enabled for child cgroups (subtree_control)."""
    try:
        return _REQUIRED_CONTROLLERS <= _read_space_file(path, "cgroup.subtree_control")
    except OSError:
        return False


def is_delegated_cgroup_parent(path: str) -> bool:
    """True when ``path`` is an empty cgroup with memory+pids delegated to children."""
    if not path or not os.path.isdir(path):
        return False
    try:
        if not controllers_available(path):
            return False
        if not subtree_control_enabled(path):
            return False
        with open(os.path.join(path, "cgroup.procs")) as f:
            return f.read().strip() == ""
    except OSError:
        return False


def _cgroup_fs_path(systemd_path: str) -> str | None:
    rel = (systemd_path or "").strip()
    if not rel or rel == "-":
        return None
    if rel.startswith("/sys/fs/cgroup"):
        return rel if os.path.isdir(rel) else None
    candidate = os.path.join("/sys/fs/cgroup", rel.lstrip("/"))
    return candidate if os.path.isdir(candidate) else None


def systemd_cgroup_path(unit: str = KART_SLICE_UNIT) -> str | None:
    """Resolve the cgroup filesystem path for a user systemd unit."""
    try:
        proc = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                "-p",
                SYSTEMD_CGROUP_PROPERTY,
                "--value",
                unit,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return _cgroup_fs_path(proc.stdout)


def enable_subtree_control(parent: str) -> str | None:
    """Write +memory +pids into parent cgroup.subtree_control. Return error or None."""
    try:
        with open(os.path.join(parent, "cgroup.subtree_control"), "w") as f:
            f.write("+memory +pids")
    except OSError as exc:
        return f"cannot write cgroup.subtree_control: {exc}"
    if not subtree_control_enabled(parent):
        return "memory+pids not enabled in cgroup.subtree_control after write"
    return None


def resolve_cgroup_parent() -> str | None:
    """Best delegated parent: explicit env, else auto-detected kart.slice."""
    explicit = os.environ.get("KART_CGROUP_PARENT", "").strip()
    if explicit and is_delegated_cgroup_parent(explicit):
        return explicit
    auto = systemd_cgroup_path()
    if auto and is_delegated_cgroup_parent(auto):
        return auto
    return None


def cgroup_status() -> dict:
    explicit = os.environ.get("KART_CGROUP_PARENT", "").strip()
    auto = systemd_cgroup_path()
    resolved = resolve_cgroup_parent()
    return {
        "ready": resolved is not None,
        "resolved_parent": resolved,
        "env_parent": explicit or None,
        "systemd_parent": auto,
        "env_valid": bool(explicit and is_delegated_cgroup_parent(explicit)),
        "systemd_valid": bool(auto and is_delegated_cgroup_parent(auto)),
        "slice_unit": KART_SLICE_UNIT,
        "slice_unit_path": str(slice_unit_path()),
    }


def _worker_env_hint(parent: str) -> str:
    return (
        f"For the systemd kart worker: systemctl --user set-environment "
        f"KART_CGROUP_PARENT={parent} && systemctl --user restart <kart-worker> "
        "(a shell profile export does not reach user services). "
        f"CLI convenience only: export KART_CGROUP_PARENT={parent}"
    )


def _failure_hint(status: dict, errors: list[str]) -> str:
    if errors:
        return "setup failed: " + "; ".join(errors)
    auto = status.get("systemd_parent")
    if auto and os.path.isdir(auto):
        if not controllers_available(auto):
            return (
                f"kart.slice exists at {auto} but memory+pids are not available in "
                "cgroup.controllers on this host"
            )
        if not subtree_control_enabled(auto):
            return (
                f"kart.slice exists at {auto} but memory+pids are not enabled in "
                "cgroup.subtree_control — child cgroups cannot be limited"
            )
        try:
            with open(os.path.join(auto, "cgroup.procs")) as f:
                if f.read().strip():
                    return (
                        f"kart.slice cgroup at {auto} has internal processes — "
                        "the parent must be empty"
                    )
        except OSError:
            pass
    return (
        "kart.slice not reachable — ensure systemd --user is running, then: "
        "systemctl --user start kart.slice"
    )


def setup_cgroup(*, start: bool = True) -> dict:
    """Idempotently install kart.slice and optionally start it."""
    unit_path = slice_unit_path()
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    changed = True
    if unit_path.exists() and unit_path.read_text(encoding="utf-8") == SLICE_UNIT_CONTENT:
        changed = False
    else:
        unit_path.write_text(SLICE_UNIT_CONTENT, encoding="utf-8")

    errors: list[str] = []
    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(f"daemon-reload: {exc}")

    started = False
    if start and not errors:
        try:
            subprocess.run(
                ["systemctl", "--user", "start", KART_SLICE_UNIT],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            started = True
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"start {KART_SLICE_UNIT}: {exc}")

    parent = systemd_cgroup_path()
    if parent and not errors:
        err = enable_subtree_control(parent)
        if err:
            errors.append(err)
        else:
            # Re-assert after reload — subtree_control can reset on daemon-reload.
            try:
                subprocess.run(
                    ["systemctl", "--user", "daemon-reload"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"post-delegate daemon-reload: {exc}")
            if not errors:
                parent = systemd_cgroup_path() or parent
                err = enable_subtree_control(parent)
                if err:
                    errors.append(err)

    status = cgroup_status()
    parent = status.get("resolved_parent")
    export_line = f"export KART_CGROUP_PARENT={parent}" if parent else ""
    return {
        "ok": bool(parent) and not errors,
        "changed": changed,
        "started": started,
        "errors": errors,
        "status": status,
        "export_line": export_line,
        "hint": _worker_env_hint(parent) if parent else _failure_hint(status, errors),
    }
