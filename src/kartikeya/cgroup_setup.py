"""Delegated cgroup parent provisioning for Kart resource caps (greenfield path)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

KART_SLICE_UNIT = "kart.slice"
SLICE_UNIT_CONTENT = """[Unit]
Description=Kart sandbox resource caps (delegated cgroup parent)

[Slice]
Delegate=memory pids
"""


def _user_config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user"


def slice_unit_path() -> Path:
    return _user_config_dir() / KART_SLICE_UNIT


def is_delegated_cgroup_parent(path: str) -> bool:
    """True when ``path`` is an empty cgroup with memory+pids controllers."""
    if not path or not os.path.isdir(path):
        return False
    try:
        with open(os.path.join(path, "cgroup.controllers")) as f:
            controllers = set(f.read().split())
        if not ({"memory", "pids"} <= controllers):
            return False
        with open(os.path.join(path, "cgroup.procs")) as f:
            return f.read().strip() == ""
    except OSError:
        return False


def systemd_cgroup_path(unit: str = KART_SLICE_UNIT) -> str | None:
    """Resolve the cgroup filesystem path for a user systemd unit."""
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "show", "-p", "ControlGroupPath", "--value", unit],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    rel = (proc.stdout or "").strip().lstrip("/")
    if proc.returncode != 0 or not rel or rel == "-":
        return None
    candidate = os.path.join("/sys/fs/cgroup", rel)
    return candidate if os.path.isdir(candidate) else None


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
        "hint": (
            "Add export_line to your shell profile so Kart uses cgroup caps."
            if parent
            else "kart.slice installed but parent not ready — is systemd --user running?"
        ),
    }
