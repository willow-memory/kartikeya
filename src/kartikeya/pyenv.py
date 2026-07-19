"""Python interpreter / venv resolution for the sandbox PATH.

Standalone reimplementation of willow-2.0's `willow.fylgja.python_env`, decoupled
from the fleet home module and with the hardcoded `~/github/willow-2.0/.venv-dev`
path dropped. The sandbox uses this to bind the venv holding psycopg2 etc. and to
pick the interpreter for tasks. Falls back to the running interpreter.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .home import willow_home, willow_home_alias


def _bin_dir(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def _python_name() -> str:
    return "python.exe" if os.name == "nt" else "python3"


def venv_candidates(root: Path | None = None) -> list[Path]:
    """Return candidate venv directories in preference order.

    Fleet-specific venv locations this generic package cannot know (e.g.
    willow-2.0's ``~/github/willow-2.0/.venv-dev``) can be injected via the
    ``KART_EXTRA_VENVS`` env var (``os.pathsep``-separated paths). They are
    inserted at high preference so a caller sharing an environment with the fleet
    resolves and binds the same venv the fleet's own resolver would — keeping the
    sandbox mount set identical. Unset → no change (standalone default).
    """
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root / ".venv-dev")
        candidates.append(root / ".venv")
    for raw in os.environ.get("KART_EXTRA_VENVS", "").split(os.pathsep):
        raw = raw.strip()
        if raw:
            candidates.append(Path(raw).expanduser())
    try:
        candidates.append(willow_home(root) / "venv")
    except Exception:
        pass
    candidates.extend([
        willow_home_alias() / "venv",
        Path.home() / ".willow-venv",
    ])

    out: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            key = str(candidate.expanduser().resolve())
        except OSError:
            key = str(candidate.expanduser())
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate.expanduser())
    return out


def venv_bin_dirs(root: Path | None = None) -> list[Path]:
    """Return existing venv bin dirs in preference order."""
    bins: list[Path] = []
    for venv in venv_candidates(root):
        bin_dir = _bin_dir(venv)
        if bin_dir.is_dir():
            bins.append(bin_dir)
    return bins


def willow_python(root: Path | None = None) -> str:
    """Resolve the Python executable to use for a task/root."""
    env_python = (os.environ.get("WILLOW_PYTHON") or "").strip()
    if env_python and Path(env_python).expanduser().is_file():
        return str(Path(env_python).expanduser())

    for bin_dir in venv_bin_dirs(root):
        py = bin_dir / _python_name()
        if py.is_file():
            return str(py)

    return sys.executable
