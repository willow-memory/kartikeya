"""Kartikeya — standalone sandboxed task queue + worker (a.k.a. Kart).

Public surface:
- Task-queue backend seam: `TaskQueue`, `TaskRow`, `QueueStats`, `SqliteTaskQueue`.
- Execution lanes: `lanes` (fast/batch constants + worker-mode helpers).
- Task security gate: `check_kart_task` (hybrid scan over task text).
- Execution: `execute_task_row`, `drain_claimed_tasks`, `run_shell_task`.
- Worker loop: `run_worker`.
"""
from __future__ import annotations

from . import lanes
from .execute import (
    NetworkAuthorizer,
    drain_claimed_tasks,
    execute_task_row,
    run_shell_task,
)
from .queue import QueueStats, SqliteTaskQueue, TaskQueue, TaskRow
from .task_scan import check_kart_task
from .worker import run_worker


# Read from installed package metadata rather than hardcoded here. The literal
# this replaces had drifted to 0.0.4 while pyproject.toml said 0.0.7 — three
# releases stale, and exported in __all__, so anything introspecting
# kartikeya.__version__ was told the wrong thing. Metadata cannot drift: it is
# written at build time from the git tag.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    __version__ = _pkg_version("kartikeya")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0+unknown"

__all__ = [
    "TaskQueue",
    "TaskRow",
    "QueueStats",
    "SqliteTaskQueue",
    "lanes",
    "check_kart_task",
    "run_shell_task",
    "NetworkAuthorizer",
    "execute_task_row",
    "drain_claimed_tasks",
    "run_worker",
    "__version__",
]
