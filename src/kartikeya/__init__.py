"""Kartikeya — standalone sandboxed task queue + worker (a.k.a. Kart).

Public surface:
- Task-queue backend seam: `TaskQueue`, `TaskRow`, `QueueStats`, `SqliteTaskQueue`.
- Execution lanes: `lanes` (fast/batch constants + worker-mode helpers).
- Task security gate: `check_kart_task` (hybrid scan over task text).
- Execution: `execute_task_row`, `drain_claimed_tasks`, `run_shell_task`.
- Worker loop: `run_worker`.
- Sandbox seam: `sandbox.resolve_sandbox_config`, `sandbox.is_vendored_default`,
  `sandbox.collect_mcp_trust_ro_overlays`, `sandbox.ensure_work_root`. Imported by
  path (`from kartikeya.sandbox import ...`), not re-exported here — adding them to
  `__all__` would invent a top-level spelling nobody calls. They are listed because
  a consumer already holds them: willow-mcp's `worker.py` refuses to start when the
  first two are absent, and its B-33 and B-65 floors exist for the other two. The
  rest of `sandbox` is internal.
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
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("kartikeya")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0+unknown"

__all__ = [
    "NetworkAuthorizer",
    "QueueStats",
    "SqliteTaskQueue",
    "TaskQueue",
    "TaskRow",
    "__version__",
    "check_kart_task",
    "drain_claimed_tasks",
    "execute_task_row",
    "lanes",
    "run_shell_task",
    "run_worker",
]
