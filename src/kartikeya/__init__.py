"""Kartikeya — standalone sandboxed task queue + worker (a.k.a. Kart).

Public surface (filled in as the lift proceeds — see docs/DESIGN.md):
- Task-queue backend seam: `TaskQueue`, `TaskRow`, `QueueStats`, `SqliteTaskQueue`.
- Execution lanes: `lanes` (fast/batch constants + worker-mode helpers).
- Task security gate: `check_kart_task` (hybrid scan over task text).
- (stage 1 cont.) sandbox, execute, worker — the bwrap runner + loop.
"""
from __future__ import annotations

from . import lanes
from .queue import QueueStats, SqliteTaskQueue, TaskQueue, TaskRow
from .task_scan import check_kart_task

__version__ = "0.0.1"

__all__ = [
    "TaskQueue",
    "TaskRow",
    "QueueStats",
    "SqliteTaskQueue",
    "lanes",
    "check_kart_task",
    "__version__",
]
