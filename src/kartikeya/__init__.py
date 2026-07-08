"""Kartikeya — standalone sandboxed task queue + worker (a.k.a. Kart).

Public surface (filled in as the lift proceeds — see docs/DESIGN.md):
- Task-queue backend seam: `TaskQueue`, `TaskRow`, `QueueStats`, `SqliteTaskQueue`.
- (stage 2) `run_worker`, `execute_task_row` — the worker loop + single-task exec.
"""
from __future__ import annotations

from .queue import QueueStats, SqliteTaskQueue, TaskQueue, TaskRow

__version__ = "0.0.1"

__all__ = ["TaskQueue", "TaskRow", "QueueStats", "SqliteTaskQueue", "__version__"]
