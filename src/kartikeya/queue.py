"""Task-queue backend interface — the one seam that inverts host coupling.

Kartikeya's worker loop is written against `TaskQueue`, not against any specific
database or fleet. A host (willow-mcp, willow-2.0, or a standalone user) provides
a concrete backend; Kartikeya owns everything downstream of "give me the next
task" / "record how it finished".

Backends shipped here:
- `SqliteTaskQueue` — reference / zero-infra backend. `pip install kartikeya`
  can execute tasks with no Postgres and no fleet.

Hosts implement their own `TaskQueue` subclass for Postgres or an adopted
schema (see the willow-mcp integration in docs/DESIGN.md §3).
"""
from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class TaskRow:
    """A claimed unit of work, backend-agnostic."""
    task_id: str
    task: str
    agent: str = "kart"
    submitted_by: str = ""
    # Opaque per-task authorization token carried through to the executor's
    # pre-launch network gate (see run_worker(network_authorizer=...)). Kartikeya
    # never interprets it — a host that gates egress fills and reads it; a host
    # that doesn't leaves it "".
    network_authorization: str = ""
    status: str = "running"
    network_authorization: str = ""


@dataclass(frozen=True)
class QueueStats:
    """Aggregate counts for liveness / fleet_health."""
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0

    @property
    def total(self) -> int:
        return self.pending + self.running + self.completed + self.failed


class TaskQueue(ABC):
    """The host-supplied storage seam. Implementations MUST make `claim_pending`
    atomic — two concurrent workers must never claim the same row."""

    @abstractmethod
    def claim_pending(self, agent: str, limit: int, lane: str | None = None) -> list[TaskRow]:
        """Atomically transition up to `limit` pending `agent` rows to
        'running' and return them. Must be safe under concurrent workers.

        `lane` is an optional hint ('fast'/'batch'); backends that don't model
        lanes ignore it."""

    @abstractmethod
    def mark_running(self, task_id: str) -> None:
        """Idempotently mark a task 'running' (for backends that separate claim
        from execution start)."""

    @abstractmethod
    def mark_done(self, task_id: str, *, status: str, result: str) -> None:
        """Record terminal state. `status` is 'completed' or 'failed'; the
        backend stamps completion time."""

    @abstractmethod
    def stats(self) -> QueueStats:
        """Aggregate counts, for worker-liveness surfacing."""


class SqliteTaskQueue(TaskQueue):
    """Reference zero-infra backend.

    Atomic claim relies on SQLite serializing writers under a `BEGIN IMMEDIATE`
    transaction: the claim UPDATE and its read happen with the reserved write
    lock held, so no two connections can claim the same row. Suitable for a
    single-host worker (one or a few processes); not a distributed queue.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS tasks (
        task_id      TEXT PRIMARY KEY,
        task         TEXT NOT NULL,
        agent        TEXT NOT NULL DEFAULT 'kart',
        submitted_by TEXT NOT NULL DEFAULT '',
        network_authorization TEXT NOT NULL DEFAULT '',
        status       TEXT NOT NULL DEFAULT 'pending',
        result       TEXT,
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(status, agent);
    """

    def __init__(self, db_path: str | Path):
        self._path = str(db_path)
        with self._connect() as conn:
            conn.executescript(self._SCHEMA)
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
            }
            if "network_authorization" not in columns:
                conn.execute(
                    "ALTER TABLE tasks ADD COLUMN network_authorization "
                    "TEXT NOT NULL DEFAULT ''"
                )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def claim_pending(self, agent: str, limit: int, lane: str | None = None) -> list[TaskRow]:
        # base SQLite backend does not model lanes; `lane` is ignored.
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT task_id, task, agent, submitted_by, network_authorization "
                "FROM tasks "
                "WHERE status='pending' AND agent=? "
                "ORDER BY created_at LIMIT ?",
                (agent, limit),
            ).fetchall()
            ids = [r["task_id"] for r in rows]
            for tid in ids:
                conn.execute(
                    "UPDATE tasks SET status='running' WHERE task_id=?", (tid,)
                )
            conn.execute("COMMIT")
        return [
            TaskRow(
                task_id=r["task_id"],
                task=r["task"],
                agent=r["agent"],
                submitted_by=r["submitted_by"] or "",
                network_authorization=r["network_authorization"] or "",
            )
            for r in rows
        ]

    def mark_running(self, task_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET status='running' WHERE task_id=? AND status!='running'",
                (task_id,),
            )

    def mark_done(self, task_id: str, *, status: str, result: str) -> None:
        if status not in ("completed", "failed"):
            raise ValueError(f"terminal status must be completed|failed, got {status!r}")
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET status=?, result=?, completed_at=datetime('now') "
                "WHERE task_id=?",
                (status, result, task_id),
            )

    def stats(self) -> QueueStats:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM tasks GROUP BY status"
            ).fetchall()
        by = {r["status"]: r["n"] for r in rows}
        return QueueStats(
            pending=by.get("pending", 0),
            running=by.get("running", 0),
            completed=by.get("completed", 0),
            failed=by.get("failed", 0),
        )

    # ── test/host convenience — not part of the TaskQueue contract ──────────
    def submit(
        self,
        task_id: str,
        task: str,
        *,
        agent: str = "kart",
        submitted_by: str = "",
        network_authorization: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tasks "
                "(task_id, task, agent, submitted_by, network_authorization, status) "
                "VALUES (?, ?, ?, ?, ?, 'pending')",
                (task_id, task, agent, submitted_by, network_authorization),
            )

    def get(self, task_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
        return dict(row) if row else None
