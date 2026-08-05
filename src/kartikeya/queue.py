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

import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .lanes import reaper_stale_seconds


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
    atomic — two concurrent workers must never claim the same row.

    Two *optional* maintenance methods are duck-typed by the worker loop
    (`worker._maybe_reap_and_prune`) and called once per poll when present:

    - ``reap_stale()`` — recover claims whose worker died. A claim is a lease,
      not a transfer: the only thing that moves a row out of 'running' is the
      process that claimed it, so a killed worker strands its row there for
      good. A backend that stamps claim time should fail such rows once the
      lease expires and return their ids (the worker logs them at WARNING).
    - ``prune_completed()`` — bound the size of the terminal-row history.

    Backends without them are fine — the worker skips what is not implemented.
    """

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

    A claim is a *lease*: `claimed_at` is stamped when the row goes 'running',
    and `reap_stale()` fails rows whose lease has expired — otherwise a worker
    killed mid-task leaves its row 'running' with no process left to finish it.
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
        claimed_at   TEXT,
        completed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(status, agent);
    """

    # Columns added after a released schema — an existing tasks table is
    # migrated in place rather than rebuilt (or silently mis-read).
    _ADDED_COLUMNS = {
        "network_authorization": "TEXT NOT NULL DEFAULT ''",
        "claimed_at": "TEXT",
    }

    def __init__(self, db_path: str | Path):
        self._path = str(db_path)
        with self._connect() as conn:
            conn.executescript(self._SCHEMA)
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for name, decl in self._ADDED_COLUMNS.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE tasks ADD COLUMN {name} {decl}")
            if "claimed_at" not in columns:
                # Rows already 'running' when the lease column arrives have no
                # claim time to recover. Start their lease now rather than
                # guessing: one full lease of grace, then the reaper sees them.
                conn.execute(
                    "UPDATE tasks SET claimed_at=datetime('now') "
                    "WHERE status='running' AND claimed_at IS NULL"
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
                    "UPDATE tasks SET status='running', claimed_at=datetime('now') "
                    "WHERE task_id=?",
                    (tid,),
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
                "UPDATE tasks SET status='running', claimed_at=datetime('now') "
                "WHERE task_id=? AND status!='running'",
                (task_id,),
            )

    # ── lease recovery ──────────────────────────────────────────────────────
    #
    # Nothing else moves a row out of 'running'. mark_done is called by the
    # process that claimed the row, so if that process is killed — OOM, SIGKILL,
    # a host reboot — the row stays 'running' forever: never retried, never
    # surfaced as failed, and (in the fast lane) still counted against the
    # worker's slots by any host that reads `running` as in-flight.

    def stale_running(
        self, max_age_seconds: int | None = None, *, agent: str = "kart"
    ) -> list[str]:
        """Task ids whose claim has outlived its lease — read-only.

        Surfacing is deliberately separate from reclaiming: an operator (or a
        health check) can see what is stranded before, or without, anything
        rewriting it. Defaults to `KART_STALE_SECONDS` (see lanes.py), which
        `lanes.reaper_alignment_warning()` keeps above every lane's own timeout
        so a task normally dies by its timeout and only ever reaches here when
        its worker did not survive to record that.
        """
        age = reaper_stale_seconds() if max_age_seconds is None else int(max_age_seconds)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT task_id FROM tasks "
                "WHERE agent=? AND status='running' AND claimed_at IS NOT NULL "
                "AND claimed_at < datetime('now', ?) "
                "ORDER BY claimed_at",
                (agent, f"-{max(0, age)} seconds"),
            ).fetchall()
        return [r["task_id"] for r in rows]

    def reap_stale(
        self, max_age_seconds: int | None = None, *, agent: str = "kart"
    ) -> list[str]:
        """Fail expired claims and return the ids actually reaped.

        Reaped rows become 'failed' carrying an `orphaned_running_reaped`
        result — the same marker willow-2.0's Postgres reaper used — rather
        than being deleted or quietly returned to 'pending'. The row says what
        happened to it, and the loss shows up in `stats().failed` instead of
        sitting invisibly in `running`. The worker loop calls this each poll
        and logs whatever comes back (see `worker._maybe_reap_and_prune`), so
        one is also swept at worker startup.
        """
        age = reaper_stale_seconds() if max_age_seconds is None else int(max_age_seconds)
        candidates = self.stale_running(age, agent=agent)
        if not candidates:
            return []
        payload = json.dumps(
            {
                "error": "orphaned_running_reaped",
                "previous_status": "running",
                "max_age_seconds": age,
            }
        )
        reaped: list[str] = []
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for tid in candidates:
                cur = conn.execute(
                    "UPDATE tasks SET status='failed', result=?, "
                    "completed_at=datetime('now') "
                    "WHERE task_id=? AND status='running'",
                    (payload, tid),
                )
                # A task that finished between the scan and this UPDATE is no
                # longer 'running' and is not reported as reaped.
                if cur.rowcount:
                    reaped.append(tid)
            conn.execute("COMMIT")
        return reaped

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
