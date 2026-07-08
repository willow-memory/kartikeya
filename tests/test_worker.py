"""End-to-end worker tests over the SqliteTaskQueue.

Proves the standalone pipeline: submit -> worker claims -> execute -> mark_done,
with no Postgres and no fleet. Runs with WILLOW_KART_NO_BWRAP=1 so the shell
runs directly (these tests execute inside a sandbox already; nested bwrap is
neither available nor the thing under test — the queue/worker/execute wiring is).
Real bwrap execution is exercised on a host with bubblewrap.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import SqliteTaskQueue, TaskRow, run_worker  # noqa: E402
from kartikeya import execute as kexec  # noqa: E402


@pytest.fixture(autouse=True)
def _no_bwrap(monkeypatch):
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.setenv("WILLOW_KART_SCAN", "1")


def _queue(tmp_path) -> SqliteTaskQueue:
    return SqliteTaskQueue(tmp_path / "kart.db")


def test_end_to_end_shell_task_completes(tmp_path):
    q = _queue(tmp_path)
    q.submit("T1", "echo hello-kartikeya")
    run_worker(q, once=True, slots=1)
    row = q.get("T1")
    assert row["status"] == "completed"
    result = json.loads(row["result"])
    assert "hello-kartikeya" in result["stdout"]
    assert result["returncode"] == 0


def test_failing_task_marked_failed(tmp_path):
    q = _queue(tmp_path)
    q.submit("T2", "exit 3")
    run_worker(q, once=True, slots=1)
    row = q.get("T2")
    assert row["status"] == "failed"


def test_blocked_task_fails_via_scan(tmp_path):
    # secret-access pattern is blocked by check_kart_task before execution
    q = _queue(tmp_path)
    q.submit("T3", "cat ~/.ssh/id_rsa")
    run_worker(q, once=True, slots=1)
    row = q.get("T3")
    assert row["status"] == "failed"
    assert "KART-SECURITY" in row["result"]


def test_once_drains_multiple_tasks(tmp_path):
    q = _queue(tmp_path)
    for i in range(5):
        q.submit(f"M{i}", f"echo task-{i}")
    run_worker(q, once=True, slots=3)
    stats = q.stats()
    assert stats.completed == 5
    assert stats.pending == 0


def test_unsupported_task_type_fails_cleanly(tmp_path):
    # a workflow_phase payload with no registered handler must fail (not crash)
    q = _queue(tmp_path)
    q.submit("W1", '{"type":"workflow_phase","run_id":"r","phase_name":"p"}')
    run_worker(q, once=True, slots=1)
    row = q.get("W1")
    assert row["status"] == "failed"
    assert "unsupported task type" in row["result"]


def test_handler_receives_non_shell_task(tmp_path):
    q = _queue(tmp_path)
    q.submit("W2", '{"type":"workflow_phase","run_id":"r","phase_name":"p"}')
    seen = {}

    def handler(row: TaskRow, *, timeout=None, context="poll"):
        seen["task_id"] = row.task_id
        return "completed", {"handled": True}

    run_worker(q, once=True, slots=1, handlers={"workflow_phase": handler})
    row = q.get("W2")
    assert row["status"] == "completed"
    assert seen["task_id"] == "W2"
    assert json.loads(row["result"])["handled"] is True


def test_on_run_event_callbacks_fire(tmp_path):
    q = _queue(tmp_path)
    q.submit("E1", "echo hi")
    events = []
    run_worker(q, once=True, slots=1,
               on_run_event=lambda ev, row, **kw: events.append((ev, row.task_id, kw.get("status"))))
    assert ("open", "E1", None) in events
    assert ("close", "E1", "completed") in events
