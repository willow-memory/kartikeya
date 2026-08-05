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


def test_worker_reaps_and_reports_a_dead_workers_orphaned_claim(tmp_path, caplog):
    """A previous worker was killed mid-task; this one must recover the row and
    say so, rather than leave it 'running' forever."""
    import sqlite3

    q = _queue(tmp_path)
    q.submit("ORPHAN", "sleep 999")
    q.claim_pending("kart", 1)
    with sqlite3.connect(tmp_path / "kart.db") as conn:
        conn.execute(
            "UPDATE tasks SET claimed_at=datetime('now', '-7200 seconds') "
            "WHERE task_id=?",
            ("ORPHAN",),
        )

    with caplog.at_level("WARNING", logger="kartikeya.worker"):
        run_worker(q, once=True, slots=1)

    row = q.get("ORPHAN")
    assert row["status"] == "failed"
    assert "orphaned_running_reaped" in row["result"]
    assert "ORPHAN" in caplog.text


def _network_row(**overrides):
    values = {
        "task_id": "NET",
        "task": "curl https://example.com\n# allow_net",
        "submitted_by": "requester",
        "network_authorization": '{"signed":true}',
    }
    values.update(overrides)
    return TaskRow(**values)


def _localhost_row(**overrides):
    values = {
        "task_id": "LOCAL",
        "task": "curl http://127.0.0.1:11434\n# allow_localhost",
        "submitted_by": "requester",
        "network_authorization": '{"signed":true}',
    }
    values.update(overrides)
    return TaskRow(**values)


@pytest.mark.parametrize(
    ("row", "authorizer", "error"),
    [
        (_network_row(), None, "verifier unavailable"),
        (_localhost_row(), None, "verifier unavailable"),
        (_network_row(submitted_by=""), lambda *_: True, "submitted_by missing"),
        (_localhost_row(submitted_by=""), lambda *_: True, "submitted_by missing"),
        (_network_row(network_authorization=""), lambda *_: True, "signed envelope missing"),
        (_localhost_row(network_authorization=""), lambda *_: True, "signed envelope missing"),
        (_network_row(), lambda *_: False, "verifier refused"),
        (_localhost_row(), lambda *_: False, "verifier refused"),
    ],
)
def test_network_request_denied_before_shell_launch(
    monkeypatch, row, authorizer, error
):
    launched = []
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: launched.append(True) or ("completed", {}),
    )
    status, result = kexec.execute_task_row(row, network_authorizer=authorizer)
    assert status == "failed"
    assert error in result["error"]
    assert launched == []


def test_network_authorizer_exception_denies_before_shell_launch(monkeypatch):
    launched = []
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: launched.append(True) or ("completed", {}),
    )

    def broken(*_args):
        raise RuntimeError("policy backend unavailable")

    status, result = kexec.execute_task_row(
        _network_row(), network_authorizer=broken
    )
    assert status == "failed"
    assert "verifier error" in result["error"]
    assert launched == []


def test_network_authorizer_receives_full_row_and_envelope(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: ("completed", {"stdout": "allowed"}),
    )
    row = _network_row()

    def authorize(received_row, envelope):
        seen["row"] = received_row
        seen["envelope"] = envelope
        return True

    status, result = kexec.execute_task_row(row, network_authorizer=authorize)
    assert status == "completed"
    assert result["stdout"] == "allowed"
    assert seen == {"row": row, "envelope": row.network_authorization}


def test_localhost_authorizer_receives_full_row_and_envelope(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: ("completed", {"stdout": "allowed"}),
    )
    row = _localhost_row()

    def authorize(received_row, envelope):
        seen["row"] = received_row
        seen["envelope"] = envelope
        return True

    status, result = kexec.execute_task_row(row, network_authorizer=authorize)
    assert status == "completed"
    assert result["stdout"] == "allowed"
    assert seen == {"row": row, "envelope": row.network_authorization}


def test_isolated_task_bypasses_network_authorizer(monkeypatch):
    called = []
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: ("completed", {"stdout": "isolated"}),
    )
    status, _ = kexec.execute_task_row(
        TaskRow(task_id="ISO", task="echo safe"),
        network_authorizer=lambda *_: called.append(True) or False,
    )
    assert status == "completed"
    assert called == []


def test_worker_threads_network_authorizer_to_executor(tmp_path, monkeypatch):
    q = _queue(tmp_path)
    q.submit(
        "NET-WORKER",
        "curl https://example.com\n# allow_net",
        submitted_by="requester",
        network_authorization='{"signed":true}',
    )
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: ("completed", {"stdout": "authorized"}),
    )
    seen = []
    run_worker(
        q,
        once=True,
        slots=1,
        network_authorizer=lambda row, envelope: seen.append(
            (row.task_id, envelope)
        )
        or True,
    )
    assert q.get("NET-WORKER")["status"] == "completed"
    assert seen == [("NET-WORKER", '{"signed":true}')]
