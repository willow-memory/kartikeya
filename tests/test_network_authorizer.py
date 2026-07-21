"""The pre-launch network authorization seam (run_worker(network_authorizer=...)).

Kartikeya owns the seam and the timing (it fires only when a shell task requests
network, before the sandbox launches); the host owns the policy. These prove the
gate denies before launch, allows when the host says yes, is never consulted for
a non-network task, and is opt-in (absent → unchanged behavior). Hermetic via
WILLOW_KART_NO_BWRAP=1, like the other worker tests.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import SqliteTaskQueue, TaskRow, run_worker  # noqa: E402


@pytest.fixture(autouse=True)
def _no_bwrap(monkeypatch):
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.setenv("WILLOW_KART_SCAN", "1")


def _queue(tmp_path) -> SqliteTaskQueue:
    return SqliteTaskQueue(tmp_path / "kart.db")


def test_taskrow_carries_opaque_network_authorization():
    assert TaskRow(task_id="y", task="t").network_authorization == ""
    assert TaskRow(task_id="x", task="t", network_authorization="env123").network_authorization == "env123"


def test_authorizer_denies_net_task_before_launch(tmp_path):
    q = _queue(tmp_path)
    q.submit("N1", "# allow_net\necho SHOULD_NOT_RUN")
    seen = []

    def deny(row, envelope):
        seen.append(row.task_id)
        return False

    run_worker(q, once=True, slots=1, network_authorizer=deny)
    row = q.get("N1")
    assert row["status"] == "failed"
    assert "verifier refused" in row["result"]
    assert "SHOULD_NOT_RUN" not in row["result"]      # the shell never ran
    assert seen == ["N1"]


def test_authorizer_denial_reason_is_surfaced(tmp_path):
    q = _queue(tmp_path)
    q.submit("N1b", "# allow_net\necho x")

    class Authz:
        last_error = "egress lease denied"

        def __call__(self, row, envelope):
            return False

    run_worker(q, once=True, slots=1, network_authorizer=Authz())
    assert "egress lease denied" in q.get("N1b")["result"]


def test_authorizer_allows_net_task_when_true(tmp_path):
    q = _queue(tmp_path)
    q.submit("N2", "# allow_net\necho net-ok")
    run_worker(q, once=True, slots=1, network_authorizer=lambda row, env: True)
    row = q.get("N2")
    assert row["status"] == "completed"
    assert "net-ok" in json.loads(row["result"])["stdout"]


def test_authorizer_not_consulted_for_non_network_task(tmp_path):
    q = _queue(tmp_path)
    q.submit("N3", "echo plain")

    def boom(row, envelope):
        raise AssertionError("authorizer must not run for a non-network task")

    run_worker(q, once=True, slots=1, network_authorizer=boom)
    row = q.get("N3")
    assert row["status"] == "completed"
    assert "plain" in json.loads(row["result"])["stdout"]


def test_net_task_runs_unchanged_without_authorizer(tmp_path):
    # opt-in: no authorizer -> no gate, behavior is exactly as before.
    q = _queue(tmp_path)
    q.submit("N4", "# allow_net\necho no-gate")
    run_worker(q, once=True, slots=1)
    assert q.get("N4")["status"] == "completed"
