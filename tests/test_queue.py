"""Backend tests for the TaskQueue seam — the SqliteTaskQueue reference impl.

These pin the two things the worker loop relies on: a claim moves a row out of
'pending' exactly once (no double-claim under concurrency), and terminal state
is recorded correctly.
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import QueueStats, SqliteTaskQueue, TaskRow  # noqa: E402


def _queue(tmp_path) -> SqliteTaskQueue:
    return SqliteTaskQueue(tmp_path / "tasks.db")


def test_submit_then_claim_returns_task(tmp_path):
    q = _queue(tmp_path)
    q.submit("T1", "echo hi")
    claimed = q.claim_pending("kart", 10)
    assert [t.task_id for t in claimed] == ["T1"]
    assert isinstance(claimed[0], TaskRow)
    assert q.get("T1")["status"] == "running"


def test_claim_respects_agent_and_limit(tmp_path):
    q = _queue(tmp_path)
    q.submit("A", "x", agent="kart")
    q.submit("B", "y", agent="kart")
    q.submit("C", "z", agent="other")
    claimed = q.claim_pending("kart", 1)
    assert len(claimed) == 1 and claimed[0].agent == "kart"
    # 'other' agent row is never claimed by a kart worker
    assert not any(t.task_id == "C" for t in q.claim_pending("kart", 10))


def test_mark_done_records_terminal_state(tmp_path):
    q = _queue(tmp_path)
    q.submit("T", "echo hi")
    q.claim_pending("kart", 10)
    q.mark_done("T", status="completed", result="hi")
    row = q.get("T")
    assert row["status"] == "completed"
    assert row["result"] == "hi"
    assert row["completed_at"] is not None


def test_mark_done_rejects_non_terminal_status(tmp_path):
    q = _queue(tmp_path)
    q.submit("T", "x")
    try:
        q.mark_done("T", status="running", result="")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_no_double_claim_under_concurrency(tmp_path):
    q = _queue(tmp_path)
    n = 50
    for i in range(n):
        q.submit(f"T{i:03d}", "echo hi")

    seen: list[str] = []
    lock = threading.Lock()

    def worker():
        while True:
            batch = q.claim_pending("kart", 3)
            if not batch:
                return
            with lock:
                seen.extend(t.task_id for t in batch)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # every task claimed exactly once
    assert sorted(seen) == sorted(f"T{i:03d}" for i in range(n))
    assert len(seen) == len(set(seen))


def test_stats_counts_by_status(tmp_path):
    q = _queue(tmp_path)
    q.submit("A", "x")
    q.submit("B", "y")
    q.claim_pending("kart", 1)  # one -> running
    s = q.stats()
    assert isinstance(s, QueueStats)
    assert s.pending == 1
    assert s.running == 1
    assert s.total == 2
