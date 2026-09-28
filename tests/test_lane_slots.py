"""Per-lane concurrency, and several workers draining one queue.

The batch lane used to be hard-wired to one task at a time, ignoring both
`slots` and any setting, so a single long batch job queued everything behind
it. It now takes `KART_BATCH_WORKERS` (default 1, today's behaviour) or an
explicit `slots`, like the fast lane's `KART_FAST_WORKERS`.

Concurrency is measured, not inferred: each task blocks until the peak number
of tasks running at once reaches the expected slot count (or a short deadline
passes), and the test asserts that peak.
"""

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import SqliteTaskQueue, run_worker
from kartikeya.lanes import batch_worker_slots, lane_worker_slots

# Only workflow_phase rows are dispatched to a registered handler; any other
# JSON body would run as a shell command.
_TASK = '{"type":"workflow_phase","run_id":"r","phase_name":"p"}'


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.delenv("KART_FAST_WORKERS", raising=False)
    monkeypatch.delenv("KART_BATCH_WORKERS", raising=False)


class _Peak:
    """Handler that records how many tasks ran at once."""

    def __init__(self, want: int, wait: float = 0.5):
        self.want = want
        self.wait = wait
        self.active = 0
        self.peak = 0
        self.ran: list[str] = []
        self.cond = threading.Condition()

    def __call__(self, row, *, timeout=None, context="poll"):
        with self.cond:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.ran.append(row.task_id)
            self.cond.notify_all()
            # Hold the slot until `want` tasks overlap, so a lane that allows
            # them is seen doing so; a lane that does not times out at 1.
            self.cond.wait_for(lambda: self.peak >= self.want, timeout=self.wait)
            self.active -= 1
        return "completed", {}


def _drain(tmp_path, n: int, handler: _Peak, **kw) -> SqliteTaskQueue:
    q = SqliteTaskQueue(tmp_path / "kart.db")
    for i in range(n):
        q.submit(f"T{i}", _TASK)
    run_worker(q, once=True, handlers={"workflow_phase": handler}, **kw)
    return q


def test_batch_lane_defaults_to_one_task_at_a_time(tmp_path):
    h = _Peak(want=2)
    _drain(tmp_path, 3, h, lane="batch")
    assert h.peak == 1
    assert batch_worker_slots() == 1


def test_batch_lane_takes_kart_batch_workers(tmp_path, monkeypatch):
    monkeypatch.setenv("KART_BATCH_WORKERS", "3")
    h = _Peak(want=3)
    _drain(tmp_path, 3, h, lane="batch")
    assert h.peak == 3


def test_batch_lane_honours_explicit_slots(tmp_path):
    h = _Peak(want=2)
    _drain(tmp_path, 2, h, lane="batch", slots=2)
    assert h.peak == 2


def test_explicit_slots_beat_the_lane_setting(tmp_path, monkeypatch):
    monkeypatch.setenv("KART_BATCH_WORKERS", "3")
    h = _Peak(want=3)
    _drain(tmp_path, 3, h, lane="batch", slots=1)
    assert h.peak == 1


def test_fast_lane_still_takes_kart_fast_workers(tmp_path, monkeypatch):
    monkeypatch.setenv("KART_FAST_WORKERS", "2")
    monkeypatch.setenv("KART_BATCH_WORKERS", "4")
    h = _Peak(want=4)
    _drain(tmp_path, 4, h, lane="fast")
    assert h.peak == 2


def test_nonpositive_slots_clamp_to_one(tmp_path, monkeypatch):
    monkeypatch.setenv("KART_BATCH_WORKERS", "0")
    assert lane_worker_slots("batch") == 1
    h = _Peak(want=2)
    _drain(tmp_path, 2, h, lane="batch", slots=0)
    assert h.peak == 1


def test_two_workers_drain_one_queue_each_task_exactly_once(tmp_path):
    # Two worker loops, each with its own queue object (its own connections)
    # on one database, as two worker processes would be. Every task runs once:
    # no double claim, none left behind.
    db = tmp_path / "kart.db"
    seed = SqliteTaskQueue(db)
    n = 40
    for i in range(n):
        seed.submit(f"T{i}", _TASK)

    ran: list[str] = []
    lock = threading.Lock()

    def handler(row, *, timeout=None, context="poll"):
        time.sleep(0.005)
        with lock:
            ran.append(row.task_id)
        return "completed", {}

    errors: list[BaseException] = []

    def worker():
        try:
            run_worker(
                SqliteTaskQueue(db),
                once=True,
                lane="batch",
                slots=2,
                handlers={"workflow_phase": handler},
            )
        except BaseException as e:  # noqa: BLE001 — surfaced by the assert below
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)

    assert not errors, errors
    assert sorted(ran) == sorted(f"T{i}" for i in range(n))
    assert seed.stats().completed == n
