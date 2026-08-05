"""The fast lane's own subprocess ceiling.

The fast lane has only a handful of slots (`KART_FAST_WORKERS`, default 3) and
serves interactive work. If a fast task inherits the batch/daemon ceiling, one
hung command holds a third of the lane for 30 minutes and everything queued
behind it waits. So `fast` is capped at `KART_FAST_TIMEOUT` (300s) while
batch keeps `KART_DAEMON_TIMEOUT` (1800s) — the arrangement carried over from
willow-2.0 (`core/kart_lanes.fast_timeout_seconds`, `core/kart_execute.kart_timeout`).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import SqliteTaskQueue, TaskRow  # noqa: E402
from kartikeya import execute as kexec  # noqa: E402
from kartikeya import worker as kworker  # noqa: E402
from kartikeya.execute import kart_timeout  # noqa: E402
from kartikeya.lanes import fast_timeout_seconds, reaper_alignment_warning  # noqa: E402


# ── kart_timeout lane matrix ────────────────────────────────────────────────

def test_fast_lane_has_its_own_short_daemon_ceiling():
    assert fast_timeout_seconds() == 300
    assert kart_timeout("daemon", lane="fast") == 300


def test_batch_lane_keeps_the_long_daemon_ceiling():
    assert kart_timeout("daemon", lane="batch") == 1800


def test_daemon_without_a_lane_is_unchanged():
    """Existing callers that pass no lane keep today's behaviour."""
    assert kart_timeout("daemon") == 1800
    assert kart_timeout("daemon", lane=None) == 1800


def test_empty_lane_normalizes_to_fast():
    assert kart_timeout("daemon", lane="") == 300


def test_poll_context_is_lane_independent():
    assert kart_timeout("poll") == 120
    assert kart_timeout("poll", lane="fast") == 120
    assert kart_timeout("poll", lane="batch") == 120


def test_fast_ceiling_is_configurable(monkeypatch):
    monkeypatch.setenv("KART_FAST_TIMEOUT", "90")
    assert fast_timeout_seconds() == 90
    assert kart_timeout("daemon", lane="fast") == 90


# ── reaper alignment must account for the fast ceiling ──────────────────────

def test_reaper_alignment_is_quiet_at_the_defaults():
    assert reaper_alignment_warning() is None


def test_reaper_alignment_flags_a_fast_ceiling_above_the_reaper(monkeypatch):
    """The reaper is defence-in-depth: a task must die by its own timeout. A
    fast ceiling raised past the reaper inverts that, and only a check that
    looks at the largest lane timeout — not just the daemon one — catches it."""
    monkeypatch.setenv("KART_FAST_TIMEOUT", "5000")   # > KART_STALE_SECONDS (3600)
    monkeypatch.setenv("KART_DAEMON_TIMEOUT", "1800")
    warning = reaper_alignment_warning()
    assert warning is not None
    assert "KART_FAST_TIMEOUT" in warning


# ── the worker actually applies it ──────────────────────────────────────────

def _timeout_seen_by_the_sandbox(monkeypatch, tmp_path, *, lane, context):
    seen = {}

    def _capture(_cmd, *, timeout=None, context="poll"):
        seen["timeout"] = timeout
        return "completed", {"stdout": ""}

    monkeypatch.setattr(kexec, "run_shell_task", _capture)
    q = SqliteTaskQueue(tmp_path / "kart.db")
    kworker._process_row(
        q,
        TaskRow(task_id="X", task="sleep 999"),
        context=context,
        lane=lane,
        handlers=None,
        network_authorizer=None,
        on_run_event=lambda *_a, **_k: None,
    )
    return seen["timeout"]


def test_worker_caps_a_fast_daemon_task_at_the_fast_ceiling(monkeypatch, tmp_path):
    """The wiring, not just the helper: a fast-lane daemon worker must hand the
    executor 300s. Resolving the ceiling without the lane silently gave 1800s."""
    assert _timeout_seen_by_the_sandbox(
        monkeypatch, tmp_path, lane="fast", context="daemon"
    ) == 300


def test_worker_caps_a_batch_daemon_task_at_the_daemon_ceiling(monkeypatch, tmp_path):
    assert _timeout_seen_by_the_sandbox(
        monkeypatch, tmp_path, lane="batch", context="daemon"
    ) == 1800


def test_run_worker_threads_its_lane_into_the_row_processor(monkeypatch, tmp_path):
    seen = {}

    def _record(_queue, row, **kwargs):
        seen["lane"] = kwargs.get("lane")
        return "completed", {}

    monkeypatch.setattr(kworker, "_process_row", _record)
    q = SqliteTaskQueue(tmp_path / "kart.db")
    q.submit("L1", "echo hi")
    kworker.run_worker(q, once=True, slots=1, lane="batch")
    assert seen["lane"] == "batch"
