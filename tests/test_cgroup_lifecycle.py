"""Task cgroup leaves: removal, misconfigured parents, and the start sweep.

Follow-ups to #73 from Loki audit 6BCF20CB:
1. a task's leaf is removed after the task, on success and on timeout, and
   whatever is left in it is killed first (cgroup.kill);
2. a cgroup parent that is configured but unusable refuses the task instead
   of quietly running it without a memory cap;
3. a worker sweeps leaves left behind by a dead worker at start, leaving live
   siblings' leaves alone;
4. the pre-exec refusal carries no returncode.

There is no real cgroup v2 here: the parent is a temp directory, and the
kernel-side effects (cgroup.kill, rmdir of a populated cgroup) are observed
through spies rather than a kernel.
"""

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import SqliteTaskQueue, run_worker, sandbox

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX cgroup paths")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.delenv("WILLOW_KART_NO_RLIMIT", raising=False)
    monkeypatch.delenv("KART_CGROUP_PARENT", raising=False)


@pytest.fixture
def parent(tmp_path, monkeypatch):
    p = tmp_path / "kart.slice"
    p.mkdir()
    monkeypatch.setattr(
        sandbox.cgroup_setup, "cgroup_parent_state", lambda: (str(p), None)
    )
    monkeypatch.setattr(sandbox.cgroup_setup, "resolve_cgroup_parent", lambda: str(p))
    return p


@pytest.fixture
def spies(monkeypatch):
    """Record cgroup.kill writes, and let rmdir remove a fake leaf that holds
    plain files (a real cgroup's control files do not block rmdir)."""
    killed: list[str] = []
    removed: list[str] = []
    real_rmdir = os.rmdir

    def rmdir(path, *a, **k):
        leaf = Path(path)
        if (
            leaf.name.startswith("kart-")
            and leaf.is_dir()
            and not (leaf / ".busy").exists()
        ):
            for f in leaf.iterdir():
                f.unlink()
            real_rmdir(leaf)
        else:
            real_rmdir(path, *a, **k)
        removed.append(str(path))

    monkeypatch.setattr(sandbox, "_write_cgroup_kill", lambda leaf: killed.append(leaf))
    monkeypatch.setattr(sandbox.os, "rmdir", rmdir)
    return killed, removed


def _leaves(parent):
    return sorted(p.name for p in parent.iterdir())


# ── 1. removal after the task ──────────────────────────────────────────────


def test_leaf_is_killed_and_removed_after_a_successful_task(parent, spies):
    killed, removed = spies
    result = sandbox.run_shell("echo ok", timeout=10)
    assert result["returncode"] == 0, result
    assert result["resource_limit"] == "cgroup"
    assert len(killed) == 1 and removed == killed
    assert _leaves(parent) == []


def test_leaf_is_killed_and_removed_after_a_timeout(parent, spies):
    killed, removed = spies
    result = sandbox.run_shell("sleep 30", timeout=1)
    assert result["error"] == "timeout", result
    assert len(killed) == 1 and removed == killed
    assert _leaves(parent) == []


def test_busy_leaf_is_retried_then_left_for_the_sweep(parent, monkeypatch):
    leaf = parent / f"kart-{os.getpid()}-{uuid.uuid4().hex}"
    leaf.mkdir()
    (leaf / "x").write_text("")  # non-empty: plain rmdir fails like a populated cgroup
    monkeypatch.setattr(sandbox.time, "sleep", lambda s: None)
    assert sandbox._kill_and_remove_leaf(str(leaf), attempts=3) is False
    assert leaf.exists()


def test_cgroup_kill_is_written_but_never_created(tmp_path):
    # On a real cgroup the file exists; elsewhere nothing is created.
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    sandbox._write_cgroup_kill(str(leaf))
    assert not (leaf / "cgroup.kill").exists()
    (leaf / "cgroup.kill").write_text("")
    sandbox._write_cgroup_kill(str(leaf))
    assert (leaf / "cgroup.kill").read_text() == "1"


# ── 2. configured but unusable parent ──────────────────────────────────────


def test_unusable_configured_parent_refuses_the_task(tmp_path, monkeypatch):
    # KART_CGROUP_PARENT names a directory that is not a delegated cgroup
    # parent (or kart.slice lost its delegation): refuse, do not run uncapped.
    bogus = tmp_path / "not-a-cgroup"
    bogus.mkdir()
    monkeypatch.setenv("KART_CGROUP_PARENT", str(bogus))
    monkeypatch.setattr(sandbox.cgroup_setup, "systemd_cgroup_path", lambda *a: None)
    marker = tmp_path / "ran"
    result = sandbox.run_shell(f"touch {marker}", timeout=10)
    assert result["error"] == "cgroup_setup_failed", result
    assert str(bogus) in result["stderr"]
    assert "returncode" not in result
    assert not marker.exists()


def test_stale_kart_slice_refuses_the_task(tmp_path, monkeypatch):
    slice_dir = tmp_path / "kart.slice"
    slice_dir.mkdir()
    monkeypatch.setattr(
        sandbox.cgroup_setup, "systemd_cgroup_path", lambda *a: str(slice_dir)
    )
    result = sandbox.run_shell("echo hi", timeout=10)
    assert result["error"] == "cgroup_setup_failed", result


def test_no_configured_parent_still_uses_rlimit(monkeypatch):
    monkeypatch.setattr(sandbox.cgroup_setup, "systemd_cgroup_path", lambda *a: None)
    assert sandbox.cgroup_setup.cgroup_parent_state() == (None, None)
    result = sandbox.run_shell("echo hi", timeout=10)
    assert result["returncode"] == 0, result
    assert result.get("resource_limit") == "rlimit"


def test_valid_parent_wins_over_nothing_configured(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    monkeypatch.setenv("KART_CGROUP_PARENT", str(good))
    monkeypatch.setattr(
        sandbox.cgroup_setup, "is_delegated_cgroup_parent", lambda p: p == str(good)
    )
    assert sandbox.cgroup_setup.cgroup_parent_state() == (str(good), None)


# ── 3. sweep at worker start ───────────────────────────────────────────────


def _dead_pid() -> int:
    proc = subprocess.Popen(["true"])
    proc.wait()
    return proc.pid


def test_sweep_removes_dead_owners_leaves_and_spares_live_ones(parent, spies):
    killed, _ = spies
    dead = parent / f"kart-{_dead_pid()}-{uuid.uuid4().hex}"
    legacy_dead = parent / f"kart-{_dead_pid()}-12345"  # pid-ms name from <= 0.3.x
    live = parent / f"kart-{os.getpid()}-{uuid.uuid4().hex}"
    ownerless_empty = parent / f"kart-{uuid.uuid4().hex}"
    ownerless_busy = parent / f"kart-{uuid.uuid4().hex}"
    other = parent / "not-ours"
    for d in (dead, legacy_dead, live, ownerless_empty, ownerless_busy, other):
        d.mkdir()
    (ownerless_busy / ".busy").write_text("")  # stands in for a populated cgroup

    swept = sandbox.sweep_stale_cgroup_leaves()

    assert sorted(swept) == sorted(str(d) for d in (dead, legacy_dead, ownerless_empty))
    assert sorted(killed) == sorted(str(d) for d in (dead, legacy_dead))
    assert _leaves(parent) == sorted([live.name, ownerless_busy.name, other.name])


def test_sweep_without_a_parent_does_nothing(monkeypatch):
    monkeypatch.setattr(sandbox.cgroup_setup, "resolve_cgroup_parent", lambda: None)
    assert sandbox.sweep_stale_cgroup_leaves() == []


def test_worker_sweeps_once_at_start(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        sandbox, "sweep_stale_cgroup_leaves", lambda: calls.append(1) or []
    )
    q = SqliteTaskQueue(tmp_path / "k.db")
    q.submit("T1", "echo hi")
    run_worker(q, once=True, slots=1)
    assert calls == [1]
    assert q.get("T1")["status"] == "completed"


def test_a_failing_sweep_does_not_stop_the_worker(tmp_path, monkeypatch):
    def boom():
        raise OSError("sweep exploded")

    monkeypatch.setattr(sandbox, "sweep_stale_cgroup_leaves", boom)
    q = SqliteTaskQueue(tmp_path / "k.db")
    q.submit("T1", "echo hi")
    started = time.time()
    run_worker(q, once=True, slots=1)
    assert q.get("T1")["status"] == "completed"
    assert time.time() - started < 30


# ── B1 (Loki 71BF5ACF): "no returncode" must survive to the task row ─────────


def test_refusal_has_no_returncode_at_every_layer(tmp_path, monkeypatch):
    # willow-mcp reads `"returncode" not in result` as "refused before
    # running". run_shell omitted it, but both normalizers put it back as
    # None, so the row the host actually reads carried returncode: null.
    from kartikeya.execute import run_shell_task

    bogus = tmp_path / "not-a-cgroup"
    bogus.mkdir()
    monkeypatch.setenv("KART_CGROUP_PARENT", str(bogus))
    monkeypatch.setattr(sandbox.cgroup_setup, "systemd_cgroup_path", lambda *a: None)

    raw = sandbox.run_shell("echo hi", timeout=10)
    status, row = sandbox.run_shell_result_for_task("echo hi", timeout=10)
    task_status, task_row = run_shell_task("echo hi", timeout=10)

    for result in (raw, row, task_row):
        assert result["error"] == "cgroup_setup_failed", result
        assert "returncode" not in result, result
    assert status == task_status == "failed"


def test_a_task_that_ran_keeps_its_returncode(monkeypatch):
    # The key is only omitted when nothing ran.
    from kartikeya.execute import run_shell_task

    monkeypatch.setattr(sandbox.cgroup_setup, "systemd_cgroup_path", lambda *a: None)
    status, row = run_shell_task("exit 3", timeout=10)
    assert status == "failed"
    assert row["returncode"] == 3


# ── cgroup.kill happens before rmdir ─────────────────────────────────────────


def test_leaf_is_killed_before_it_is_removed(tmp_path, monkeypatch):
    events: list[str] = []
    leaf = tmp_path / f"kart-{os.getpid()}-{uuid.uuid4().hex}"
    leaf.mkdir()
    real_rmdir = os.rmdir
    monkeypatch.setattr(sandbox, "_write_cgroup_kill", lambda p: events.append("kill"))

    def rmdir(path, *a, **k):
        events.append("rmdir")
        real_rmdir(path, *a, **k)

    monkeypatch.setattr(sandbox.os, "rmdir", rmdir)
    assert sandbox._kill_and_remove_leaf(str(leaf)) is True
    assert events == ["kill", "rmdir"]
