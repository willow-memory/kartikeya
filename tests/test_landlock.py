"""Landlock as a second filesystem lock (KART_LANDLOCK).

The confinement tests run the real launcher on the real kernel, in plain mode
(no bwrap here), where Landlock is the only filesystem confinement. They skip
where the kernel has no Landlock. The mode, refusal and parsing tests run
everywhere.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import landlock, sandbox
from kartikeya.execute import run_shell_task

needs_landlock = pytest.mark.skipif(
    landlock.landlock_abi() is None, reason="kernel has no Landlock"
)


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A plain-mode sandbox policy binding one rw and one ro dir, plus a
    secret outside every bind."""
    rw, ro, secret = tmp_path / "rw", tmp_path / "ro", tmp_path / "secret"
    for d in (rw, ro, secret):
        d.mkdir()
    (ro / "f").write_text("readable\n")
    (secret / "key").write_text("s3cret\n")
    base = json.loads(
        (Path(sandbox.__file__).parent / "data" / "kart-sandbox.json").read_text()
    )
    base.update(
        bind_read_only=["/usr", "/etc", str(ro)],
        bind_read_write=[str(rw)],
        bind_try=[],
        bind_try_read_only=[],
        rtk_compress={"enabled": False},
    )
    cfg = tmp_path / "kart-sandbox.json"
    cfg.write_text(json.dumps(base))
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(cfg))
    monkeypatch.setenv("WILLOW_KART_NO_BWRAP", "1")
    monkeypatch.setenv("WILLOW_KART_NO_RLIMIT", "1")
    monkeypatch.setattr(
        sandbox.cgroup_setup, "cgroup_parent_state", lambda: (None, None)
    )
    monkeypatch.setattr(sandbox, "collect_mcp_trust_ro_overlays", lambda *a: [])
    return rw, ro, secret


PROBE = (
    "cat {ro}/f; "
    "(echo w > {rw}/x) 2>/dev/null && echo rw-write-ok; "
    "(echo w > {ro}/y) 2>/dev/null || echo ro-write-denied; "
    "cat {secret}/key 2>/dev/null || echo secret-denied"
)


# ── real confinement ─────────────────────────────────────────────────────────


@needs_landlock
def test_auto_confines_the_task_to_its_binds(box, monkeypatch):
    rw, ro, secret = box
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    result = sandbox.run_shell(PROBE.format(rw=rw, ro=ro, secret=secret), timeout=20)
    assert result["returncode"] == 0, result
    assert result["landlock"] == f"abi{landlock.landlock_abi()}"
    assert result["stdout"].split() == [
        "readable",
        "rw-write-ok",
        "ro-write-denied",
        "secret-denied",
    ], result
    assert (rw / "x").exists() and not (ro / "y").exists()


@needs_landlock
def test_confinement_holds_for_child_processes(box, monkeypatch):
    # Landlock survives exec: a grandchild is just as confined.
    _, _, secret = box
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    result = sandbox.run_shell(
        f"bash -c 'sh -c \"cat {secret}/key\"' 2>/dev/null || echo denied", timeout=20
    )
    assert result["stdout"].strip() == "denied", result


@pytest.mark.skipif(os.name == "nt", reason="POSIX paths in the probe")
def test_off_changes_nothing(box, monkeypatch):
    rw, ro, secret = box
    monkeypatch.delenv("KART_LANDLOCK", raising=False)
    result = sandbox.run_shell(PROBE.format(rw=rw, ro=ro, secret=secret), timeout=20)
    assert result["returncode"] == 0, result
    assert "landlock" not in result
    assert "s3cret" in result["stdout"]  # nothing stops it: Landlock is off


@needs_landlock
def test_the_task_row_carries_the_landlock_state(box, monkeypatch):
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    status, row = run_shell_task("echo hi", timeout=20)
    assert status == "completed", row
    assert row["landlock"] == f"abi{landlock.landlock_abi()}"


# ── kernel without Landlock ──────────────────────────────────────────────────


def test_enforce_refuses_when_the_kernel_has_no_landlock(box, tmp_path, monkeypatch):
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    monkeypatch.setattr(landlock, "landlock_abi", lambda: None)
    marker = tmp_path / "ran"
    result = sandbox.run_shell(f"touch {marker}", timeout=20)
    assert result["error"] == "landlock_unavailable", result
    assert "returncode" not in result  # refused before running
    assert not marker.exists()
    status, row = run_shell_task(f"touch {marker}", timeout=20)
    assert status == "failed" and row["error"] == "landlock_unavailable"
    assert not marker.exists()


def test_auto_degrades_loudly_when_the_kernel_has_no_landlock(box, monkeypatch, caplog):
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    monkeypatch.setattr(landlock, "landlock_abi", lambda: None)
    monkeypatch.setattr(landlock, "_warned_unsupported", False)
    with caplog.at_level(logging.WARNING, logger="kart.landlock"):
        first = sandbox.run_shell("echo hi", timeout=20)
        second = sandbox.run_shell("echo hi", timeout=20)
    for result in (first, second):
        assert result["returncode"] == 0, result
        assert result["landlock"] == "unsupported"
    warnings = [r for r in caplog.records if "no Landlock" in r.getMessage()]
    assert len(warnings) == 1


def test_an_unknown_mode_is_treated_as_enforce(monkeypatch):
    monkeypatch.setenv("KART_LANDLOCK", "enforec")
    assert landlock.landlock_mode() == "enforce"


# ── launcher failure ─────────────────────────────────────────────────────────


@needs_landlock
def test_a_launcher_that_cannot_confine_refuses_the_task(box, tmp_path, monkeypatch):
    # Any failure inside the sandbox (here: an unusable rule spec) exits 126
    # before exec'ing the task, and run_shell labels it landlock_failed.
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    monkeypatch.setattr(landlock, "landlock_spec", lambda *a, **k: "{not json")
    marker = tmp_path / "ran"
    result = sandbox.run_shell(f"touch {marker}", timeout=20)
    assert result["error"] == "landlock_failed", result
    assert result["returncode"] == landlock.LANDLOCK_FAILED_EXIT
    assert landlock.LANDLOCK_FAILED in result["stderr"]
    assert not marker.exists()


# ── rule building ────────────────────────────────────────────────────────────


def test_rules_come_from_the_bwrap_argv():
    argv = [
        "bwrap", "--unshare-net", "--dev", "/dev", "--proc", "/proc",
        "--tmpfs", "/tmp", "--ro-bind", "/usr", "/usr",
        "--bind", "/h/.willow", "/h/.willow", "--ro-bind-try", "/h/k", "/h/k",
        "--symlink", "usr/bin", "/bin", "--json-status-fd", "3",
        "--", "bash", "-c", "--bind x y",
    ]  # fmt: skip
    rw, ro = landlock.binds_from_bwrap_argv(argv)
    assert rw == ["/tmp", "/h/.willow"]
    assert ro == ["/usr", "/h/k"]


def test_plain_mode_never_grants_the_hosts_tmp():
    plain = json.loads(landlock.landlock_spec(["/w"], ["/usr"], bwrap=False))
    boxed = json.loads(landlock.landlock_spec(["/w"], ["/usr"], bwrap=True))
    assert "/tmp" not in plain["rw"] and "/dev/shm" not in plain["rw"]
    assert "/tmp" in boxed["rw"] and "/dev/shm" in boxed["rw"]


def test_read_write_wins_a_path_listed_both_ways():
    spec = json.loads(landlock.landlock_spec(["/a"], ["/a", "/b"], bwrap=False))
    assert "/a" in spec["rw"] and "/a" not in spec["ro"] and "/b" in spec["ro"]


def test_launcher_python_is_the_system_interpreter():
    # The worker's venv may not be mounted inside the sandbox; /usr is.
    exe = landlock.landlock_python()
    assert exe.startswith("/usr/") or exe == sys.executable
    assert os.path.exists(exe)


# ── under bwrap (the production path) ───────────────────────────────────────


def _bwrap_works() -> bool:
    import shutil
    import subprocess

    if not shutil.which("bwrap"):
        return False
    probe = [
        "bwrap", "--unshare-pid", "--dev", "/dev", "--proc", "/proc",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--", "/usr/bin/true",
    ]  # fmt: skip
    try:
        run = subprocess.run(probe, capture_output=True, timeout=10, check=False)
        return run.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@needs_landlock
@pytest.mark.skipif(not _bwrap_works(), reason="bwrap cannot start here")
def test_an_ordinary_task_still_works_under_bwrap_with_landlock(monkeypatch):
    # The risk of a second lock is breaking tasks bwrap allowed. Under bwrap
    # every rule comes from bwrap's own argv, so an ordinary task (read /usr,
    # use the private /tmp, write and read back) must be unaffected.
    monkeypatch.delenv("WILLOW_KART_NO_BWRAP", raising=False)
    monkeypatch.setenv("WILLOW_KART_NO_RLIMIT", "1")
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    monkeypatch.setattr(
        sandbox.cgroup_setup, "cgroup_parent_state", lambda: (None, None)
    )
    result = sandbox.run_shell(
        'ls /usr >/dev/null && t=$(mktemp) && echo ok > "$t" && cat "$t"', timeout=60
    )
    assert result["returncode"] == 0, result
    assert result["stdout"].strip() == "ok", result
    assert result["sandbox"] == "bwrap"
    assert result["landlock"] == f"abi{landlock.landlock_abi()}"


# ── Loki 1645BC7C: parity for read-only paths nested in read-write binds ─────


@pytest.fixture
def nested(tmp_path, box, monkeypatch):
    """A read-write bind holding a read-only child (like a repo's .git/hooks)
    and a trust overlay (like $WILLOW_HOME/mcp_apps)."""
    rw, _ro, _secret = box
    locked = rw / "locked"
    overlay = rw / "mcp_apps"
    (rw / "open").mkdir()
    for d in (locked, overlay):
        d.mkdir()
        (d / "f").write_text("orig\n")
    cfg = Path(os.environ["KART_SANDBOX_CONFIG"])
    data = json.loads(cfg.read_text())
    data["bind_read_only"].append(str(locked))
    cfg.write_text(json.dumps(data))
    monkeypatch.setattr(sandbox, "collect_mcp_trust_ro_overlays", lambda *a: [overlay])
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    return rw, locked, overlay


@needs_landlock
def test_a_read_only_child_of_a_read_write_bind_stays_read_only(nested):
    # Landlock only adds rights, so a read-write rule on the parent used to
    # make the read-only child writable again (B1). The parent is now carved.
    rw, locked, _ = nested
    result = sandbox.run_shell(
        f"cat {locked}/f; "
        f"(echo EVIL > {locked}/f) 2>/dev/null || echo write-denied; "
        f"rm -f {locked}/f 2>/dev/null || echo delete-denied; "
        f"(echo ok > {rw}/open/new) && echo sibling-ok",
        timeout=20,
    )
    assert result["stdout"].split() == [
        "orig",
        "write-denied",
        "delete-denied",
        "sibling-ok",
    ], result
    assert (locked / "f").read_text() == "orig\n"


@needs_landlock
def test_plain_mode_protects_the_trust_overlays(nested):
    _, _, overlay = nested
    result = sandbox.run_shell(
        f"(echo EVIL > {overlay}/f) 2>/dev/null || echo denied", timeout=20
    )
    assert result["stdout"].strip() == "denied", result
    assert (overlay / "f").read_text() == "orig\n"


@needs_landlock
def test_nothing_can_be_created_directly_in_a_carved_directory(nested):
    # The known cost of parity: the right to create entries in the parent
    # would be inherited by the read-only child, so a carved directory is
    # read-only at its own level. (This is what stops `git commit` from
    # writing .git/index.lock when .git/hooks is read-only.)
    rw, _, _ = nested
    result = sandbox.run_shell(
        f"(echo x > {rw}/new-at-top) 2>/dev/null || echo create-denied", timeout=20
    )
    assert result["stdout"].strip() == "create-denied", result


# ── B2: the launcher imports nothing a task could have planted ───────────────


@needs_landlock
def test_the_launcher_does_not_import_from_the_task_directory(
    box, tmp_path, monkeypatch
):
    # The launcher runs before it confines itself. Without -I -S, `python3 -c`
    # puts the working directory (and PYTHONPATH, user site) on sys.path, so
    # a planted json.py would run unconfined in every later task.
    rw, _, _ = box
    marker = tmp_path / "planted-code-ran"
    (rw / "json.py").write_text(
        f"open({str(marker)!r}, 'w').close()\nraise SystemExit(0)\n"
    )
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    monkeypatch.setenv("PYTHONPATH", str(rw))
    result = sandbox.run_shell("echo ran", timeout=20, cwd=str(rw))
    assert result["returncode"] == 0 and result["stdout"].strip() == "ran", result
    assert not marker.exists()


def test_launcher_is_isolated_and_uses_no_packed_ctypes_struct():
    argv = landlock.wrap_argv(["true"], "{}")
    assert argv[1:3] == ["-I", "-S"]
    # F3: ctypes `_pack_` without `_layout_` is deprecated in Python 3.14.
    assert "_pack_ =" not in landlock.LAUNCHER


# ── minor ────────────────────────────────────────────────────────────────────


@needs_landlock
@pytest.mark.skipif(os.name == "nt", reason="POSIX sleep")
def test_a_timed_out_task_keeps_its_landlock_state(box, monkeypatch):
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    result = sandbox.run_shell("sleep 30", timeout=1)
    assert result["error"] == "timeout", result
    assert result["landlock"] == f"abi{landlock.landlock_abi()}"


def test_pty_devices_are_granted_under_bwrap_only():
    boxed = json.loads(landlock.landlock_spec([], [], bwrap=True))
    plain = json.loads(landlock.landlock_spec([], [], bwrap=False))
    assert {"/dev/ptmx", "/dev/pts"} <= set(boxed["rw"])
    assert not {"/dev/ptmx", "/dev/pts"} & set(plain["rw"])


# ── Loki 0BBEF1FF: follow-ups ────────────────────────────────────────────────


def _add_ro(path):
    cfg = Path(os.environ["KART_SANDBOX_CONFIG"])
    data = json.loads(cfg.read_text())
    data["bind_read_only"].append(str(path))
    cfg.write_text(json.dumps(data))


@needs_landlock
def test_a_read_only_path_two_levels_down_stays_read_only(box, monkeypatch):
    # M14: like repo/.git/hooks: carving must recurse through .git, which is
    # itself carved, and leave .git's other entries writable.
    rw, _, _ = box
    hooks = rw / "repo" / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").write_text("orig\n")
    (rw / "repo" / ".git" / "objects").mkdir()
    _add_ro(hooks)
    monkeypatch.setenv("KART_LANDLOCK", "enforce")
    result = sandbox.run_shell(
        f"(echo EVIL > {hooks}/pre-commit) 2>/dev/null || echo hook-denied; "
        f"(echo x > {hooks}/new) 2>/dev/null || echo hook-create-denied; "
        f"(echo x > {rw}/repo/.git/objects/o) && echo objects-ok; "
        f"(echo x > {rw}/repo/.git/index.lock) 2>/dev/null || echo git-dir-carved",
        timeout=20,
    )
    assert result["stdout"].split() == [
        "hook-denied",
        "hook-create-denied",
        "objects-ok",
        "git-dir-carved",
    ], result
    assert (hooks / "pre-commit").read_text() == "orig\n"


@needs_landlock
@pytest.mark.skipif(os.geteuid() == 0, reason="root can list a mode-000 dir")
def test_a_directory_that_cannot_be_listed_refuses_the_task(nested, tmp_path):
    # M8: carving must list the parent; if it cannot, the launcher refuses
    # rather than grant the parent read-write and lose the read-only child.
    rw, _, _ = nested
    marker = tmp_path / "ran"
    rw.chmod(0o300)
    try:
        result = sandbox.run_shell(f"touch {marker}", timeout=20)
    finally:
        rw.chmod(0o755)
    assert result["error"] == "landlock_failed", result
    assert result["returncode"] == landlock.LANDLOCK_FAILED_EXIT
    assert not marker.exists()


@needs_landlock
def test_the_launcher_resolves_symlinks_before_carving(tmp_path):
    # The host resolves config binds, but the launcher must not depend on
    # it: given a read-write path named through a symlink and its read-only
    # child by real path, a prefix check on the unresolved names misses the
    # nesting, nothing is carved, and the child is writable via the parent.
    rw = tmp_path / "rw"
    locked = rw / "locked"
    locked.mkdir(parents=True)
    (locked / "f").write_text("orig\n")
    link = tmp_path / "rw-link"
    link.symlink_to(rw)
    spec = landlock.landlock_spec([str(link)], ["/usr", str(locked)], bwrap=False)
    argv = landlock.wrap_argv(
        ["/bin/sh", "-c", f"(echo EVIL > {locked}/f) 2>/dev/null || echo denied"],
        spec,
    )
    out = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    assert out.stdout.strip() == "denied", out
    assert (locked / "f").read_text() == "orig\n"


def test_a_launch_failure_keeps_its_landlock_state(box, monkeypatch):
    # M12: the exception row carries the landlock field like the others.
    monkeypatch.setenv("KART_LANDLOCK", "auto")
    monkeypatch.setattr(landlock, "landlock_abi", lambda: 7)

    def boom(*a, **k):
        raise OSError("no exec for you")

    monkeypatch.setattr(sandbox.subprocess, "Popen", boom)
    result = sandbox.run_shell("true", timeout=20)
    assert result["error"] == "no exec for you", result
    assert result["landlock"] == "abi7"


def test_carved_directories_are_listed():
    assert landlock.carved_dirs(
        ["/w", "/v"], ["/w/repo/.git/hooks", "/w2/x", "/v", "/elsewhere"]
    ) == ["/w", "/w/repo", "/w/repo/.git"]
    assert landlock.carved_dirs(["/w"], ["/wx/y"]) == []


def test_carving_is_announced_once(nested, monkeypatch, caplog):
    monkeypatch.setattr(landlock, "_warned_carving", frozenset())
    monkeypatch.setattr(landlock, "landlock_abi", lambda: 7)
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *a, **k: 1 / 0)
    rw, _, _ = nested
    with caplog.at_level(logging.WARNING, logger=landlock._log.name):
        sandbox.run_shell("true", timeout=20)
        sandbox.run_shell("true", timeout=20)
    carved = [r for r in caplog.records if "carved" in r.getMessage()]
    assert len(carved) == 1, caplog.text
    assert str(rw) in carved[0].getMessage()
