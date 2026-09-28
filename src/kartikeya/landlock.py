"""Landlock — a second filesystem lock behind bwrap.

bwrap confines a task by what it mounts. Landlock confines it by what the
process may touch, enforced by the kernel on every open, independent of the
mount namespace. With both, a path bwrap binds by mistake still has to be on
the Landlock allow-list, and in plain mode (``WILLOW_KART_NO_BWRAP=1``),
where nothing is mounted away, Landlock is the only filesystem confinement.

How it is applied: the task's argv is prefixed with a small, self-contained
Python launcher (``LAUNCHER``). Inside the sandbox it builds a ruleset from
the same paths bwrap binds (read-write binds get full access, read-only binds
read + execute), sets ``no_new_privs``, restricts itself, and execs the real
command. Landlock survives exec, so everything the task starts is confined.
No ``preexec_fn`` is involved (unsafe once the worker's thread pool runs).

``KART_LANDLOCK`` selects the mode:

* ``off`` (default): nothing changes.
* ``auto``: apply when the kernel supports Landlock; otherwise run without
  it, but loudly: the result carries ``landlock: "unsupported"`` and the
  worker logs a warning once.
* ``enforce``: apply, and refuse the task (``landlock_unavailable``) when the
  kernel lacks Landlock.

In every mode that applies it, a failure to build or apply the ruleset inside
the sandbox refuses the task (exit 126, ``landlock_failed``): once Landlock
was asked for and the kernel has it, the task never runs unconfined.

Only filesystem access is restricted. Network is bwrap's job
(``--unshare-net``), and Landlock's TCP rules (ABI 4+) are not used.
"""

from __future__ import annotations

import ctypes
import functools
import json
import logging
import os
import sys

_log = logging.getLogger("kart.landlock")

LANDLOCK_MODES = ("off", "auto", "enforce")

# Exit status and stderr marker the launcher uses when it cannot confine the
# task. run_shell turns the pair into error "landlock_failed".
LANDLOCK_FAILED_EXIT = 126
LANDLOCK_FAILED = "kart: landlock failed"

# Paths every task needs beyond the configured binds. bwrap provides them
# itself (--dev, --proc, --tmpfs), so they never appear in the bind list.
EXTRA_RW = ("/dev/null", "/dev/zero", "/dev/full")
EXTRA_RO = ("/proc", "/dev/urandom", "/dev/random")
# Under bwrap /tmp and /dev/shm are private per-task tmpfs, so they are safe
# to grant. In plain mode they are the host's, holding other processes'
# files, so they are not granted: give plain-mode tasks a writable bind (and
# TMPDIR) for scratch.
BWRAP_TMPFS_RW = ("/tmp", "/dev/shm")

_SYS_CREATE_RULESET = 444  # same number on every architecture (asm-generic)
_CREATE_RULESET_VERSION = 1


def landlock_mode() -> str:
    """The configured mode. An unrecognised value is treated as ``enforce``:
    a typo in an attempt to turn confinement on must not leave it off."""
    raw = (os.environ.get("KART_LANDLOCK") or "off").strip().lower()
    if raw in LANDLOCK_MODES:
        return raw
    _log.warning("KART_LANDLOCK=%r is not off|auto|enforce; treating as enforce", raw)
    return "enforce"


@functools.lru_cache(maxsize=1)
def landlock_abi() -> int | None:
    """The kernel's Landlock ABI version, or None when it has none.

    Asked from the worker (host side): the sandbox shares the host kernel,
    so the answer is the same inside. Cached: the kernel does not change
    under a running worker.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        abi = libc.syscall(
            _SYS_CREATE_RULESET,
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(_CREATE_RULESET_VERSION),
        )
    except (OSError, AttributeError):
        return None
    return int(abi) if abi >= 1 else None


_warned_unsupported = False


def warn_unsupported_once() -> None:
    global _warned_unsupported
    if not _warned_unsupported:
        _warned_unsupported = True
        _log.warning(
            "KART_LANDLOCK=auto but this kernel has no Landlock: tasks run "
            "without the second filesystem lock (bwrap only)"
        )


def landlock_python() -> str:
    """Interpreter for the launcher. It runs inside the sandbox, where the
    worker's own venv interpreter may not be mounted; the system one under
    /usr is (merged-usr is always bound)."""
    for candidate in ("/usr/bin/python3", "/bin/python3"):
        if os.path.exists(candidate):
            return candidate
    return sys.executable


def landlock_spec(rw_paths, ro_paths, *, bwrap: bool) -> str:
    """JSON rule spec for the launcher.

    Read-write wins when a path is listed both ways, matching bwrap's own
    collision rule. ``bwrap`` adds bwrap's private /tmp and /dev/shm; in
    plain mode those are the host's and are not granted.
    """
    rw: dict[str, None] = dict.fromkeys(str(p) for p in rw_paths)
    ro: dict[str, None] = dict.fromkeys(str(p) for p in ro_paths)
    for p in EXTRA_RW + (BWRAP_TMPFS_RW if bwrap else ()):
        rw[p] = None
    for p in EXTRA_RO:
        ro[p] = None
    return json.dumps({"rw": list(rw), "ro": [p for p in ro if p not in rw]})


_BWRAP_RW_BINDS = ("--bind", "--bind-try", "--dev-bind", "--dev-bind-try")
_BWRAP_RO_BINDS = ("--ro-bind", "--ro-bind-try")


def binds_from_bwrap_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """``(rw, ro)`` destination paths mounted by a bwrap argv.

    Reading the argv bwrap will actually run keeps the Landlock allow-list
    identical to what is mounted, including binds build_bwrap_argv adds on
    its own (known_hosts, nsswitch, the db socket). ``--tmpfs`` targets are
    read-write; ``--symlink`` entries need no rule (Landlock checks the
    resolved target).
    """
    rw: list[str] = []
    ro: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            break
        if tok in _BWRAP_RW_BINDS and i + 2 < len(argv):
            rw.append(argv[i + 2])
            i += 3
        elif tok in _BWRAP_RO_BINDS and i + 2 < len(argv):
            ro.append(argv[i + 2])
            i += 3
        elif tok == "--tmpfs" and i + 1 < len(argv):
            rw.append(argv[i + 1])
            i += 2
        else:
            i += 1
    return rw, ro


# The launcher runs as `python3 -c LAUNCHER <spec> -- <argv...>` inside the
# sandbox. It must stand alone: kartikeya itself may not be importable there.
LAUNCHER = r"""
import ctypes, json, os, stat, sys

FAILED = "kart: landlock failed"

def fail(msg):
    sys.stderr.write(FAILED + ": " + msg + "\n")
    sys.stderr.flush()
    os._exit(126)

try:
    spec = json.loads(sys.argv[1])
    if sys.argv[2] != "--" or len(sys.argv) < 4:
        fail("usage: <spec> -- <argv...>")
    argv = sys.argv[3:]
except Exception as e:
    fail("bad arguments: %r" % (e,))

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.restype = ctypes.c_int

def call(*args):
    r = libc.syscall(*args)
    if r < 0:
        err = ctypes.get_errno()
        return r, os.strerror(err)
    return r, None

abi, err = call(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
if abi < 1:
    fail("kernel has no Landlock (%s)" % err)

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
handled = (1 << 13) - 1                       # ABI 1: bits 0..12
if abi >= 2:
    handled |= 1 << 13                        # REFER
if abi >= 3:
    handled |= 1 << 14                        # TRUNCATE
if abi >= 5:
    handled |= 1 << 15                        # IOCTL_DEV
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | (1 << 14) | (1 << 15)
RW = handled
RO = EXECUTE | READ_FILE | READ_DIR

class RulesetAttr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]

class PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

attr = RulesetAttr(handled, 0, 0)
size = 8 if abi < 4 else (16 if abi < 6 else 24)
ruleset, err = call(444, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0))
if ruleset < 0:
    fail("create_ruleset: %s" % err)

for path, access in [(p, RW) for p in spec["rw"]] + [(p, RO) for p in spec["ro"]]:
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        continue
    except OSError as e:
        fail("open %s: %s" % (path, e))
    try:
        allowed = access & handled
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            allowed &= FILE_RIGHTS
        rule = PathBeneath(allowed, fd)
        r, err = call(445, ctypes.c_int(ruleset), ctypes.c_int(1), ctypes.byref(rule),
                      ctypes.c_uint32(0))
        if r < 0:
            fail("add_rule %s: %s" % (path, err))
    finally:
        os.close(fd)

if libc.prctl(38, 1, 0, 0, 0) != 0:           # PR_SET_NO_NEW_PRIVS
    fail("no_new_privs: %s" % os.strerror(ctypes.get_errno()))
r, err = call(446, ctypes.c_int(ruleset), ctypes.c_uint32(0))
if r < 0:
    fail("restrict_self: %s" % err)
os.close(ruleset)

try:
    os.execvp(argv[0], argv)
except OSError as e:
    sys.stderr.write("kart: exec %s: %s\n" % (argv[0], e))
    os._exit(127)
"""


def wrap_argv(argv: list[str], spec: str) -> list[str]:
    """``argv`` run under the launcher with ``spec``."""
    return [landlock_python(), "-c", LAUNCHER, spec, "--", *argv]
