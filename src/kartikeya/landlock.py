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
# Under bwrap /tmp and /dev/shm are private per-task tmpfs, and --dev gives
# a private devpts (/dev/ptmx, /dev/pts, needed by pty tools such as
# script and expect), so they are safe to grant. In plain mode they are the host's, holding other processes'
# files, so they are not granted: give plain-mode tasks a writable bind (and
# TMPDIR) for scratch.
BWRAP_TMPFS_RW = ("/tmp", "/dev/shm", "/dev/ptmx", "/dev/pts")

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


def carved_dirs(rw_paths, ro_paths) -> list[str]:
    """Directories the launcher will carve: each read-write path with a
    read-only descendant, and every directory between the two. Nothing can
    be created, removed or renamed directly in these (the right would be
    inherited by the read-only child), so e.g. ``git commit`` fails in a
    repo whose ``.git/hooks`` is read-only: it cannot write .git/index.lock.
    Paths are resolved through symlinks, as the launcher resolves them."""
    ro = [os.path.realpath(str(p)) for p in ro_paths]
    out: set[str] = set()
    for r in (os.path.realpath(str(p)) for p in rw_paths):
        prefix = r.rstrip("/") + "/"
        for d in ro:
            if d.startswith(prefix):
                parts = d[len(prefix) :].split("/")[:-1]
                cur = r
                out.add(cur)
                for part in parts:
                    cur = os.path.join(cur, part)
                    out.add(cur)
    return sorted(out)


# Every set already announced, not just the last: two policies alternating
# on one worker would otherwise warn on every task.
_warned_carving: set[frozenset[str]] = set()


def warn_carving_once(carved: list[str]) -> None:
    """Say once per distinct set, loudly, which directories lose create and
    remove rights under Landlock. The cost is otherwise invisible until a
    task (a git commit, typically) fails with EACCES."""
    key = frozenset(carved)
    if not carved or key in _warned_carving:
        return
    _warned_carving.add(key)
    shown = ", ".join(carved[:5]) + (
        f", … (+{len(carved) - 5})" if len(carved) > 5 else ""
    )
    _log.warning(
        "KART_LANDLOCK: %d writable director%s hold read-only paths and are "
        "carved: nothing can be created, removed or renamed directly in them "
        "(git commit fails where .git/hooks is read-only): %s",
        len(carved),
        "y" if len(carved) == 1 else "ies",
        shown,
    )


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


def ro_binds_needing_carving(argv: list[str]) -> list[str]:
    """The read-only binds in a bwrap argv that will *not* be read-only
    mounts, so the launcher still carves around them: one shadowed by a later
    bind or tmpfs on the same path or an ancestor, or a ``--ro-bind-try``
    whose source is missing. The launcher decides for itself from the live
    mount flags; this host-side view only feeds the carving warning."""
    mounts: list[tuple[str, bool, bool]] = []  # (dest, read_only, mounted)
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            break
        if (tok in _BWRAP_RW_BINDS or tok in _BWRAP_RO_BINDS) and i + 2 < len(argv):
            mounted = not tok.endswith("-try") or os.path.exists(argv[i + 1])
            mounts.append((argv[i + 2], tok in _BWRAP_RO_BINDS, mounted))
            i += 3
        elif tok == "--tmpfs" and i + 1 < len(argv):
            mounts.append((argv[i + 1], False, True))
            i += 2
        else:
            i += 1

    def covers(outer: str, inner: str) -> bool:
        return inner == outer or inner.startswith(outer.rstrip("/") + "/")

    out = []
    for n, (dest, read_only, mounted) in enumerate(mounts):
        if not read_only:
            continue
        shadowed = any(
            later_mounted and covers(later, dest)
            for later, _ro, later_mounted in mounts[n + 1 :]
        )
        if not mounted or shadowed:
            out.append(dest)
    return out


# The launcher runs as `python3 -c LAUNCHER <spec> -- <argv...>` inside the
# sandbox. It must stand alone: kartikeya itself may not be importable there.
LAUNCHER = r"""
import ctypes, json, os, stat, struct, sys

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

attr = RulesetAttr(handled, 0, 0)
size = 8 if abi < 4 else (16 if abi < 6 else 24)
ruleset, err = call(444, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0))
if ruleset < 0:
    fail("create_ruleset: %s" % err)

def add_rule_fd(fd, access, what):
    # struct landlock_path_beneath_attr is packed: u64 allowed_access, s32
    # parent_fd (12 bytes). Built with struct, not a packed ctypes Structure,
    # which Python 3.14 deprecates.
    allowed = access & handled
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        allowed &= FILE_RIGHTS
    buf = ctypes.create_string_buffer(struct.pack("=Qi", allowed, fd), 12)
    r, err = call(445, ctypes.c_int(ruleset), ctypes.c_int(1), buf, ctypes.c_uint32(0))
    if r < 0:
        fail("add_rule %s: %s" % (what, err))

def add_rule(path, access):
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    except OSError as e:
        fail("open %s: %s" % (path, e))
    try:
        add_rule_fd(fd, access, path)
    finally:
        os.close(fd)

def norm(p):
    # Resolve symlinks before comparing: a writable bind named through a
    # symlink (or a read-only one) must still be seen as the parent (or the
    # descendant) it really is, or carving is skipped and the read-only path
    # stays writable through the parent's rule.
    return os.path.realpath(p)

def under(child, parent):
    return child != parent and child.startswith(parent.rstrip("/") + "/")

def ident(st):
    return (st.st_dev, st.st_ino)

ro_paths = [norm(p) for p in spec["ro"]]
ro_ids = set()
# Read-only paths that sit on a read-only mount (under bwrap: every
# --ro-bind). The mount already refuses every write, and a mount point cannot
# be renamed or removed (EBUSY), so their writable parents need no carving,
# and git can create .git/index.lock beside a read-only .git/hooks. A path
# that is missing, or whose read-only bind was shadowed by a later mount, is
# not on a read-only mount and is carved around as before.
mounted_ro = set()
for p in ro_paths:
    # O_NOFOLLOW: p was resolved above, so a link here means it was swapped
    # since. Opened without following, fstatvfs reports the filesystem the
    # link sits on, not where it points; the S_ISLNK check says the same
    # thing outright. Either way a link is carved around, never trusted.
    try:
        fd = os.open(p, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        continue
    except OSError as e:
        fail("open %s: %s" % (p, e))
    try:
        st = os.fstat(fd)
        ro_ids.add(ident(st))
        if not stat.S_ISLNK(st.st_mode) and os.fstatvfs(fd).f_flag & os.ST_RDONLY:
            mounted_ro.add(p)
    except OSError as e:
        fail("stat %s: %s" % (p, e))
    finally:
        os.close(fd)
to_carve = [p for p in ro_paths if p not in mounted_ro]

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def carve(dfd, label, on_way):
    # Landlock only adds rights: a read-write rule on this directory would
    # make every read-only descendant writable again. So it gets read-only
    # rights, and each entry that is not on the way to a read-only subtree
    # gets read-write; entries that are, recurse. The walk goes by fd, each
    # entry opened relative to its parent with O_NOFOLLOW, and entries are
    # classified by (st_dev, st_ino), never by name: a task on the writable
    # bind that swaps an entry for a symlink mid-walk gets the link itself,
    # which is skipped (the kernel checks a link's target, not the link). A
    # directory that cannot be listed cannot be carved, so the ruleset is
    # refused.
    add_rule_fd(dfd, RO, label)
    try:
        entries = sorted(os.listdir(dfd))
    except OSError as e:
        fail("cannot carve %s: %s" % (label, e))
    for name in entries:
        child = label.rstrip("/") + "/" + name
        try:
            cfd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            continue
        except OSError as e:
            fail("open %s: %s" % (child, e))
        try:
            st = os.fstat(cfd)
            if stat.S_ISLNK(st.st_mode) or ident(st) in ro_ids:
                # A link gets no rule (opened O_NOFOLLOW, a rule would sit on
                # the link inode and grant nothing; skipped to keep it plain).
                # A read-only path gets its own rule below.
                continue
            if stat.S_ISDIR(st.st_mode) and ident(st) in on_way:
                try:
                    sub = os.open(name, DIR_FLAGS, dir_fd=dfd)
                except OSError as e:
                    fail("cannot carve %s: %s" % (child, e))
                try:
                    if ident(os.fstat(sub)) != ident(st):
                        fail("%s changed while carving" % child)
                    carve(sub, child, on_way)
                finally:
                    os.close(sub)
            else:
                add_rule_fd(cfd, RW, child)
        finally:
            os.close(cfd)

for path in (norm(p) for p in spec["rw"]):
    nested = [d for d in to_carve if under(d, path)]
    if not nested:
        add_rule(path, RW)
        continue
    # Every directory from `path` down to (not including) each read-only
    # path: these are carved, everything else under `path` is read-write.
    on_way = set()
    for d in nested:
        cur = os.path.dirname(d)
        while True:
            try:
                on_way.add(ident(os.stat(cur)))
            except FileNotFoundError:
                pass
            except OSError as e:
                fail("stat %s: %s" % (cur, e))
            if cur == path or not under(cur, path):
                break
            cur = os.path.dirname(cur)
    try:
        dfd = os.open(path, DIR_FLAGS)
    except FileNotFoundError:
        continue
    except OSError as e:
        fail("cannot carve %s: %s" % (path, e))
    try:
        # The bind root was stat'd into on_way by name; the fd must be the
        # same directory, or the root was swapped in between.
        if ident(os.fstat(dfd)) not in on_way:
            fail("%s changed while carving" % path)
        carve(dfd, path, on_way)
    finally:
        os.close(dfd)
for path in ro_paths:
    add_rule(path, RO)

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
    # -I: no cwd, PYTHONPATH or user site on sys.path; -S: no site import.
    # The launcher runs before confinement, so it must not import anything a
    # previous task could have planted (e.g. in a read-write ~/.local).
    return [landlock_python(), "-I", "-S", "-c", LAUNCHER, spec, "--", *argv]
