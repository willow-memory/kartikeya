"""
kart_sandbox.py — unified bwrap sandbox for Kart execution paths.

Used by: core/kart_execute.py (daemon + poll), sap kart_task_run fallback

Mount policy: willow/fylgja/config/kart-sandbox.json (+ dynamic worktree discovery).

Public, and promised to callers outside this package — see the surface list in
`kartikeya/__init__.py` and `tests/test_public_surface.py`:

    resolve_sandbox_config, is_vendored_default,
    collect_mcp_trust_ro_overlays, ensure_work_root

Everything else here is internal and may change without a major. That split is
not cosmetic: willow-mcp imports the first two at module scope and refuses to
start a worker without them, and pins the other two from its own test suite.
Until now this module was undeclared in either direction, so a consumer depended
on names this package had never promised.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import functools
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sysconfig
import tempfile
import time
from pathlib import Path

from . import cgroup_setup

try:
    import resource as _resource  # POSIX only
except ImportError:  # pragma: no cover - non-POSIX
    _resource = None

_log = logging.getLogger("kart.sandbox")

_ALLOW_NET_DIRECTIVE = "# allow_net"
_ALLOW_LOCALHOST_DIRECTIVE = "# allow_localhost"
_ALLOW_DB_DIRECTIVE = "# allow_db"
_DEFAULT_CONFIG = Path(__file__).resolve().parent / "data" / "kart-sandbox.json"
# Reported as the manifest's config_source when every candidate was missing or
# unparseable — distinct from "resolved the vendored default", which is a real file.
_NO_CONFIG_SOURCE = "<none>"

# Credential-bearing env prefixes (GAP-B). Only passed into the sandbox when a task
# opts into network (allow_net) — a no-network task receives zero credentials.
# Overridable via the "credential_env_prefixes" key in kart-sandbox.json.
#: Env prefixes `allow_db` adds. A config that already lists these in
#: `env_prefixes` hands them to every task, which is what _warn_if_db_gate_defeated
#: exists to catch.
_DEFAULT_DB_ENV_PREFIXES = ("PG", "POSTGRES")

#: Exact variable names never handed to a task, even when their prefix is in
#: `env_prefixes`. The allow list is by prefix, so a variable that names a
#: file deliberately NOT mounted rides in by accident: WILLOW_KEYRING points at
#: config/verifiers.json (ed25519 private halves, unmounted on purpose), and a
#: task that inherits the name without the file reports "no keyring at …"
#: instead of "keyring disabled" — 40 of willow-mcp's tests fail that way in
#: the sandbox and pass on the host. Deleting the line from $WILLOW_HOME/env
#: would fix Kart and break the operator's own terminal. Overridable via the
#: "env_deny" key in kart-sandbox.json; applied last, after every source.
_DEFAULT_ENV_DENY = ("WILLOW_KEYRING",)

#: psycopg2's default socket directory. Bound only under allow_db (build_bwrap_argv);
#: a config listing it in an unconditional bind list undoes that.
_PG_SOCKET_DIR = "/var/run/postgresql"

#: Inference keys only (operator rulings 2026-09-10). GITHUB_, the publishing
#: prefixes (TWINE_, PYPI_, NPM_), AWS_ and DISCORD_ are gone from the default:
#: those are push-shaped acts, and the host performs them under its own
#: authorization rather than handing a task the key.
_DEFAULT_CREDENTIAL_PREFIXES = (
    "ANTHROPIC_",
    "OPENROUTER_",
    "GROQ_",
    "HUGGINGFACE_",
    "HF_",
    "OPENAI_",
)


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def use_bwrap() -> bool:
    """Whether Kart intends bubblewrap sandboxing (not whether bwrap is installed)."""
    return os.environ.get("WILLOW_KART_NO_BWRAP", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    )


@functools.lru_cache(maxsize=1)
def _bwrap_supports_json_status() -> bool:
    """Whether the host bwrap understands --json-status-fd (KP3/S15)."""
    try:
        h = subprocess.run(
            ["bwrap", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return "--json-status-fd" in (h.stdout + h.stderr)
    except (OSError, subprocess.SubprocessError):
        return False


def _is_fleet_repo(base: Path) -> bool:
    return (base / "core" / "kart_sandbox.py").is_file() or (
        base / "core" / "pg_bridge.py"
    ).is_file()


def _is_willow_mcp_repo(base: Path) -> bool:
    """True when ``base`` looks like a willow-mcp checkout (not a legacy monolith fleet tree)."""
    if (base / "src" / "willow_mcp").is_dir():
        return True
    pkg = base / "willow_mcp"
    if pkg.is_dir() and (pkg / "__init__.py").is_file():
        return True
    pyproject = base / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            return False
        return 'name = "willow-mcp"' in text or "name='willow-mcp'" in text
    return False


def _resolve_repo_candidate(base: Path) -> Path | None:
    try:
        resolved = base.expanduser().resolve()
    except OSError:
        return None
    if _is_fleet_repo(resolved) or _is_willow_mcp_repo(resolved):
        return resolved
    return None


def _installed_willow_mcp_root() -> Path | None:
    try:
        import willow_mcp  # type: ignore[import-untyped]
    except ImportError:
        return None
    pkg = Path(willow_mcp.__file__).resolve().parent
    for candidate in [pkg, *pkg.parents]:
        if _is_willow_mcp_repo(candidate):
            return candidate
    return None


def willow_repo_root() -> Path | None:
    """Resolve the host work root for Kart mount policy and venv discovery.

    Preference order when ``$WILLOW_ROOT`` is unset:
      1. ``$WILLOW_MCP_REPO`` (explicit willow-mcp checkout)
      2. Installed ``willow_mcp`` package tree (``pip install willow-mcp`` / editable)
      3. ``~/github/willow-mcp`` when present
      4. Legacy monolith archive checkout ``~/github/willow-2.0`` (historical directory name)

    When ``$WILLOW_ROOT`` *is* set, only that path is considered — no fleet fallback.
    """
    env = (os.environ.get("WILLOW_ROOT") or "").strip()
    if env:
        return _resolve_repo_candidate(Path(env))

    candidates: list[Path] = []
    mcp_env = (os.environ.get("WILLOW_MCP_REPO") or "").strip()
    if mcp_env:
        candidates.append(Path(mcp_env))
    installed = _installed_willow_mcp_root()
    if installed is not None:
        candidates.append(installed)
    candidates.append(Path.home() / "github" / "willow-mcp")
    candidates.append(Path.home() / "github" / "willow-2.0")

    for base in candidates:
        resolved = _resolve_repo_candidate(base)
        if resolved is not None:
            return resolved
    return None


def work_root(root: Path | None = None) -> Path | None:
    """The writable lane for sandboxed tasks: ``$WILLOW_ROOT/worktrees``.

    WILLOW_ROOT is the *product* — the product's source on a developer box, the
    installed package tree on a pip install. It is bound read-only, so a task
    that needs to change source does it in a worktree under here rather than in
    the checkout itself.
    """
    repo = root or willow_repo_root()
    return None if repo is None else repo / "worktrees"


def ensure_work_root(root: Path | None = None) -> Path | None:
    """Create the work root if absent, so its read-write bind is not skipped.

    ``_add`` silently drops a bind whose host path does not exist, and a missing
    read-write lane inside a read-only WILLOW_ROOT cannot be created from inside
    the sandbox — the task would have nowhere to work and the failure would look
    like a permissions bug rather than a missing directory. Best-effort: a
    read-only or absent repo simply yields None and the bind stays unlisted.
    """
    wr = work_root(root)
    if wr is None:
        return None
    try:
        wr.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return wr


def _template_ctx(root: Path | None) -> dict[str, str]:
    home = str(Path.home())
    repo = str(root or willow_repo_root() or Path.cwd())
    ctx = {
        "HOME": home,
        "WILLOW_ROOT": repo,
        "WILLOW_GROVE_ROOT": os.environ.get(
            "WILLOW_GROVE_ROOT", str(Path(home) / "github" / "safe-app-willow-grove")
        ),
        "WILLOW_SAFE_ROOT": os.environ.get(
            "WILLOW_SAFE_ROOT", str(Path(home) / "SAFE" / "Applications")
        ),
        "WILLOW_AGENTS_ROOT": os.environ.get(
            "WILLOW_AGENTS_ROOT", str(Path(home) / "SAFE" / "Agents")
        ),
    }
    # /run/user/<uid> is systemd-logind's default and needs a POSIX uid. A host
    # without one (Windows) has neither, so the key is left out: a config's
    # `{{XDG_RUNTIME_DIR}}` then stays an unrendered placeholder that no path
    # exists for and the bind is skipped — rather than raising here, before
    # any bind is read, or rendering to "" (which Path reads as the cwd).
    getuid = getattr(os, "getuid", None)
    if "XDG_RUNTIME_DIR" in os.environ or getuid is not None:
        ctx["XDG_RUNTIME_DIR"] = os.environ.get(
            "XDG_RUNTIME_DIR", f"/run/user/{getuid()}" if getuid else ""
        )
    return ctx


def _render(path_template: str, ctx: dict[str, str]) -> str:
    out = path_template
    for key, val in ctx.items():
        out = out.replace(f"{{{{{key}}}}}", val)
    return os.path.expanduser(out)


#: Sources already warned about, so a per-task worker does not repeat itself
#: once per task forever. Keyed by resolved config path.
_DB_GATE_WARNED: set[str] = set()

_UNCONDITIONAL_BIND_KEYS = (
    "bind_read_only",
    "bind_read_write",
    "bind_try",
    "bind_try_read_only",
)


def _warn_if_db_gate_defeated(cfg: dict, source: str) -> list[str]:
    """Say so when a mount policy makes ``allow_db`` unable to gate anything.

    `build_bwrap_argv` binds the Postgres socket only under ``allow_db``, and
    `kart_env` adds the DB env prefixes only under ``allow_db``. A config can undo
    both without looking wrong: put ``PG``/``POSTGRES`` in ``env_prefixes`` (which
    is unconditional) instead of leaving them to ``db_env_prefixes``, or list the
    socket in one of the unconditional bind lists. Either way every task gets the
    database and the ``# allow_db`` directive becomes decoration.

    Same posture as the read-only/read-write promotion warning above: never
    silent, and name the entry to move. Returns the reasons, so callers and tests
    can assert on them rather than scraping the log.
    """
    reasons: list[str] = []
    db_prefixes = tuple(cfg.get("db_env_prefixes") or _DEFAULT_DB_ENV_PREFIXES)
    env_prefixes = tuple(cfg.get("env_prefixes") or ())
    leaked = [p for p in db_prefixes if p in env_prefixes]
    if leaked:
        reasons.append(
            f"env_prefixes already contains {', '.join(leaked)} — DB credentials "
            f"reach every task whether or not it opted in. Move them to db_env_prefixes."
        )
    bound = []
    for key in _UNCONDITIONAL_BIND_KEYS:
        for raw in cfg.get(key) or []:
            if _PG_SOCKET_DIR in str(raw):
                bound.append(f"{key}: {raw}")
    if bound:
        reasons.append(
            f"{_PG_SOCKET_DIR} is bound unconditionally ({'; '.join(bound)}) — the "
            f"socket is present for every task. Remove the entry; allow_db binds it."
        )
    if reasons and source not in _DB_GATE_WARNED:
        _DB_GATE_WARNED.add(source)
        for reason in reasons:
            _log.warning(
                "kart-sandbox: allow_db cannot gate anything — %s (%s)", reason, source
            )
    return reasons


def resolve_sandbox_config(root: Path | None = None) -> tuple[dict, str]:
    """Resolve the bwrap mount policy AND report which candidate supplied it.

    Order: ``$KART_SANDBOX_CONFIG`` → ``$WILLOW_HOME/kart-sandbox.json`` →
    the vendored product-neutral default (`data/kart-sandbox.json`). The
    vendored default always exists, so a standalone install is never left
    without a mount policy.

    Returns ``(config, source)`` where ``source`` is the resolved path, or
    ``_NO_CONFIG_SOURCE`` when every candidate was missing or unparseable.

    The second element exists because the fallback used to be silent: a fleet
    worker started without ``$KART_SANDBOX_CONFIG`` in its environment ran on
    the vendored default indefinitely, producing a reduced mount set that is
    indistinguishable — from the task result alone — from the fleet policy.
    Callers that know a fleet policy is expected can now detect the drift
    instead of inferring it from which paths happen to be missing.
    """
    candidates: list[Path] = []
    env = os.environ.get("KART_SANDBOX_CONFIG", "").strip()
    if env:
        candidates.append(Path(env).expanduser())
    with contextlib.suppress(Exception):
        from .home import willow_home

        candidates.append(willow_home(root) / "kart-sandbox.json")
    candidates.append(_DEFAULT_CONFIG)
    for path in candidates:
        if path.is_file():
            try:
                cfg = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            _warn_if_db_gate_defeated(cfg, str(path))
            return cfg, str(path)
    return {}, _NO_CONFIG_SOURCE


def load_sandbox_config(root: Path | None = None) -> dict:
    """Resolve the bwrap mount policy. See :func:`resolve_sandbox_config`."""
    return resolve_sandbox_config(root)[0]


def work_root_read_only(root: Path | None = None) -> bool:
    """Whether the resolved mount policy binds ``{{WILLOW_ROOT}}`` read-only.

    True under the shipped default and under any fleet policy that kept
    `work_root_is_not_the_product`. A task that rewrites the working tree
    under such a root half-succeeds — refs move in the writable .git, the
    checkout cannot follow — so the task scanner asks this before admitting
    a tree-rewriting git verb (gap 5fd840cb5000). A policy that binds the root
    read-write (or lists it nowhere) answers False and nothing is refused.
    """
    cfg = load_sandbox_config(root)
    ro = cfg.get("bind_read_only") or []
    rw = cfg.get("bind_read_write") or []
    return "{{WILLOW_ROOT}}" in ro and "{{WILLOW_ROOT}}" not in rw


def path_read_only_in_policy(path: str | Path, root: Path | None = None) -> bool | None:
    """How the resolved mount policy binds ``path``: True read-only, False
    read-write, None when no bind covers it at all.

    Longest matching bind wins, which is how bwrap applies them too: the
    read-write ``{{WILLOW_ROOT}}/worktrees`` and ``.git`` children answer False
    under a read-only root, and a checkout bound read-write by a parent entry
    (``{{HOME}}/github/<org>``) answers False for every path inside it. The
    task scanner asks this about the directory a git verb will run in, so a
    tree rewrite is refused only where the half-write can actually happen —
    inside the read-only root — and not policy-wide (gap bd6284e3496d).
    """
    try:
        target = str(Path(path).expanduser().resolve())
    except OSError:
        return None
    best: bool | None = None
    best_len = -1
    for host, _container, ro in collect_bind_mounts(root):
        h = str(host).rstrip("/") or "/"
        if (target == h or target.startswith(h + "/")) and len(h) > best_len:
            best, best_len = ro, len(h)
    return best


def is_vendored_default(source: str) -> bool:
    """True when ``source`` is the package's own product-neutral fallback.

    A fleet install resolving to this has lost its mount policy — the symptom
    is a reduced bind set, not an error.
    """
    return source == str(_DEFAULT_CONFIG)


def _discover_worktree_targets(scan_roots: list[Path]) -> list[Path]:
    """Bind worktrees/ once; add external symlink targets only.

    Per-child directory binds are redundant (the parent rw bind covers them) and
    can leave stale host mount entries that block ``git worktree remove`` with
    EBUSY after Kart exits. Symlinked worktrees pointing outside the parent
    still need an explicit bind at their resolved path.
    """
    found: list[Path] = []
    seen: set[str] = set()
    for root in scan_roots:
        if not root.is_dir():
            continue
        try:
            resolved_root = root.resolve()
        except OSError:
            continue
        key = str(resolved_root)
        if key not in seen:
            seen.add(key)
            found.append(resolved_root)
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for candidate in children:
            if not candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if not resolved.exists():
                continue
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            found.append(resolved)
    return found


def collect_bind_mounts(root: Path | None = None) -> list[tuple[Path, Path, bool]]:
    """
    Return unique (host, container, read_only) mount triples for bwrap.
    read_only=False means read-write bind.
    """
    repo = root or willow_repo_root()
    cfg = load_sandbox_config(repo)
    ctx = _template_ctx(repo)
    # Must happen before the bind loops: the work root is the one read-write
    # path inside a read-only WILLOW_ROOT, and a bind target that does not exist
    # is dropped rather than created.
    ensure_work_root(repo)

    mounts: dict[str, tuple[Path, Path, bool]] = {}

    def _add(host: Path, read_only: bool, *, required: bool = False) -> None:
        try:
            if not host.exists():
                # KP6a (S9): a required bind that is missing is usually config rot —
                # surface it. bind_try entries are optional, so they stay silent.
                if required:
                    _log.warning(
                        "kart-sandbox: required bind target missing, skipped: %s", host
                    )
                return
            resolved = host.resolve()
        except OSError:
            return
        key = str(resolved)
        ro = read_only
        if key in mounts:
            existing = mounts[key]
            # Read-write wins a collision regardless of listing order. That is
            # load-bearing for promotions a host means (a repo listed rw on top
            # of a ro parent), and a trap when it is not: a per-repo rw entry
            # for WILLOW_ROOT silently undoes the read-only work root, and the
            # config still reads correct. Never silent — say which path flipped.
            if existing[2] and not ro:
                _log.warning(
                    "kart-sandbox: %s was listed read-only and is being promoted to "
                    "read-write by a later entry. If this is WILLOW_ROOT or a trust "
                    "path, remove the read-write entry: the read-only one does not "
                    "win.",
                    key,
                )
            mounts[key] = (existing[0], existing[1], existing[2] and ro)
        else:
            mounts[key] = (resolved, resolved, ro)

    for raw in cfg.get("bind_read_only", []):
        _add(Path(_render(str(raw), ctx)), True, required=True)
    for raw in cfg.get("bind_try_read_only", []):
        _add(Path(_render(str(raw), ctx)), True)
    for raw in cfg.get("bind_read_write", []):
        _add(Path(_render(str(raw), ctx)), False, required=True)
    for raw in cfg.get("bind_try", []):
        _add(Path(_render(str(raw), ctx)), False)

    # A pip-installed box resolves the work root to the installed willow_mcp
    # package tree, and a policy that binds its parent read-write (~/.local is
    # in the shipped bind_read_write; a user-site install lives under it) hands
    # a task write access to gate.py — the code deciding what tasks may do. The
    # fleet is masked because a checkout exists; a consumer install is not
    # (WHERE_KART_GOES.md, gap 939264d1298e). The installed tree is never
    # writable from a task: if a read-write bind covers it, overlay it
    # read-only. bwrap applies the later, more specific bind, and this list is
    # emitted sorted by path, so the child overlay wins over its parent.
    installed = _installed_willow_mcp_root()
    if installed is not None:
        ikey = str(installed)
        covering = [
            k
            for k, (_h, _c, ro) in mounts.items()
            if not ro and (k == ikey or ikey.startswith(k.rstrip("/") + "/"))
        ]
        if covering:
            _log.warning(
                "kart-sandbox: the installed willow_mcp tree %s is covered by a "
                "read-write bind (%s); overlaying it read-only. A task must not be "
                "able to edit the code that gates it.",
                ikey,
                ", ".join(sorted(covering)),
            )
            mounts[ikey] = (installed, installed, True)

    scan_roots = [
        Path(_render(str(raw), ctx))
        for raw in cfg.get("worktree_scan_roots", ["{{WILLOW_ROOT}}/worktrees"])
    ]
    for wt in _discover_worktree_targets(scan_roots):
        _add(wt, False)

    # Python runtime paths for Willow venvs / psycopg2 inside bwrap.
    # Worktrees usually do not have .venv-dev, so bind every known venv candidate.
    try:
        from .pyenv import venv_candidates

        for venv in venv_candidates(repo):
            if venv.is_dir():
                _add(venv, True)
    except Exception:  # noqa: BLE001 — any failure in the resolver degrades to the pre-pyenv binds below
        repo_venv = (repo / ".venv-dev") if repo else None
        if repo_venv and repo_venv.is_dir():
            _add(repo_venv, True)
        home_venv = Path.home() / ".willow-venv"
        if home_venv.is_dir() and (
            not repo_venv or home_venv.resolve() != repo_venv.resolve()
        ):
            _add(home_venv, True)
    try:
        import psycopg2 as _pg2

        _add(Path(_pg2.__file__).resolve().parent, True)
        libs = Path(_pg2.__file__).resolve().parent.parent / "psycopg2_binary.libs"
        _add(libs, True)
    except ImportError:
        pass
    user_site = sysconfig.get_path("purelib")
    if user_site:
        _add(Path(user_site), True)

    return sorted(mounts.values(), key=lambda t: str(t[0]))


def collect_mcp_trust_ro_overlays(root: Path | None = None) -> list[Path]:
    """Return willow-mcp on-disk trust roots that must be read-only inside bwrap.

    $WILLOW_HOME/mcp_apps holds per-app manifest.json ACLs and _identity_bindings/
    confirmed OAuth records — the gate for host stdio/serve. The fleet home is
    bind-mounted read-write for store/kart logs; this overlay blocks sandbox tasks
    from rewriting the ACLs that gate them (FRANK baf2f63a / #777).

    B-33 (willow-mcp docs/BUGS.md): the CONSENT files beside mcp_apps are the
    documented fleet-wide egress off switch, and the rw home bind left them
    writable from inside the sandbox — the one control described as the kill
    switch was the one the untrusted runtime could write. Overlay them
    read-only exactly as B-14 did for mcp_apps/: settings.global.json (canonical,
    also under config/), consent.json (legacy mirror at home root and under
    config/).
    """
    from .home import willow_home, willow_home_alias

    repo = root or willow_repo_root()
    seen: set[str] = set()
    overlays: list[Path] = []
    bases = [willow_home(repo)]
    # When WILLOW_HOME is explicit (sandbox / alternate install), do not overlay the
    # operator's ~/.willow trust root — that would ro-bind fleet mcp_apps into an
    # isolated new-user home.
    if not os.environ.get("WILLOW_HOME"):
        bases.append(willow_home_alias())
    for base in bases:
        candidates = (
            base / "mcp_apps",
            base / "settings.global.json",
            base / "config" / "settings.global.json",
            base / "consent.json",
            base / "config" / "consent.json",
        )
        for trust in candidates:
            try:
                if not trust.exists():
                    continue
                resolved = trust.resolve()
            except OSError:
                continue
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            overlays.append(resolved)
    return overlays


def collect_config_symlinks(root: Path | None = None) -> list[tuple[str, str]]:
    """S8/KP6b: (resolved_target, configured_path) for every configured bind
    path that is a symlink on the host.

    collect_bind_mounts resolves and dedups by real path, so a symlinked
    store never appears in the container at its configured path unless the
    sandbox re-emits it as a --symlink. Generalizing here replaces the old
    hand-maintained re-add list — a new symlinked store in config Just Works.
    """
    repo = root or willow_repo_root()
    cfg = load_sandbox_config(repo)
    ctx = _template_ctx(repo)
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key in ("bind_read_only", "bind_try_read_only", "bind_read_write", "bind_try"):
        for raw in cfg.get(key, []):
            p = Path(_render(str(raw), ctx))
            try:
                if not p.is_symlink():
                    continue
                resolved = p.resolve()
                if not resolved.exists():
                    continue
            except OSError:
                continue
            if str(p) in seen:
                continue
            seen.add(str(p))
            links.append((str(resolved), str(p)))
    return links


def build_bwrap_argv(
    *,
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
    root: Path | None = None,
) -> list[str]:
    args = ["bwrap"]
    # Isolated: --unshare-net blocks all sockets (including 127.0.0.1:11434 Ollama).
    # allow_localhost shares the host net ns so loopback services work, but does NOT
    # mount credentials (GAP-B) — unlike allow_net.
    if not allow_net and not allow_localhost:
        args.append("--unshare-net")
    # KP2 — namespace + kernel-surface hardening.
    #  --tmpfs /tmp + /dev/shm : private scratch, not a host bind (S11, S16) — no
    #                            cross-task channel, no host /tmp pollution.
    #  --unshare-ipc/--unshare-uts : isolate SysV/POSIX IPC + hostname (S12).
    #  --new-session           : own session → blocks TIOCSTI terminal injection,
    #                            CVE-2017-5226 (S2). Safe: Kart is non-interactive.
    #  --as-pid-1              : init/reaper inside the PID ns so children don't
    #                            leak as zombies (S14).
    # NOTE: a --seccomp syscall filter (S13) is deferred — it needs a libseccomp/BPF
    #       toolchain decision; --new-session already covers the CVE-2017-5226 vector.
    args += [
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/dev/shm",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--new-session",
        "--as-pid-1",
        "--die-with-parent",
    ]

    # Track every destination already claimed inside the sandbox so the
    # symlink passes below never emit a second entry at the same path.
    # bwrap hard-fails on a duplicate ("Can't make symlink at /bin:
    # existing destination is usr/bin"), killing the task before its
    # command ever runs (flag-kart-bwrap-merged-usr-symlink-race —
    # 8.5% of "failed" tasks died in sandbox bring-up, not task logic).
    _claimed: set[str] = set()
    for host, container, read_only in collect_bind_mounts(root):
        flag = "--ro-bind" if read_only else "--bind"
        args += [flag, str(host), str(container)]
        _claimed.add(str(container))

    # Trust-root overlay: fleet home is rw, but mcp_apps must not be writable
    # from inside the sandbox (see collect_mcp_trust_ro_overlays).
    for trust_root in collect_mcp_trust_ro_overlays(root):
        trust_str = str(trust_root)
        if trust_str in _claimed:
            continue
        args += ["--ro-bind", trust_str, trust_str]
        _claimed.add(trust_str)

    # On merged-usr systems /bin, /lib, /lib64, /sbin are symlinks → /usr/*.
    # Recreate them in the sandbox so ELF interpreters (e.g. /lib64/ld-linux*.so.2)
    # resolve — ro-binding /usr alone is not enough for execvp.
    _MERGED_USR_LINKS = [
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib32", "usr/lib32"),
        ("/lib64", "usr/lib64"),
        ("/libx32", "usr/libx32"),
    ]
    for link_path, target in _MERGED_USR_LINKS:
        if not Path(link_path).is_symlink():
            continue
        if link_path in _claimed:
            continue
        args += ["--symlink", target, link_path]
        _claimed.add(link_path)

    # S8/KP6b: any configured bind path that is a host symlink resolves away in
    # collect_bind_mounts (dedup by real path), so re-emit each one as --symlink
    # at its configured path. Generalizes the old hand-coded ~/.willow re-add —
    # the next symlinked store added to config needs no code change.
    for _target, _link in collect_config_symlinks(root):
        if _link in _claimed:
            continue
        args += ["--symlink", _target, _link]
        _claimed.add(_link)

    # ~/.willow keeps one extra behavior the generic pass can't infer: on hosts
    # where the alias does not exist at all, create it anyway so legacy
    # ~/.willow paths work inside bwrap.
    from .home import willow_home, willow_home_alias

    _home_willow = willow_home_alias()
    _canonical_willow = willow_home()
    if (
        str(_home_willow) not in _claimed
        and _canonical_willow.is_dir()
        and (_home_willow.is_symlink() or not _home_willow.exists())
    ):
        args += ["--symlink", str(_canonical_willow), str(_home_willow)]

    # psycopg2's default socket dir is /var/run/postgresql. Only bind it when the
    # task opted into the local Postgres lane (allow_db) — default tasks must not
    # reach the production socket.
    if allow_db:
        _pg_sock = Path(_PG_SOCKET_DIR)
        if _pg_sock.exists():
            args += ["--bind", str(_pg_sock.resolve()), str(_pg_sock)]

    if allow_net:
        # No GitHub credential enters the sandbox on ANY network mode (operator
        # ruling 2026-09-10, "kart push is brokered"). ~/.netrc and ~/.config/gh
        # used to be bound read-only here under allow_net; they are not bound at
        # all now. Who holds the key and who initiates a push are two questions:
        # the task initiates, the host-side broker holds the credential and
        # performs the push inside a signed git.push envelope. A task that needs
        # GitHub asks for it; it never carries it. The env-prefix half of the
        # same rule is the policy's credential_env_prefixes list.
        home = Path.home()

        # ~/.ssh is never bound (S1) — private keys do not enter the sandbox.
        # The SSH agent socket is not bound either (operator, 2026-09-10: "include
        # SSH as well"). It exposed no key material, but a socket the agent
        # answers on is a credential in effect: a task could sign as the
        # operator for any ssh remote. Same rule as gh/netrc — the broker holds
        # the key, the task asks. Host-key verification is not a credential, so
        # known_hosts stays, read-only, for whatever ssh a task still does.
        known_hosts = home / ".ssh" / "known_hosts"
        if known_hosts.is_file():
            args += ["--ro-bind", str(known_hosts), str(known_hosts)]

        # Ubuntu/Debian nsswitch.conf has mdns4_minimal [NOTFOUND=return] before dns,
        # which causes non-.local lookups to abort before reaching the DNS backend.
        # Shadow /etc/nsswitch.conf with a minimal version that goes straight to dns.
        # Written under WILLOW_HOME (not host /tmp) so it survives --tmpfs /tmp and
        # does not pollute the host /tmp (S11).
        from .home import willow_home as _wh

        _nsswitch = _wh(root) / "kart-nsswitch.conf"
        _nsswitch.write_text(
            "passwd:   files\ngroup:    files\nhosts:    files dns\n",
            encoding="utf-8",
        )
        args += ["--ro-bind", str(_nsswitch), "/etc/nsswitch.conf"]

    return args


def _bash_outside(path: str, system_dir: str | None) -> str | None:
    """`bash` resolved on `path` (os.pathsep-separated), ignoring any entry
    under `system_dir`. On Windows, System32 carries a `bash.exe` that is the
    WSL launcher, not a shell: with no distribution installed it prints a
    UTF-16 notice and exits 1, and it sits ahead of Git for Windows' real bash
    on PATH. So the system directory is skipped and the first other bash wins."""
    entries = [d for d in path.split(os.pathsep) if d]
    if system_dir:
        prefix = os.path.normcase(os.path.normpath(system_dir))
        entries = [
            d
            for d in entries
            if not os.path.normcase(os.path.normpath(d)).startswith(prefix)
        ]
    return shutil.which("bash", path=os.pathsep.join(entries)) if entries else None


def _sandbox_bash() -> str:
    """Absolute bash path for bwrap exec (merged-usr has no /bin in the sandbox)."""
    for candidate in ("/usr/bin/bash", "/bin/bash"):
        if Path(candidate).is_file():
            return candidate
    if os.name == "nt":
        found = _bash_outside(
            os.environ.get("PATH", ""), os.environ.get("SystemRoot", r"C:\Windows")
        )
        if found:
            return found
    return "bash"


def task_allows_network(task_text: str) -> bool:
    return any(line.strip() == _ALLOW_NET_DIRECTIVE for line in task_text.splitlines())


def task_allows_localhost(task_text: str) -> bool:
    return any(
        line.strip() == _ALLOW_LOCALHOST_DIRECTIVE for line in task_text.splitlines()
    )


def task_allows_db(task_text: str) -> bool:
    return any(line.strip() == _ALLOW_DB_DIRECTIVE for line in task_text.splitlines())


def task_requests_shared_network(task_text: str) -> bool:
    """Whether a task asks to share the host network namespace.

    Both directives cross the network isolation boundary. ``allow_localhost``
    does not receive credential environment variables, but it can still reach
    every service listening on the host namespace and therefore requires the
    same attributable per-task authorization as ``allow_net``.
    """
    return task_allows_network(task_text) or task_allows_localhost(task_text)


def parse_task_network(task_text: str) -> tuple[str, bool, bool, bool]:
    """Strip sandbox directives; return (cmd_body, allow_net, allow_localhost, allow_db)."""
    allow_net = task_allows_network(task_text)
    allow_localhost = (not allow_net) and task_allows_localhost(task_text)
    allow_db = task_allows_db(task_text)
    skip = {_ALLOW_NET_DIRECTIVE, _ALLOW_LOCALHOST_DIRECTIVE, _ALLOW_DB_DIRECTIVE}
    lines = [line for line in task_text.splitlines() if line.strip() not in skip]
    return "\n".join(lines).strip(), allow_net, allow_localhost, allow_db


def _parse_fleet_env_file(path: Path, prefixes: tuple[str, ...]) -> dict[str, str]:
    """Parse a shell KEY=VALUE env file. Skips comments and blank lines.
    Only includes keys matching prefixes. Strips surrounding quotes from values."""
    result: dict[str, str] = {}
    with contextlib.suppress(Exception):
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if not key or not key.startswith(prefixes):
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if val:
                result[key] = val
    return result


def kart_env(
    root: Path | None = None,
    *,
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
) -> dict[str, str]:
    repo = root or willow_repo_root()
    cfg = load_sandbox_config(repo)
    prefixes = tuple(
        cfg.get("env_prefixes")
        or ("WILLOW_", "GROVE_", "OLLAMA_", "GIT_", "ANTHROPIC_", "GROQ_")
    )
    db_prefixes = tuple(cfg.get("db_env_prefixes") or _DEFAULT_DB_ENV_PREFIXES)
    if allow_db:
        prefixes = prefixes + db_prefixes
    # GAP-B: credential-bearing env vars only reach the sandbox on a network-opted
    # task. A no-network task cannot exfil keys it was never handed.
    cred_prefixes = tuple(
        cfg.get("credential_env_prefixes") or _DEFAULT_CREDENTIAL_PREFIXES
    )

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        "PYTHONUNBUFFERED": "1",
        # Marker so code inside bwrap tasks can detect the Kart sandbox context.
        "WILLOW_IN_KART": "1",
        "WILLOW_KART_ALLOW_NET": "1" if allow_net else "0",
        "WILLOW_KART_ALLOW_LOCALHOST": "1"
        if allow_localhost and not allow_net
        else "0",
        "WILLOW_KART_ALLOW_DB": "1" if allow_db else "0",
    }
    for key, val in os.environ.items():
        if key.startswith(prefixes):
            env[key] = val

    # Supplement with fleet env file so API keys (ANTHROPIC_API_KEY, GROQ_API_KEY, …)
    # reach bwrap tasks even when the calling process (MCP server, kart worker) didn't
    # inherit them from the user's shell. os.environ values take priority.
    from .home import willow_home

    _fleet_env_path = willow_home(repo) / "env"
    for k, v in _parse_fleet_env_file(_fleet_env_path, prefixes).items():
        if k not in env:
            env[k] = v

    # Resolved repo wins over inherited env (MCP may pass $HOME or a stale path).
    if repo:
        env["WILLOW_ROOT"] = str(repo.resolve())
        env["PYTHONPATH"] = str(repo.resolve())

    try:
        from .pyenv import venv_bin_dirs, willow_python

        env["WILLOW_PYTHON"] = willow_python(repo)
        for bin_dir in reversed(venv_bin_dirs(repo)):
            venv_bin = str(bin_dir)
            if venv_bin not in env["PATH"].split(":"):
                env["PATH"] = venv_bin + ":" + env["PATH"]
    except Exception:  # noqa: BLE001 — same fallback as the binds: the resolver failing means the legacy venv
        venv_bin = None
        if repo and (repo / ".venv-dev" / "bin").is_dir():
            venv_bin = str(repo / ".venv-dev" / "bin")
        elif (Path.home() / ".willow-venv" / "bin").is_dir():
            venv_bin = str(Path.home() / ".willow-venv" / "bin")
        if venv_bin and venv_bin not in env["PATH"]:
            env["PATH"] = venv_bin + ":" + env["PATH"]

    # KP5 (S6): ensure host user + npm-global bin dirs are on PATH so host-installed
    # shims (cursor-agent, npm-global CLIs) resolve inside the sandbox. Appended at
    # the tail so they never shadow venv/system binaries.
    _user_bins = [str(Path.home() / ".local" / "bin")]
    _npm_prefix = os.environ.get("NPM_CONFIG_PREFIX")
    if _npm_prefix:
        _user_bins.append(str(Path(_npm_prefix) / "bin"))
    _user_bins.append(str(Path.home() / ".npm-global" / "bin"))
    _user_bins.append(str(Path.home() / ".fly" / "bin"))
    _path_parts = env["PATH"].split(":")
    for _b in _user_bins:
        if _b not in _path_parts:
            env["PATH"] = env["PATH"] + ":" + _b
            _path_parts.append(_b)

    if "GIT_AUTHOR_NAME" not in env:
        with contextlib.suppress(Exception):
            name = subprocess.check_output(
                ["git", "config", "--global", "user.name"], text=True
            ).strip()
            email = subprocess.check_output(
                ["git", "config", "--global", "user.email"], text=True
            ).strip()
            if name:
                env["GIT_AUTHOR_NAME"] = name
                env["GIT_COMMITTER_NAME"] = name
            if email:
                env["GIT_AUTHOR_EMAIL"] = email
                env["GIT_COMMITTER_EMAIL"] = email

    # Inside bwrap, /var/run is not present unless allow_db mounted the socket.
    # psycopg2 with host=None defaults to /var/run/postgresql.
    if allow_db and not env.get("WILLOW_PG_HOST"):
        import glob as _glob

        for _sock in _glob.glob("/run/postgresql/.s.PGSQL.*") + _glob.glob(
            "/tmp/.s.PGSQL.*"
        ):
            env["WILLOW_PG_HOST"] = str(Path(_sock).parent)
            break

    # The SAP gate requires WILLOW_SAFE_ROOT to initialize; without it classify
    # fails inside bwrap and promote_intake falls back to heuristic routing.
    if not env.get("WILLOW_SAFE_ROOT"):
        default_safe = Path.home() / "github" / "SAFE" / "Applications"
        if default_safe.is_dir():
            env["WILLOW_SAFE_ROOT"] = str(default_safe)

    # GAP-B: strip credential env vars unless the task opted into network. Done last
    # so it catches keys sourced from both os.environ and the fleet env file.
    if not allow_net and cred_prefixes:
        for key in [k for k in env if k.startswith(cred_prefixes)]:
            del env[key]

    # Unconditional deny by exact name — after every source (os.environ, the
    # fleet env file, the defaults above) so nothing re-adds a denied name.
    env_deny = cfg.get("env_deny")
    if env_deny is None:
        env_deny = _DEFAULT_ENV_DENY
    for key in env_deny:
        env.pop(str(key), None)

    # XDG_RUNTIME_DIR names a path that only exists inside the sandbox when the
    # config binds it (/run/user or {{XDG_RUNTIME_DIR}} in a bind list). The
    # vendored default binds it; an operator who removed those binds to close
    # the desktop-bus exposure (willow-mcp env-fs.write-3ea8d27806c2) was left
    # with a variable pointing at nothing, which some tools warn on and a few
    # fail on. Emit it only when it is actually reachable.
    xdg = env.get("XDG_RUNTIME_DIR")
    if xdg and not _xdg_runtime_bound(cfg, repo, xdg):
        del env["XDG_RUNTIME_DIR"]

    return env


def _xdg_runtime_bound(cfg: dict, repo: Path | None, xdg: str) -> bool:
    """Whether any configured bind (rendered with the same template context the
    mount collector uses) is `xdg` itself or an ancestor of it, and exists on
    the host — the conditions under which the path will be present in bwrap."""
    ctx = _template_ctx(repo)
    try:
        target = Path(xdg).resolve(strict=False)
    except OSError:
        return False
    for key in ("bind_read_only", "bind_read_write", "bind_try", "bind_try_read_only"):
        for raw in cfg.get(key) or ():
            if not isinstance(raw, str):
                continue
            try:
                bound = Path(_render(raw, ctx)).resolve(strict=False)
            except (OSError, KeyError, ValueError):
                continue
            if (bound == target or bound in target.parents) and bound.exists():
                return True
    return False


def sandbox_manifest(
    *,
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
    root: Path | None = None,
) -> dict:
    """KP3 — declare the boundary so a caller can tell 'empty' from 'absent'.

    Reports the roots that ARE mounted (rw vs ro), the tmpfs scratch, the network
    state, and the PATH dirs visible inside the sandbox. This is the read-side cure
    for the audit's defining defect: an unbound path returns empty, identical to a
    real absence, with no signal. The manifest is that signal.
    """
    engine = "bwrap" if use_bwrap() else "plain"
    _cfg, config_source = resolve_sandbox_config(root)
    bound_rw: list[str] = []
    bound_ro: list[str] = []
    with contextlib.suppress(Exception):
        for host, _container, read_only in collect_bind_mounts(root):
            (bound_ro if read_only else bound_rw).append(str(host))
        for trust_root in collect_mcp_trust_ro_overlays(root):
            bound_ro.append(str(trust_root))
    path_dirs = (
        kart_env(
            root,
            allow_net=allow_net,
            allow_localhost=allow_localhost,
            allow_db=allow_db,
        )
        .get("PATH", "")
        .split(":")
    )
    if allow_net:
        network_mode = "full"
    elif allow_localhost:
        network_mode = "localhost"
    else:
        network_mode = "isolated"
    return {
        "engine": engine,
        "allow_net": allow_net,
        "allow_localhost": allow_localhost and not allow_net,
        "allow_db": allow_db,
        "network_mode": network_mode,
        "bound_rw": sorted(bound_rw),
        "bound_ro": sorted(bound_ro),
        "tmpfs": ["/tmp", "/dev/shm"] if engine == "bwrap" else [],
        "path_dirs": [p for p in path_dirs if p],
        # Which mount policy produced the bind sets above. Without this a
        # reduced manifest reads as a legitimate boundary rather than as a
        # worker that never found the fleet config.
        "config_source": config_source,
        "config_is_vendored_default": is_vendored_default(config_source),
    }


def unreachable_notes(cmd: str, manifest: dict) -> list[str]:
    """KP3 — cheap pre-flight: flag home-dir absolute paths the task references that
    are not mounted in the sandbox, so a silent empty result is annotated
    ('note: ~/.claude not mounted') rather than read as a real absence (S3/S5)."""
    if manifest.get("engine") != "bwrap":
        return []
    home = str(Path.home())
    bound = (
        manifest.get("bound_rw", [])
        + manifest.get("bound_ro", [])
        + manifest.get("tmpfs", [])
    )
    notes: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"(?<![\w])(" + re.escape(home) + r"/[\w.\-/]+)", cmd):
        path = m.group(1).rstrip("/.,;:)\"'")
        if path in seen:
            continue
        seen.add(path)
        if not any(path == b or path.startswith(b.rstrip("/") + "/") for b in bound):
            notes.append(f"path not mounted in sandbox: {path}")
    return notes


# Matches a standalone `rtk` command token (not part of another word or path)
# so a rewritten command's `rtk <subcommand>` segments can be repointed at our
# vetted binary regardless of its on-disk filename or PATH.
_RTK_TOKEN_RE = re.compile(r"(?<![\w./-])rtk(?=\s)")


def _rtk_rewrite(cmd: str, config: dict) -> str:
    """Rewrite `cmd` through the vetted rtk-plus binary for output-token
    compression, when enabled in kart-sandbox.json's rtk_compress block.
    Fails open (returns cmd unchanged) on any error, missing binary, or when
    rtk itself declines to rewrite — never blocks execution."""
    rtk_cfg = (config or {}).get("rtk_compress") or {}
    if not rtk_cfg.get("enabled"):
        return cmd
    binary = os.path.expanduser(rtk_cfg.get("binary", "~/.willow/bin/rtk-plus"))
    if not os.path.isfile(binary):
        return cmd
    try:
        result = subprocess.run(
            [binary, "rewrite", cmd],
            capture_output=True,
            text=True,
            timeout=2,
            env={"PATH": os.environ.get("PATH", ""), "RTK_TELEMETRY_DISABLED": "1"},
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return cmd
    if result.returncode != 0:
        return cmd
    rewritten = result.stdout.strip()
    if not rewritten or rewritten == cmd:
        return cmd
    return _RTK_TOKEN_RE.sub(binary, rewritten)


# ── resource caps: memory + PID limits on the sandboxed task ─────────────────
# bwrap isolates namespaces and a wall-clock timeout bounds duration, but neither
# caps memory or PID count. A memory hog (arbitrary code — the static scanner
# cannot detect allocation) or any novel resource bomb can therefore degrade the
# host until the timeout fires. This caps the task's address space and process
# count, inherited across bwrap's fork/exec into the sandbox.
#
# Two mechanisms, best-first:
#   1. cgroup v2 leaf under an operator-delegated parent (KART_CGROUP_PARENT) —
#      counts real RSS and enforces a per-tree PID cap. cgroup v2's "no internal
#      processes" rule means we cannot carve a child out of our own cgroup, so
#      this needs an explicitly delegated, controller-enabled, empty parent.
#   2. Task-scoped POSIX rlimits via prlimit/ulimit *inside* the sandbox command
#      (post-namespace), not host preexec on bwrap. Default fallback applies
#      RLIMIT_NPROC only; RLIMIT_AS is opt-in (KART_RLIMIT_USE_AS=1) because it
#      caps virtual address space and breaks large-VA runtimes.
# Greenfield: `kartikeya setup-cgroup` provisions kart.slice (Delegate=memory pids).
# Off switch: WILLOW_KART_NO_RLIMIT=1 (explicit escape hatch, not the remedy).
_MEM_MAX_DEFAULT = "2G"
_PIDS_MAX_DEFAULT = 512


def _parse_size(s: str) -> int | None:
    s = (s or "").strip().upper()
    if not s:
        return None
    mult = 1
    if s and s[-1] in "KMGT":
        mult = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}[s[-1]]
        s = s[:-1]
    try:
        return int(float(s) * mult)
    except ValueError:
        return None


def resource_caps_enabled() -> bool:
    return os.environ.get("WILLOW_KART_NO_RLIMIT", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    )


def _resource_limits() -> dict | None:
    if not resource_caps_enabled():
        return None
    limits: dict = {}
    mem = _parse_size(os.environ.get("KART_MEM_MAX", _MEM_MAX_DEFAULT))
    if mem and mem > 0:
        limits["mem"] = mem
    try:
        pids = int(os.environ.get("KART_PIDS_MAX", _PIDS_MAX_DEFAULT))
    except ValueError:
        pids = _PIDS_MAX_DEFAULT
    if pids and pids > 0:
        limits["pids"] = pids
    return limits or None


def rlimit_use_as() -> bool:
    """Opt-in RLIMIT_AS for rlimit-only installs (breaks large-VA workloads)."""
    return os.environ.get("KART_RLIMIT_USE_AS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def wrap_task_with_rlimits(cmd: str, limits: dict) -> str:
    """Apply resource limits to the task inside the sandbox, not to bwrap setup."""
    prlimit = shutil.which("prlimit")
    if prlimit:
        args = [prlimit]
        if "pids" in limits:
            args.append(f"--nproc={int(limits['pids'])}")
        if "mem" in limits and rlimit_use_as():
            args.append(f"--as={int(limits['mem'])}")
        if len(args) == 1:
            return cmd
        args.extend(["bash", "-c", cmd])
        return " ".join(shlex.quote(part) for part in args)

    lines: list[str] = []
    if "pids" in limits:
        lines.append(f"ulimit -u {int(limits['pids'])}")
    if "mem" in limits and rlimit_use_as():
        kb = max(1, int(limits["mem"]) // 1024)
        lines.append(f"ulimit -v {kb}")
    if not lines:
        return cmd
    lines.append(cmd)
    return "; ".join(lines)


def _try_make_cgroup(limits: dict) -> str | None:
    """Create a limited cgroup v2 leaf under a delegated parent, or None."""
    parent = cgroup_setup.resolve_cgroup_parent()
    if not parent:
        return None
    try:
        with open(os.path.join(parent, "cgroup.controllers")) as f:
            controllers = set(f.read().split())
        if not ({"memory", "pids"} <= controllers):
            return None
        leaf = os.path.join(
            parent, f"kart-{os.getpid()}-{int(time.time() * 1000) % 100000}"
        )
        os.mkdir(leaf)
        if "mem" in limits:
            with open(os.path.join(leaf, "memory.max"), "w") as f:
                f.write(str(limits["mem"]))
        if "pids" in limits:
            with open(os.path.join(leaf, "pids.max"), "w") as f:
                f.write(str(limits["pids"]))
        return leaf
    except OSError:
        return None


def _limits_context(limits: dict):
    """Return (preexec_fn, cleanup_fn, mode).

    cgroup: preexec joins the bwrap child to a leaf cgroup (host-side).
    rlimit: no preexec — limits are applied inside the sandbox via
    wrap_task_with_rlimits() so bwrap setup is not capped.
    """
    leaf = _try_make_cgroup(limits)
    if leaf:

        def _preexec_cgroup() -> None:
            try:
                with open(os.path.join(leaf, "cgroup.procs"), "w") as f:
                    f.write(str(os.getpid()))
            except OSError:
                pass

        def _cleanup_cgroup() -> None:
            try:
                os.rmdir(leaf)
            except OSError:
                pass

        return _preexec_cgroup, _cleanup_cgroup, "cgroup"

    return None, None, "rlimit"


def run_shell(
    cmd: str,
    *,
    timeout: int = 120,
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    """
    Execute one shell command via bash -c (inside bwrap when enabled).
    Returns {returncode, stdout, stderr, elapsed_s, sandbox: bwrap|plain}.
    """
    started = time.time()
    run_env = kart_env(
        allow_net=allow_net, allow_localhost=allow_localhost, allow_db=allow_db
    )
    if env:
        run_env.update(env)
    if cwd:
        run_env["PWD"] = cwd

    if not cmd.strip():
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "empty command",
            "elapsed_s": 0.0,
            "sandbox": "none",
        }

    original_cmd = cmd
    cmd = _rtk_rewrite(cmd, load_sandbox_config())
    rtk_rewritten = cmd != original_cmd

    limits = _resource_limits()
    preexec_fn = cleanup = None
    resource_mode = "none"
    if limits:
        preexec_fn, cleanup, resource_mode = _limits_context(limits)
        if resource_mode == "rlimit":
            cmd = wrap_task_with_rlimits(cmd, limits)

    # Use bash -c so shell operators (&&, |, $(), redirects) work correctly.
    bash = _sandbox_bash()
    argv = [bash, "-c", cmd]
    sandbox = "plain"
    pass_fds: tuple[int, ...] = ()
    status_file = None
    if use_bwrap():
        prefix = build_bwrap_argv(
            allow_net=allow_net, allow_localhost=allow_localhost, allow_db=allow_db
        )
        # KP3/S15: --json-status-fd lets us tell a sandbox-SETUP failure (mount/ns
        # error, bwrap exits before exec) from a COMMAND failure. bwrap writes
        # {"child-pid":N} once the child execs; its absence on a non-zero exit
        # means setup failed. Feature-gated so an old bwrap is unaffected.
        if _bwrap_supports_json_status():
            status_file = tempfile.TemporaryFile(mode="w+")  # noqa: SIM115 — closed in the finally below; the fd must outlive this block
            fd = status_file.fileno()
            prefix = [prefix[0], "--json-status-fd", str(fd)] + prefix[1:]
            pass_fds = (fd,)
        full = prefix + ["--", bash, "-c", cmd]
        sandbox = "bwrap"
    else:
        full = argv

    def _setup_state() -> str | None:
        if status_file is None:
            return None
        try:
            status_file.seek(0)
            txt = status_file.read()
        except (OSError, ValueError):
            return None
        return "ok" if '"child-pid"' in txt else "failed"

    try:
        proc = subprocess.run(
            full,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=run_env,
            cwd=cwd,
            pass_fds=pass_fds,
            preexec_fn=preexec_fn,
            check=False,
        )
        elapsed = round(time.time() - started, 2)
        setup = _setup_state()
        out = {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_s": elapsed,
            "sandbox": sandbox,
        }
        if resource_mode != "none":
            out["resource_limit"] = resource_mode
        if rtk_rewritten:
            out["rtk_rewritten"] = True
        if setup is not None:
            out["sandbox_setup"] = setup
            if setup == "failed":
                out["error"] = "sandbox_setup_failed"
        return out
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": (e.stderr or "") if isinstance(e.stderr, str) else "",
            "elapsed_s": round(time.time() - started, 2),
            "error": "timeout",
            "sandbox": sandbox,
        }
    except Exception as e:  # noqa: BLE001 — every failure to launch becomes a result row, never an exception out of the runner
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "elapsed_s": round(time.time() - started, 2),
            "error": str(e),
            "sandbox": sandbox,
        }
    finally:
        if cleanup is not None:
            cleanup()
        if status_file is not None:
            with contextlib.suppress(Exception):
                status_file.close()


def clip_output(text: str, limit: int) -> str:
    """Clip long output keeping head and tail, with an explicit marker.

    Replaces the old silent tail-keep slice ([-N:]) that dropped the
    beginning of output with no indication anything was missing.
    """
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    dropped = len(text) - head - tail
    return f"{text[:head]}\n…[kart: {dropped} chars clipped]…\n{text[-tail:]}"


def run_shell_result_for_task(
    cmd: str,
    *,
    timeout: int = 120,
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
) -> tuple[str, dict]:
    """Normalize run_shell output for pg.task_complete(status, result)."""
    raw = run_shell(
        cmd,
        timeout=timeout,
        allow_net=allow_net,
        allow_localhost=allow_localhost,
        allow_db=allow_db,
    )
    status = (
        "completed"
        if raw.get("returncode") == 0 and raw.get("error") != "timeout"
        else "failed"
    )
    result = {
        "returncode": raw.get("returncode"),
        "stdout": clip_output((raw.get("stdout") or "").strip(), 8000),
        "stderr": clip_output((raw.get("stderr") or "").strip(), 1500),
        "elapsed_s": raw.get("elapsed_s"),
        "sandbox": raw.get("sandbox"),
    }
    if raw.get("sandbox_setup"):
        result["sandbox_setup"] = raw["sandbox_setup"]
    if raw.get("error"):
        result["error"] = raw["error"]
    # Uniform error capture: every failed task carries a non-empty, human-readable
    # `error`. A command that fails by exit code with empty stderr (e.g. grep
    # no-match, a silent non-zero step in an `&&` chain) would otherwise leave the
    # failure causeless and untriageable. Full stdout/stderr stay in their fields.
    if status == "failed" and not result.get("error"):
        rc = result["returncode"]
        last_err = result["stderr"].splitlines()[-1].strip() if result["stderr"] else ""
        last_out = result["stdout"].splitlines()[-1].strip() if result["stdout"] else ""
        if last_err:
            result["error"] = last_err[:200]
        elif last_out:
            result["error"] = f"exited {rc}: {last_out[:180]}"
        else:
            result["error"] = f"exited {rc} with no output"
    # KP7/S10: unclipped output rides along under private keys so the task-level
    # caller (which knows the task_id) can write a durable log artifact. Popped
    # by execute_task_row before the result reaches task_complete.
    result["_full_stdout"] = raw.get("stdout") or ""
    result["_full_stderr"] = raw.get("stderr") or ""
    # KP3: attach the boundary manifest + any unreachable-path notes so a caller can
    # tell "this is empty" from "I couldn't see this." Best-effort — never fail the
    # task over manifest construction.
    with contextlib.suppress(Exception):
        manifest = sandbox_manifest(
            allow_net=allow_net,
            allow_localhost=allow_localhost,
            allow_db=allow_db,
            root=None,
        )
        notes = unreachable_notes(cmd, manifest)
        if notes:
            manifest["notes"] = notes
        result["sandbox_manifest"] = manifest
    return status, result


# ── KP7/S10 — durable per-task log artifacts ──────────────────────────────────

KART_LOG_RETENTION = 200


def _kart_logs_root() -> Path:
    from .home import willow_home

    return Path(willow_home()) / ".kart-logs"


def _prune_task_logs(root: Path, keep: int = KART_LOG_RETENTION) -> None:
    """Keep the newest `keep` task-log dirs; remove the rest. Best-effort."""
    with contextlib.suppress(Exception):
        dirs = sorted(
            (d for d in root.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        for stale in dirs[keep:]:
            shutil.rmtree(stale, ignore_errors=True)


def write_task_log(
    task_id: str,
    cmd: str,
    status: str,
    result: dict,
    *,
    full_stdout: str | None = None,
    full_stderr: str | None = None,
) -> str | None:
    """Write a durable forensic artifact for one task (KP7/S10).

    $WILLOW_HOME/.kart-logs/<task_id>/{meta.json, stdout.log, stderr.log}.
    meta.json carries the env *key list* only — values may hold credentials
    and must never land in a log file. Never raises; returns the dir path or
    None if the write failed.
    """
    try:
        safe_id = (
            "".join(c for c in str(task_id) if c.isalnum() or c in "_-") or "unknown"
        )
        log_dir = _kart_logs_root() / safe_id
        log_dir.mkdir(parents=True, exist_ok=True)

        manifest = result.get("sandbox_manifest") or {}
        env = kart_env(
            allow_net=bool(manifest.get("allow_net")),
            allow_localhost=bool(manifest.get("allow_localhost")),
            allow_db=bool(manifest.get("allow_db")),
        )
        meta = {
            "task_id": str(task_id),
            "cmd": cmd[:4000],
            "status": status,
            "returncode": result.get("returncode"),
            "error": result.get("error"),
            "elapsed_s": result.get("elapsed_s"),
            "sandbox": result.get("sandbox"),
            "sandbox_setup": result.get("sandbox_setup"),
            "allow_net": manifest.get("allow_net"),
            "allow_localhost": manifest.get("allow_localhost"),
            "allow_db": manifest.get("allow_db"),
            "network_mode": manifest.get("network_mode"),
            "cwd": os.getcwd(),
            "written_at": _dt.datetime.now().astimezone().isoformat(),
            "bwrap_argv_summary": {
                "bound_ro": manifest.get("bound_ro"),
                "bound_rw": manifest.get("bound_rw"),
                "tmpfs": manifest.get("tmpfs"),
                "path_dirs": manifest.get("path_dirs"),
                "notes": manifest.get("notes"),
            },
            "env_keys": sorted(env.keys()),
        }
        (log_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, default=str), encoding="utf-8"
        )
        (log_dir / "stdout.log").write_text(
            full_stdout if full_stdout is not None else (result.get("stdout") or ""),
            encoding="utf-8",
        )
        (log_dir / "stderr.log").write_text(
            full_stderr if full_stderr is not None else (result.get("stderr") or ""),
            encoding="utf-8",
        )
        _prune_task_logs(log_dir.parent)
        return str(log_dir)
    except Exception:  # noqa: BLE001 — a log that cannot be written is None; it never fails the task it describes
        return None
