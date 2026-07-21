"""
kart_sandbox.py — unified bwrap sandbox for Kart execution paths.

Used by: core/kart_execute.py (daemon + poll), sap kart_task_run fallback

Mount policy: willow/fylgja/config/kart-sandbox.json (+ dynamic worktree discovery).
"""
from __future__ import annotations

import datetime as _dt
import functools
import json
import logging
import os
import re
import shutil
import subprocess
import sysconfig
import tempfile
import time
from pathlib import Path

try:
    import resource as _resource  # POSIX only
except ImportError:  # pragma: no cover - non-POSIX
    _resource = None

_log = logging.getLogger("kart.sandbox")

_ALLOW_NET_DIRECTIVE = "# allow_net"
_ALLOW_LOCALHOST_DIRECTIVE = "# allow_localhost"
_DEFAULT_CONFIG = Path(__file__).resolve().parent / "data" / "kart-sandbox.json"

# Credential-bearing env prefixes (GAP-B). Only passed into the sandbox when a task
# opts into network (allow_net) — a no-network task receives zero credentials.
# Overridable via the "credential_env_prefixes" key in kart-sandbox.json.
_DEFAULT_CREDENTIAL_PREFIXES = (
    "TWINE_", "PYPI_", "ANTHROPIC_", "OPENROUTER_", "GROQ_", "GITHUB_",
    "NPM_", "HUGGINGFACE_", "HF_", "OPENAI_", "AWS_", "DISCORD_",
)


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def use_bwrap() -> bool:
    """Whether Kart intends bubblewrap sandboxing (not whether bwrap is installed)."""
    if os.environ.get("WILLOW_KART_NO_BWRAP", "").strip().lower() in ("1", "true", "yes"):
        return False
    return True


@functools.lru_cache(maxsize=1)
def _bwrap_supports_json_status() -> bool:
    """Whether the host bwrap understands --json-status-fd (KP3/S15)."""
    try:
        h = subprocess.run(["bwrap", "--help"], capture_output=True, text=True, timeout=5)
        return "--json-status-fd" in (h.stdout + h.stderr)
    except Exception:
        return False


def _is_fleet_repo(base: Path) -> bool:
    return (base / "core" / "kart_sandbox.py").is_file() or (base / "core" / "pg_bridge.py").is_file()


def _is_willow_mcp_repo(base: Path) -> bool:
    """True when ``base`` looks like a willow-mcp checkout (not willow-2.0 fleet)."""
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
      4. Legacy fleet checkout ``~/github/willow-2.0``

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


def _template_ctx(root: Path | None) -> dict[str, str]:
    home = str(Path.home())
    repo = str(root or willow_repo_root() or Path.cwd())
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return {
        "HOME": home,
        "WILLOW_ROOT": repo,
        "WILLOW_GROVE_ROOT": os.environ.get("WILLOW_GROVE_ROOT", str(Path(home) / "github" / "safe-app-willow-grove")),
        "WILLOW_SAFE_ROOT": os.environ.get("WILLOW_SAFE_ROOT", str(Path(home) / "SAFE" / "Applications")),
        "WILLOW_AGENTS_ROOT": os.environ.get("WILLOW_AGENTS_ROOT", str(Path(home) / "SAFE" / "Agents")),
        "XDG_RUNTIME_DIR": xdg_runtime,
    }


def _render(path_template: str, ctx: dict[str, str]) -> str:
    out = path_template
    for key, val in ctx.items():
        out = out.replace(f"{{{{{key}}}}}", val)
    return os.path.expanduser(out)


def load_sandbox_config(root: Path | None = None) -> dict:
    """Resolve the bwrap mount policy.

    Order: ``$KART_SANDBOX_CONFIG`` → ``$WILLOW_HOME/kart-sandbox.json`` →
    the vendored product-neutral default (`data/kart-sandbox.json`). The
    vendored default always exists, so a standalone install is never left
    without a mount policy.
    """
    candidates: list[Path] = []
    env = os.environ.get("KART_SANDBOX_CONFIG", "").strip()
    if env:
        candidates.append(Path(env).expanduser())
    try:
        from .home import willow_home
        candidates.append(willow_home(root) / "kart-sandbox.json")
    except Exception:
        pass
    candidates.append(_DEFAULT_CONFIG)
    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
    return {}


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

    mounts: dict[str, tuple[Path, Path, bool]] = {}

    def _add(host: Path, read_only: bool, *, required: bool = False) -> None:
        try:
            if not host.exists():
                # KP6a (S9): a required bind that is missing is usually config rot —
                # surface it. bind_try entries are optional, so they stay silent.
                if required:
                    _log.warning("kart-sandbox: required bind target missing, skipped: %s", host)
                return
            resolved = host.resolve()
        except OSError:
            return
        key = str(resolved)
        ro = read_only
        if key in mounts:
            existing = mounts[key]
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
    except Exception:
        repo_venv = (repo / ".venv-dev") if repo else None
        if repo_venv and repo_venv.is_dir():
            _add(repo_venv, True)
        home_venv = Path.home() / ".willow-venv"
        if home_venv.is_dir() and (not repo_venv or home_venv.resolve() != repo_venv.resolve()):
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
    also under config/), consent.json (legacy mirror).
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
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/dev/shm",
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

    # psycopg2's default socket dir is /var/run/postgresql. collect_bind_mounts
    # resolves the /var/run → /run symlink, so the socket ends up mounted at
    # /run/postgresql but never at /var/run/postgresql. Add a direct bind at
    # the original unresolved path so pg_bridge finds the socket without
    # needing PGHOST set explicitly.
    _pg_sock = Path("/var/run/postgresql")
    if _pg_sock.exists():
        args += ["--bind", str(_pg_sock.resolve()), str(_pg_sock)]

    if allow_net:
        # Credentials are present ONLY on a network-opted task (S1, GAP-B/C).
        # All read-only: a task may use them, never modify or replace them.
        home = Path.home()
        netrc = home / ".netrc"
        if netrc.is_file():
            args += ["--ro-bind", str(netrc), str(netrc)]

        gh_cfg = home / ".config" / "gh"
        if gh_cfg.is_dir():
            args += ["--ro-bind", str(gh_cfg), str(gh_cfg)]

        # ~/.ssh is never bound (S1) — private keys do not enter the sandbox.
        # SSH git auth flows through the agent socket; host-key verification needs
        # only known_hosts (read-only).
        known_hosts = home / ".ssh" / "known_hosts"
        if known_hosts.is_file():
            args += ["--ro-bind", str(known_hosts), str(known_hosts)]
        ssh_sock = os.environ.get("SSH_AUTH_SOCK", "").strip()
        if ssh_sock and Path(ssh_sock).exists():
            # The agent socket is read-write (clients write requests to it), but it
            # exposes no key material — the agent holds the keys out of process.
            args += ["--bind", ssh_sock, ssh_sock]

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


def _sandbox_bash() -> str:
    """Absolute bash path for bwrap exec (merged-usr has no /bin in the sandbox)."""
    for candidate in ("/usr/bin/bash", "/bin/bash"):
        if Path(candidate).is_file():
            return candidate
    return "bash"


def task_allows_network(task_text: str) -> bool:
    return any(line.strip() == _ALLOW_NET_DIRECTIVE for line in task_text.splitlines())


def task_allows_localhost(task_text: str) -> bool:
    return any(line.strip() == _ALLOW_LOCALHOST_DIRECTIVE for line in task_text.splitlines())


def task_requests_shared_network(task_text: str) -> bool:
    """Whether a task asks to share the host network namespace.

    Both directives cross the network isolation boundary. ``allow_localhost``
    does not receive credential environment variables, but it can still reach
    every service listening on the host namespace and therefore requires the
    same attributable per-task authorization as ``allow_net``.
    """
    return task_allows_network(task_text) or task_allows_localhost(task_text)


def parse_task_network(task_text: str) -> tuple[str, bool, bool]:
    """Strip network directives; return (cmd_body, allow_net, allow_localhost)."""
    allow_net = task_allows_network(task_text)
    allow_localhost = (not allow_net) and task_allows_localhost(task_text)
    skip = {_ALLOW_NET_DIRECTIVE, _ALLOW_LOCALHOST_DIRECTIVE}
    lines = [line for line in task_text.splitlines() if line.strip() not in skip]
    return "\n".join(lines).strip(), allow_net, allow_localhost


def _parse_fleet_env_file(path: Path, prefixes: tuple[str, ...]) -> dict[str, str]:
    """Parse a shell KEY=VALUE env file. Skips comments and blank lines.
    Only includes keys matching prefixes. Strips surrounding quotes from values."""
    result: dict[str, str] = {}
    try:
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
    except Exception:
        pass
    return result


def kart_env(
    root: Path | None = None,
    *,
    allow_net: bool = False,
    allow_localhost: bool = False,
) -> dict[str, str]:
    repo = root or willow_repo_root()
    cfg = load_sandbox_config(repo)
    prefixes = tuple(cfg.get("env_prefixes") or ("WILLOW_", "GROVE_", "PG", "POSTGRES", "OLLAMA_", "GIT_", "ANTHROPIC_", "GROQ_"))
    # GAP-B: credential-bearing env vars only reach the sandbox on a network-opted
    # task. A no-network task cannot exfil keys it was never handed.
    cred_prefixes = tuple(cfg.get("credential_env_prefixes") or _DEFAULT_CREDENTIAL_PREFIXES)

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        "PYTHONUNBUFFERED": "1",
        # Marker so code inside bwrap tasks can detect the Kart sandbox context.
        "WILLOW_IN_KART": "1",
        "WILLOW_KART_ALLOW_NET": "1" if allow_net else "0",
        "WILLOW_KART_ALLOW_LOCALHOST": "1" if allow_localhost and not allow_net else "0",
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
    except Exception:
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
        try:
            name = subprocess.check_output(["git", "config", "--global", "user.name"], text=True).strip()
            email = subprocess.check_output(["git", "config", "--global", "user.email"], text=True).strip()
            if name:
                env["GIT_AUTHOR_NAME"] = name
                env["GIT_COMMITTER_NAME"] = name
            if email:
                env["GIT_AUTHOR_EMAIL"] = email
                env["GIT_COMMITTER_EMAIL"] = email
        except Exception:
            pass

    # Inside bwrap, /var/run is not present (collect_bind_mounts resolves the
    # /var/run → /run symlink away). psycopg2 with host=None defaults to
    # /var/run/postgresql, which doesn't exist in the container.
    # Set WILLOW_PG_HOST to the real socket directory so pg_bridge finds it.
    if not env.get("WILLOW_PG_HOST"):
        import glob as _glob
        for _sock in _glob.glob("/run/postgresql/.s.PGSQL.*") + _glob.glob("/tmp/.s.PGSQL.*"):
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

    return env


def sandbox_manifest(
    *,
    allow_net: bool = False,
    allow_localhost: bool = False,
    root: Path | None = None,
) -> dict:
    """KP3 — declare the boundary so a caller can tell 'empty' from 'absent'.

    Reports the roots that ARE mounted (rw vs ro), the tmpfs scratch, the network
    state, and the PATH dirs visible inside the sandbox. This is the read-side cure
    for the audit's defining defect: an unbound path returns empty, identical to a
    real absence, with no signal. The manifest is that signal.
    """
    engine = "bwrap" if use_bwrap() else "plain"
    bound_rw: list[str] = []
    bound_ro: list[str] = []
    try:
        for host, _container, read_only in collect_bind_mounts(root):
            (bound_ro if read_only else bound_rw).append(str(host))
        for trust_root in collect_mcp_trust_ro_overlays(root):
            bound_ro.append(str(trust_root))
    except Exception:
        pass
    path_dirs = kart_env(
        root, allow_net=allow_net, allow_localhost=allow_localhost
    ).get("PATH", "").split(":")
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
        "network_mode": network_mode,
        "bound_rw": sorted(bound_rw),
        "bound_ro": sorted(bound_ro),
        "tmpfs": ["/tmp", "/dev/shm"] if engine == "bwrap" else [],
        "path_dirs": [p for p in path_dirs if p],
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
        )
    except Exception:
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
#   2. POSIX rlimits (RLIMIT_AS, RLIMIT_NPROC) — no root, no delegation, works in
#      a rootless container. RLIMIT_AS caps *virtual* address space (blunter than
#      cgroup RSS accounting), so the default is generous and env-tunable.
# Off switch: WILLOW_KART_NO_RLIMIT=1.
_MEM_MAX_DEFAULT = "2G"
_PIDS_MAX_DEFAULT = 512


def _parse_size(s: str) -> int | None:
    s = (s or "").strip().upper()
    if not s:
        return None
    mult = 1
    if s and s[-1] in "KMGT":
        mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[s[-1]]
        s = s[:-1]
    try:
        return int(float(s) * mult)
    except ValueError:
        return None


def resource_caps_enabled() -> bool:
    return os.environ.get("WILLOW_KART_NO_RLIMIT", "").strip().lower() not in ("1", "true", "yes")


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


def _try_make_cgroup(limits: dict) -> str | None:
    """Create a limited cgroup v2 leaf under KART_CGROUP_PARENT, or None. The
    parent must be a delegated cgroup with memory+pids controllers enabled and no
    internal processes; without one we fall back to rlimits."""
    parent = os.environ.get("KART_CGROUP_PARENT", "").strip()
    if not parent or not os.path.isdir(parent):
        return None
    try:
        with open(os.path.join(parent, "cgroup.controllers")) as f:
            controllers = set(f.read().split())
        if not ({"memory", "pids"} <= controllers):
            return None
        leaf = os.path.join(parent, f"kart-{os.getpid()}-{int(time.time() * 1000) % 100000}")
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
    """Return (preexec_fn, cleanup_fn, mode). preexec runs in the child post-fork
    and is best-effort — a limit that can't be applied must not fail the task."""
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

    if _resource is None:
        return None, None, "none"

    def _preexec_rlimit() -> None:
        if "mem" in limits:
            try:
                _resource.setrlimit(_resource.RLIMIT_AS, (limits["mem"], limits["mem"]))
            except (ValueError, OSError):
                pass
        if "pids" in limits:
            try:
                _resource.setrlimit(_resource.RLIMIT_NPROC, (limits["pids"], limits["pids"]))
            except (ValueError, OSError):
                pass

    return _preexec_rlimit, None, "rlimit"


def run_shell(
    cmd: str,
    *,
    timeout: int = 120,
    allow_net: bool = False,
    allow_localhost: bool = False,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    """
    Execute one shell command via bash -c (inside bwrap when enabled).
    Returns {returncode, stdout, stderr, elapsed_s, sandbox: bwrap|plain}.
    """
    started = time.time()
    run_env = kart_env(allow_net=allow_net, allow_localhost=allow_localhost)
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

    # Use bash -c so shell operators (&&, |, $(), redirects) work correctly.
    bash = _sandbox_bash()
    argv = [bash, "-c", cmd]
    sandbox = "plain"
    pass_fds: tuple[int, ...] = ()
    status_file = None
    if use_bwrap():
        prefix = build_bwrap_argv(
            allow_net=allow_net, allow_localhost=allow_localhost
        )
        # KP3/S15: --json-status-fd lets us tell a sandbox-SETUP failure (mount/ns
        # error, bwrap exits before exec) from a COMMAND failure. bwrap writes
        # {"child-pid":N} once the child execs; its absence on a non-zero exit
        # means setup failed. Feature-gated so an old bwrap is unaffected.
        if _bwrap_supports_json_status():
            status_file = tempfile.TemporaryFile(mode="w+")
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
        except Exception:
            return None
        return "ok" if '"child-pid"' in txt else "failed"

    limits = _resource_limits()
    preexec_fn = cleanup = None
    resource_mode = "none"
    if limits:
        preexec_fn, cleanup, resource_mode = _limits_context(limits)

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
    except Exception as e:
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
            try:
                status_file.close()
            except Exception:
                pass


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
) -> tuple[str, dict]:
    """Normalize run_shell output for pg.task_complete(status, result)."""
    raw = run_shell(
        cmd,
        timeout=timeout,
        allow_net=allow_net,
        allow_localhost=allow_localhost,
    )
    status = "completed" if raw.get("returncode") == 0 and raw.get("error") != "timeout" else "failed"
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
    try:
        manifest = sandbox_manifest(
            allow_net=allow_net,
            allow_localhost=allow_localhost,
            root=None,
        )
        notes = unreachable_notes(cmd, manifest)
        if notes:
            manifest["notes"] = notes
        result["sandbox_manifest"] = manifest
    except Exception:
        pass
    return status, result


# ── KP7/S10 — durable per-task log artifacts ──────────────────────────────────

KART_LOG_RETENTION = 200


def _kart_logs_root() -> Path:
    from .home import willow_home
    return Path(willow_home()) / ".kart-logs"


def _prune_task_logs(root: Path, keep: int = KART_LOG_RETENTION) -> None:
    """Keep the newest `keep` task-log dirs; remove the rest. Best-effort."""
    try:
        dirs = sorted(
            (d for d in root.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        for stale in dirs[keep:]:
            shutil.rmtree(stale, ignore_errors=True)
    except Exception:
        pass


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
        safe_id = "".join(c for c in str(task_id) if c.isalnum() or c in "_-") or "unknown"
        log_dir = _kart_logs_root() / safe_id
        log_dir.mkdir(parents=True, exist_ok=True)

        manifest = result.get("sandbox_manifest") or {}
        env = kart_env(
            allow_net=bool(manifest.get("allow_net")),
            allow_localhost=bool(manifest.get("allow_localhost")),
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
    except Exception:
        return None
