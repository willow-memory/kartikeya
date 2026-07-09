"""
task_scan.py — hybrid security scan for task bodies.

Contract (hybrid lane):
  - Common automation verbs (git, pytest, gh, python3 -m pytest, ruff, mypy, …)
    skip the pattern scan when the command matches the allowlist — normal work
    is not blocked.
  - All other shell fragments get full scan_bash at SEV_HIGH+.
  - script_body (Python) is scanned for content-injection patterns.
  - Exfiltration / secret access / obfuscation always block at SEV_HIGH+ even
    when an allowed verb is present on another fragment.
  - Optional hook-tamper guard: a host may register source paths that must not
    be read/written via task text (e.g. a fleet's hook runner). Empty by
    default — a standalone install protects nothing extra. Configure via
    `HOOK_GUARD_FRAGMENTS` (module global) or the `KART_HOOK_GUARD_PATHS` env
    var (comma/`os.pathsep`-separated). Maintenance bypass: WILLOW_HOOK_MAINTENANCE=1.

Disable the whole scan: WILLOW_KART_SCAN=0
"""
from __future__ import annotations

import os
import re

from .security_scan import (
    SEV_CRITICAL,
    SEV_HIGH,
    ScanIssue,
    scan_bash,
    scan_write,
    worst,
)

_ALLOW_NET = "# allow_net"
_ALLOW_LOCALHOST = "# allow_localhost"
_NETWORK_DIRECTIVES = frozenset({_ALLOW_NET, _ALLOW_LOCALHOST})
_FENCE_RE = re.compile(r"```(bash|sh|python3?|python)?\n?(.*?)```", re.DOTALL)
_CHAIN_SPLIT = re.compile(r"\s*&&\s*|\s*\|\|\s*")

# Safe command shapes — matched against whole fragment (after strip). These are
# universal automation verbs, not fleet-specific; a host may extend the set.
_FLEET_ALLOWED: tuple[str, ...] = (
    r"^pytest\b",
    r"^py\.test\b",
    r"^gh\s+(pr|issue|run|api|repo)\b",
    r"^git\s+(status|log|diff|show|fetch|pull|push|add|commit|branch|checkout|"
    r"worktree|rev-parse|merge|rebase|stash|tag|remote|clone|ls-files|grep)\b",
    r"^python3?\s+(-m\s+)?(pytest|ruff|mypy)\b",
    r"^ruff\b",
    r"^mypy\b",
    r"^make\b",
    r"^npm\s+(test|run|ci)\b",
    r"^echo\b",
    r"^cd\s+\S+\s+&&\s+(git|pytest|gh|ruff|mypy)\b",
    r"^\$\{WILLOW_PYTHON:-python3\}\s+",
)

_ALWAYS_BLOCK_CATEGORIES = frozenset({"exfiltration", "obfuscation", "secret_access",
                                      "resource_exhaustion"})

# Host-configurable source paths that must not be read/written via task text.
# Empty by default (standalone). A fleet host sets this to protect its hook
# runner / settings files. Merged with $KART_HOOK_GUARD_PATHS at call time.
HOOK_GUARD_FRAGMENTS: tuple[str, ...] = ()


def _hook_guard_fragments() -> tuple[str, ...]:
    env = os.environ.get("KART_HOOK_GUARD_PATHS", "")
    extra: list[str] = []
    if env.strip():
        parts = env.replace(os.pathsep, ",").split(",")
        extra = [p.strip() for p in parts if p.strip()]
    return tuple(HOOK_GUARD_FRAGMENTS) + tuple(extra)


def kart_scan_enabled() -> bool:
    return os.environ.get("WILLOW_KART_SCAN", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )


def _fleet_allowed(fragment: str) -> bool:
    text = fragment.strip()
    if not text:
        return True
    return any(re.search(pat, text, re.IGNORECASE | re.MULTILINE) for pat in _FLEET_ALLOWED)


def _blocking_issues(issues: list[ScanIssue], *, fleet: bool) -> list[ScanIssue]:
    out: list[ScanIssue] = []
    for issue in issues:
        if issue.severity >= SEV_CRITICAL:
            out.append(issue)
        elif issue.category in _ALWAYS_BLOCK_CATEGORIES and issue.severity >= SEV_HIGH:
            out.append(issue)
        elif not fleet and issue.severity >= SEV_HIGH:
            out.append(issue)
    return out


def _scan_shell_fragment(fragment: str) -> ScanIssue | None:
    text = fragment.strip()
    if not text:
        return None
    fleet = _fleet_allowed(text)
    issues = _blocking_issues(scan_bash(text), fleet=fleet)
    return worst(issues)


def _shell_fragments_from_task(task_text: str) -> list[str]:
    lines = [
        ln
        for ln in (task_text or "").splitlines()
        if ln.strip() and ln.strip() not in _NETWORK_DIRECTIVES
    ]
    body = "\n".join(lines).strip()
    if not body:
        return []

    fragments: list[str] = []
    pos = 0
    for match in _FENCE_RE.finditer(body):
        before = body[pos : match.start()].strip()
        if before:
            fragments.extend(_expand_shell_body(before))
        inner = (match.group(2) or "").strip()
        if inner:
            fragments.extend(_expand_shell_body(inner))
        pos = match.end()
    tail = body[pos:].strip()
    if tail:
        fragments.extend(_expand_shell_body(tail))
    if not fragments:
        fragments.extend(_expand_shell_body(body))
    return [f.strip() for f in fragments if f.strip()]


def _expand_shell_body(body: str) -> list[str]:
    """Split compound shell; keep heredoc / multiline blocks as one unit."""
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if len(lines) == 1:
        return _CHAIN_SPLIT.split(lines[0])
    if len(lines) > 1 and not any("<<" in ln for ln in lines):
        return _CHAIN_SPLIT.split(lines[0])
    return [body]


def _issue_payload(issue: ScanIssue, *, where: str) -> dict:
    return {
        "error": (
            f"[KART-SECURITY] {issue.message} "
            f"(category: {issue.category}, severity: {issue.severity}, where: {where})"
        ),
        "kart_scan": {
            "category": issue.category,
            "severity": issue.severity,
            "message": issue.message,
            "where": where,
        },
    }


def _hook_tamper_fragment(text: str) -> str | None:
    if not text:
        return None
    return next((frag for frag in _hook_guard_fragments() if frag in text), None)


def check_hook_tamper(task_text: str = "", *, script_body: str = "") -> dict | None:
    """Block task/script_body text that reads or writes a host-protected source
    path (see HOOK_GUARD_FRAGMENTS). No-op unless the host registered paths.
    Maintenance bypass: WILLOW_HOOK_MAINTENANCE=1.
    """
    if os.environ.get("WILLOW_HOOK_MAINTENANCE"):
        return None
    frag = _hook_tamper_fragment(task_text) or _hook_tamper_fragment(script_body)
    if not frag:
        return None
    where = "task" if _hook_tamper_fragment(task_text) else "script_body"
    return {
        "error": (
            f"[KART-SECURITY] Protected source ({frag}) cannot be read or written "
            "via task/script_body (prevents bypass discovery and silent "
            "tampering). Maintainers: set WILLOW_HOOK_MAINTENANCE=1 for edits."
        ),
        "kart_scan": {
            "category": "hook_tamper",
            "severity": SEV_CRITICAL,
            "message": f"Protected source reference: {frag}",
            "where": where,
        },
    }


def check_kart_task(task_text: str = "", *, script_body: str = "") -> dict | None:
    """
    Return an error dict if the task should not run/queue, else None.
    """
    if not kart_scan_enabled():
        return None

    tamper = check_hook_tamper(task_text, script_body=script_body)
    if tamper:
        return tamper

    if script_body.strip():
        issues = scan_write("", script_body)
        bad = worst([i for i in issues if i.severity >= SEV_HIGH])
        if bad:
            return _issue_payload(bad, where="script_body")

    for fragment in _shell_fragments_from_task(task_text or ""):
        bad = _scan_shell_fragment(fragment)
        if bad:
            return _issue_payload(bad, where="task")

    return None
