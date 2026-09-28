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

import contextlib
import os
import posixpath
import re
import shlex

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
_ALLOW_DB = "# allow_db"
_NETWORK_DIRECTIVES = frozenset({_ALLOW_NET, _ALLOW_LOCALHOST, _ALLOW_DB})
_FENCE_RE = re.compile(r"```(bash|sh|python3?|python)?\n?(.*?)```", re.DOTALL)
_CHAIN_SPLIT = re.compile(r"\s*&&\s*|\s*\|\|\s*")

# Safe command shapes — matched against whole fragment (after strip). These are
# universal automation verbs, not fleet-specific; a host may extend the set.
_FLEET_ALLOWED: tuple[str, ...] = (
    r"^pytest\b",
    r"^py\.test\b",
    r"^gh\s+(pr|issue|run|api|repo)\b",
    (
        r"^git\s+(status|log|diff|show|fetch|pull|push|add|commit|branch|checkout|"
        r"worktree|rev-parse|merge|rebase|stash|tag|remote|clone|ls-files|grep)\b"
    ),
    r"^python3?\s+(-m\s+)?(pytest|ruff|mypy)\b",
    r"^ruff\b",
    r"^mypy\b",
    r"^make\b",
    r"^npm\s+(test|run|ci)\b",
    r"^echo\b",
    r"^cd\s+\S+\s+&&\s+(git|pytest|gh|ruff|mypy)\b",
    r"^\$\{WILLOW_PYTHON:-python3\}\s+",
)

_ALWAYS_BLOCK_CATEGORIES = frozenset(
    {"exfiltration", "obfuscation", "secret_access", "resource_exhaustion"}
)

# systemd user/system manager verbs are never Kart-eligible (SOIL
# kart-vs-operator-systemctl-broker-2026-09-23): no user D-Bus in bwrap, and
# mounting one would punch a hole into host systemd. Broker path:
# unit_install_execute / unit_reload_execute (+ willow-mcp-unit-ops helper).
_SYSTEMD_MANAGER_RE = re.compile(
    r"(?:^|[\s;&|`(])(?:/bin/|/usr/bin/)?(?:systemctl|busctl)\b",
    re.IGNORECASE,
)
_SYSTEMD_MANAGER_REFUSAL = (
    "[KART-SECURITY] systemctl/busctl are never Kart-eligible "
    "(kart-vs-operator-surface). Use unit_install_execute or "
    "unit_reload_execute on the willow-mcp broker under a unit.install / "
    "unit.reload envelope; enable without a desk bus goes through "
    "willow-mcp-unit-ops."
)

# Git verbs that rewrite the WORKING TREE. Under a read-only checkout with a
# writable .git (the fleet's WILLOW_ROOT shape since 2026-09-09) these
# half-succeed: refs and HEAD move, files cannot, and git degrades to "carry
# the local changes", leaving the checkout on a new branch with another
# branch's content staged dirty — measured 2026-09-09, gap 5fd840cb5000.
# Commits, adds and reads need only .git and stay allowed. Branch creation at
# HEAD (`checkout -b NAME`, `switch -c NAME`, any flag order) touches no file
# and passes; the same with a start point, or any bare checkout/switch of a
# ref, is a rewrite.
#
# The refusal is judged PER DIRECTORY, not policy-wide (gap bd6284e3496d):
# the first cut asked only "does the policy bind WILLOW_ROOT read-only" and so
# refused `git checkout -- file` inside a checkout that was bound read-write by
# a parent entry, where the half-write cannot happen. Now the directory the
# verb runs in — a leading `cd X` in the same chain, else the task's working
# directory — is resolved against the mount policy, and only a read-only bind
# with no writable child over it refuses.
_TREE_WRITE_VERBS = frozenset({"merge", "rebase", "restore", "clean"})
_RESET_TREE_FLAGS = frozenset({"--hard", "--merge", "--keep"})
_BRANCH_CREATE_FLAGS = frozenset({"-b", "-B", "-c", "-C"})
_CD_RE = re.compile(r"^cd\s+(\S+)\s*$")


def _tree_rewrite_verb(fragment: str) -> bool:
    """Whether one shell fragment is a git verb that rewrites the working tree."""
    try:
        toks = shlex.split(fragment.strip())
    except ValueError:
        toks = fragment.strip().split()
    if len(toks) < 2 or toks[0] != "git":
        return False
    verb, rest = toks[1], toks[2:]
    if verb in ("checkout", "switch"):
        for i, t in enumerate(rest):
            if t in _BRANCH_CREATE_FLAGS:
                # `-b NAME` at HEAD creates a ref and touches no file. A start
                # point after the name (`-b NAME origin/x`) checks that ref out.
                positional_after = [x for x in rest[i + 2 :] if not x.startswith("-")]
                return bool(positional_after)
        return True
    if verb in _TREE_WRITE_VERBS:
        return True
    if verb == "reset":
        return any(t in _RESET_TREE_FLAGS for t in rest)
    if verb == "stash":
        return bool(rest) and rest[0] in ("pop", "apply")
    return False


def _dir_read_only(path: str) -> bool | None:
    """Ask the mount policy about ``path``. Lazy import: sandbox is the heavier
    module and this is only consulted when a git fragment matches. An
    unresolvable policy answers None (unknown), which does not refuse."""
    try:
        from .sandbox import path_read_only_in_policy

        return path_read_only_in_policy(path)
    except Exception:  # noqa: BLE001 — an unresolvable policy is "unknown", which the docstring says does not refuse
        return None


def _task_cwd() -> str:
    """Where a task's shell starts: the resolved WILLOW_ROOT (the worker's
    working directory on the fleet), else the process cwd."""
    with contextlib.suppress(Exception):
        from .sandbox import willow_repo_root

        root = willow_repo_root()
        if root is not None:
            return str(root)
    return os.getcwd()


_VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _expand_vars(raw: str, task_vars: dict[str, str]) -> str | None:
    """Substitute `$NAME` / `${NAME}` references in ``raw``. A name assigned
    earlier in this same task body (``task_vars``) wins over the host env —
    the task's own shell would see its own assignment first. A name neither
    assigned in-task nor present in the host env is unresolvable: returns
    None so the caller can fail closed instead of guessing."""
    unresolved = False

    def _sub(match: re.Match) -> str:
        nonlocal unresolved
        name = match.group(1) or match.group(2)
        if name in task_vars:
            return task_vars[name]
        if name in os.environ:
            return os.environ[name]
        unresolved = True
        return ""

    expanded = _VAR_REF_RE.sub(_sub, raw)
    return None if unresolved else expanded


def _var_assignment(fragment: str) -> tuple[str, str] | None:
    """A bare `NAME=value` statement — the shape a later `cd $NAME` in the
    same task body needs resolved. Anchored so `echo a=b` (a command, not an
    assignment) does not match."""
    m = _ASSIGN_RE.match(fragment.strip())
    return (m.group(1), m.group(2)) if m else None


def _expand_cd_target(raw: str, current: str, task_vars: dict[str, str]) -> str | None:
    """The directory a `cd` in the task lands in, or None ("unknown") when a
    variable reference in it cannot be resolved. The task is a POSIX shell
    command run inside the Linux sandbox, so its paths are joined with
    posixpath whatever the host — `cd src` under `/srv/product` is
    `/srv/product/src` on a Windows host too."""
    expanded = _expand_vars(raw.strip("'\""), task_vars)
    if expanded is None:
        return None
    target = os.path.expanduser(expanded)
    return target if posixpath.isabs(target) else posixpath.join(current, target)


_STATEMENT_OPERATORS = frozenset({";", "&&", "||"})
# `|&` (pipe stderr+stdout) is a single punctuation token under
# `_punctuation_split`'s tokenizer (both chars are in punctuation_chars) — it
# must be recognised as its own split point or the command on either side of
# it merges into one simple command, judged only by the leading verb (B2,
# Loki 918CFAD0).
_SIMPLE_CMD_OPERATORS = frozenset({";", "&", "|", "&&", "||", "|&"})


def _punctuation_split(fragment: str, operators: frozenset[str]) -> list[str] | None:
    """Quote-aware tokenizer shared by every operator-based split in this
    module: the punctuation-aware shlex tokenizer (the same quoting engine
    already used by `_tree_rewrite_verb`), grouped into statements at
    whichever ``operators`` the caller names. A `;`/`&`/`|` inside quotes is
    just content, never a split point. Returns None on unbalanced quoting —
    the caller decides how to fail; see `_split_statement` (fails open, to
    "don't split") vs `_split_simple_commands` (fails closed, to "not
    allowed") for the two policies in use."""
    try:
        lexer = shlex.shlex(fragment, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        # shlex's default commenters='#' fires on a `#` *inside* a word too
        # (shlex.py: the commenters check runs before the wordchars check in
        # word-accumulating state), not only at the start of one — bash only
        # ever starts a comment at the start of a word. Left at the default,
        # a mid-word `#` throws away the rest of the *line* via
        # instream.readline(), silently dropping every simple command after
        # it (B1, Loki 918CFAD0). A real leading `#` comment line is already
        # stripped per-line before this ever runs (`_expand_shell_body`), so
        # turning shlex's own comment handling off here costs nothing.
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return None

    statements: list[str] = []
    current: list[str] = []
    for tok in tokens:
        if tok in operators:
            if current:
                statements.append(" ".join(current))
            current = []
            continue
        current.append(tok)
    if current:
        statements.append(" ".join(current))
    return statements


def _split_statement(fragment: str) -> list[str]:
    """Quote-aware split of one shell fragment into its `;`/`&&`/`||`
    -separated statements, for `check_tree_rewrite`'s cd walk. Unbalanced
    quoting fails open to "don't split" — dropping part of the fragment
    silently would be worse for cwd-tracking than scanning it as one piece."""
    statements = _punctuation_split(fragment, _STATEMENT_OPERATORS)
    return [fragment] if statements is None else statements


def _split_simple_commands(fragment: str) -> list[str] | None:
    """Quote-aware split of one shell fragment into its `;`/`&`/`|`/`&&`/`||`
    -separated simple commands, for the fleet-allowance decision in
    `_fleet_allowed`: every one of these must independently be an allowed
    verb for the fragment as a whole to count as fleet-allowed. Returns None
    on unparseable (unbalanced-quote) input — `_fleet_allowed` fails CLOSED
    on that, the opposite of `_split_statement`'s fail-open contract, because
    here the cost of guessing wrong is a downgraded security finding."""
    return _punctuation_split(fragment, _SIMPLE_CMD_OPERATORS)


def _statement_fragments(task_text: str) -> list[str]:
    """Per-statement fragments for `check_tree_rewrite`'s `cd`/verb walk — a
    finer split than the general security scan needs. Some scan patterns
    (e.g. `while ...; do ...; done`) depend on seeing a whole compound
    statement together, so the general scan keeps `_shell_fragments_from_task`
    as-is; only this tree-rewrite-specific walk also splits on `;`."""
    fragments: list[str] = []
    for frag in _shell_fragments_from_task(task_text):
        fragments.extend(_split_statement(frag))
    return fragments


def check_tree_rewrite(task_text: str = "", *, cwd: str | None = None) -> dict | None:
    """Refuse a git verb that would rewrite the working tree of a checkout the
    mount policy binds read-only. A verb in a read-write checkout, or in the
    writable lane under a read-only root, passes. See `_tree_rewrite_verb`.

    Tracks `cd` targets and simple `NAME=value` assignments made earlier in
    the same task body, so `W=/path; cd $W` resolves against what the task
    itself set rather than only the host env. A `cd` target that cannot be
    resolved at all is unknown, and an unknown cwd fails CLOSED here — the
    opposite of an unresolvable *mount-policy* lookup on a known path, which
    fails open (see `_dir_read_only`)."""
    current: str | None = cwd or _task_cwd()
    task_vars: dict[str, str] = {}
    for fragment in _statement_fragments(task_text or ""):
        text = fragment.strip()
        assign = _var_assignment(text)
        if assign is not None:
            name, raw_value = assign
            value = _expand_vars(raw_value.strip("'\""), task_vars)
            if value is not None:
                task_vars[name] = value
            continue
        m = _CD_RE.match(text)
        if m:
            current = _expand_cd_target(m.group(1), current or "", task_vars)
            continue
        if not _tree_rewrite_verb(text):
            continue
        is_blocked = True if current is None else _dir_read_only(current) is True
        if not is_blocked:
            continue
        where = current if current is not None else "an unresolved `cd` target"
        message = (
            f"refuses to rewrite the working tree of {where}, which the mount "
            f"policy binds read-only: this git verb would move refs in the writable "
            f".git and then fail to update files, leaving the checkout half-switched. "
            f"Read verbs, add, commit and `checkout -b NAME` are fine here; do tree "
            f"work in a read-write checkout or under {{{{WILLOW_ROOT}}}}/worktrees, "
            f"the writable lane."
        )
        return {
            "error": f"[KART-SECURITY] {message} (fragment: {text!r})",
            "kart_scan": {
                "category": "tree_rewrite_on_read_only_root",
                "severity": SEV_HIGH,
                "message": message,
                "where": "task",
                "fragment": text,
                "cwd": current,
            },
        }
    return None


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


# Backticks, `$(`, `<(`, `>(` are none of shlex's quote chars or this
# module's punctuation_chars, so with whitespace_split they read as ordinary
# word characters and stay inside the one simple command that contains them.
# An allowed verb's own arguments must never vouch for a substitution's
# payload this way (F4, Loki 918CFAD0 — pre-existing, not a regression).
_SUBSTITUTION_RE = re.compile(r"`|\$\(|<\(|>\(")


def _simple_command_allowed(command: str) -> bool:
    """Whether ONE simple command (no `;`/`&`/`|` of its own) matches an
    allowed verb shape. No MULTILINE: a simple command is always one logical
    line by construction, and `^` must mean the true start of it, not "the
    start of any line somewhere in a bigger fragment" — that MULTILINE
    latitude is exactly what let `echo x; <dangerous>` read as allowed."""
    text = command.strip()
    if not text:
        return True
    if _SUBSTITUTION_RE.search(text):
        return False
    return any(re.search(pat, text, re.IGNORECASE) for pat in _FLEET_ALLOWED)


_HEREDOC_MARKER_RE = re.compile(r"<<(-)?[ \t]*(['\"]?)(\w+)\2")


def _heredoc_marker_on_line(line: str) -> tuple[int, bool, str] | str | None:
    """Locate a real bash heredoc-start operator on ``line`` — quote-aware,
    and stopping at a real (unquoted, word-initial) trailing comment, since
    bash never starts a heredoc inside one. Returns:

      - ``None``: no heredoc operator on this line — either there is no
        `<<` at all, or what looks like one is definitively NOT a heredoc
        to bash (inside a real trailing comment, or a `<<<` here-string,
        which is an argument, not a redirection). The line is then judged
        as an ordinary command line, same as any other.
      - ``(start_index, dash, word)``: a plain ``<<WORD`` / ``<<-WORD`` /
        ``<<'WORD'`` / ``<<"WORD"`` operator with a ``\\w+`` delimiter,
        found as a real unquoted token. ``dash`` is True for ``<<-`` (bash
        strips leading TABs, and only TABs, from the terminator line before
        comparing) and False for plain ``<<`` (bash requires an exact
        match, no stripping at all) — B4, Loki 6AA36297: the caller used to
        discard this flag and compare every terminator the same
        (``.strip()``-loose) way.
      - ``"invalid"``: a `<<`/`<<-` operator is present whose delimiter
        shape the walker cannot confidently model (e.g. one containing a
        non-word character) — B3(c), Loki 918CFAD0: fail CLOSED here,
        same policy as an unterminated marker below, rather than guess at
        a delimiter shape bash might read differently.
    """
    quote: str | None = None
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            # Real trailing comment: bash does not open a heredoc inside
            # one — nothing after this point on the line is a heredoc
            # operator, real or otherwise.
            return None
        if ch == "<" and i + 1 < n and line[i + 1] == "<":
            if (i + 2 < n and line[i + 2] == "<") or (i > 0 and line[i - 1] == "<"):
                return None  # `<<<` here-string — an argument, not a heredoc
            m = _HEREDOC_MARKER_RE.match(line, i)
            if m is None:
                return "invalid"  # e.g. a non-\w delimiter that \w+ can't fully capture
            end = m.end()
            if end < n and line[end] not in " \t":
                return "invalid"  # delimiter continues past the \w+ capture
            return (i, bool(m.group(1)), m.group(3))
        i += 1
    return None


def _fleet_allowed_block(block: str) -> bool:
    """Fleet-allowance for a heredoc / kept-whole multiline block (see
    `_expand_shell_body`): allowed only if every COMMAND line in it is
    allowed. Heredoc payload lines are data, not commands, and are skipped
    entirely — they never see `_simple_command_allowed`. A shape this can't
    confidently classify (an opened heredoc marker with no matching
    terminator line, or a marker `_heredoc_marker_on_line` can't model) is
    NOT allowed: fail closed, same policy as `_split_simple_commands`
    returning None.

    Split on `\\n` only (never `.splitlines()`, which also breaks lines on
    `\\r`, `\\v`, `\\f`, `\\x1c`-`\\x1e`, `\\x85`, U+2028/U+2029 — none of
    which end a line to bash) — B4, Loki 6AA36297: a payload line carrying
    one of those characters used to be cut in two, and if the tail half
    happened to equal the terminator the walker closed the heredoc there,
    early. The terminator comparison is exact for `<<`; `<<-` strips only
    leading TABs first (the flag `_heredoc_marker_on_line` now returns) —
    never `.strip()`, which also ate trailing whitespace and other leading
    whitespace bash never touches, letting a decoy line close the heredoc
    before its real terminator. A `\\r` that survives the `\\n`-only split
    stays part of the line, so it breaks an exact match same as it would
    for bash — the heredoc goes unterminated, which fails closed here."""
    lines = block.split("\n")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        marker = _heredoc_marker_on_line(line)
        if marker is None:
            if line.strip() and not _fleet_allowed(line.strip()):
                return False
            i += 1
            continue
        if marker == "invalid":
            return False
        start, dash, terminator = marker
        before = line[:start].strip()
        if before and not _fleet_allowed(before):
            return False
        i += 1
        closed = False
        while i < n:
            candidate = lines[i].lstrip("\t") if dash else lines[i]
            if candidate == terminator:
                closed = True
                i += 1
                break
            i += 1  # heredoc payload line — not a command, not checked
        if not closed:
            return False  # unterminated heredoc marker — fail closed
    return True


def _fleet_allowed(fragment: str) -> bool:
    """A fragment is fleet-allowed only if EVERY simple command inside it is
    individually an allowed verb (gap: the old any-pattern-match-anywhere
    check let one allowed verb, e.g. `echo`, vouch for an unrelated command
    chained after it with `;` on the same line, or on another line of a
    heredoc/multiline block kept whole under `re.MULTILINE`). A fragment
    `_split_simple_commands` cannot parse (unbalanced quoting) is NOT
    allowed: fail closed."""
    text = fragment.strip()
    if not text:
        return True
    if "\n" in text:
        # Only a heredoc / kept-whole multiline block reaches `_fleet_allowed`
        # with an embedded newline — every other shape is split to one
        # logical line per fragment before it gets here (`_expand_shell_body`).
        return _fleet_allowed_block(text)
    commands = _split_simple_commands(text)
    if commands is None:
        return False
    return all(_simple_command_allowed(c) for c in commands)


def _blocking_issues(issues: list[ScanIssue], *, fleet: bool) -> list[ScanIssue]:
    out: list[ScanIssue] = []
    for issue in issues:
        if (
            issue.severity >= SEV_CRITICAL
            or issue.category in _ALWAYS_BLOCK_CATEGORIES
            and issue.severity >= SEV_HIGH
            or not fleet
            and issue.severity >= SEV_HIGH
        ):
            out.append(issue)
    return out


# Quote removal, roughly as bash does it, for a second pass of the text rules
# (bite B0 of docs/design/parser-scanner.md). bash drops quotes, escaping
# backslashes and backslash-newlines before running a word, so `c'u'rl`,
# `c\url`, `$'cu'rl`, `cu\<newline>rl` and `~/.s''sh` run as `curl` and
# `~/.ssh` while the rules, which read the text as written, never see those
# words. The copies are only ever scanned in addition to the original: they
# can add a block, never lift one. What they do not model (variables,
# substitutions, globs, `$'\x..'` escapes) waits for the parser.
_LINE_CONTINUATION = "\\\n"
_ANSI_C_QUOTE_RE = re.compile(r"\$(?=['\"])")
_BACKSLASH_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)


def _quote_normalised(text: str) -> str:
    """Every quote and escaping backslash removed: for the per-fragment rule
    pass. Errs towards removing too much (a backslash inside single quotes
    is literal to bash, and is dropped here anyway)."""
    out = text.replace(_LINE_CONTINUATION, "")
    out = _ANSI_C_QUOTE_RE.sub("", out)
    out = _BACKSLASH_ESCAPE_RE.sub(r"\1", out)
    return out.replace("'", "").replace('"', "")


# Outside quotes, these end a word as far as a quoted mention is concerned:
# shell operators, and the brackets, commas and colons of the Python or JSON
# a heredoc often carries (`["systemctl", ...]`, `{"systemctl": 1}`).
_WORD_BREAKS = frozenset(";|&()[]{},:\n")
# After these (and at the start of the text or a line) a word is in command
# position: bash runs it, so a quoted command name there (`'systemctl' ...`)
# is not a mention.
_COMMAND_STARTERS = frozenset(";|&(){}\n")
# A quoted word followed by one of these is list or dict data, not a command.
_DATA_FOLLOWERS = frozenset(",:]}")
# Inside double quotes a backslash escapes only these; elsewhere it is literal.
_DQ_ESCAPABLE = frozenset('"\\$`\n')
# Reserved words after which the next word is still a command.
_KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "time", "{"}
)
# Words that leave the next word in command position: an assignment
# (`X=1 cmd`) or a redirection with its target (`2>/dev/null cmd`).
_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_REDIRECTION_RE = re.compile(r"(?:[0-9]*|&)(?:>>?|<<?<?|>&|<&|>\||<>)(.*)", re.DOTALL)


def _unquote(text: str) -> str:
    """``text`` with bash's quote removal applied to the words bash would run
    as more than their quoted text: a word built from several pieces
    (`sys''temctl`, `c'u'rl`, `run\\ner.py`), and a quoted word in command
    position (`'systemctl' ...`). Any other word that is a single quoted
    string is a mention (`grep -rn 'systemctl' src/`) and is kept as written,
    as is a word that would contain whitespace once unquoted (never a command
    name or a path bash runs as one) and a trailing comment. Quotes pair as
    bash pairs them, across lines: a backslash escapes `"`, `\\`, `$`, a
    backquote and a newline inside double quotes, and nothing inside single
    quotes; `$'..'` has its own escapes.

    This is an approximation of bash, not a parser, and it is only ever one
    of several views the checks read, any of which can refuse
    (`_mention_views`). It can add a refusal; it never lifts one."""
    out: list[str] = []
    pieces: list[tuple[str, str, bool]] = []  # (as written, as run, quoted)
    command_position = True
    redirect_target = False  # the next word is a redirection's target

    def flush(follower: str) -> None:
        nonlocal command_position, redirect_target
        if not pieces:
            return
        raw = "".join(r for r, _i, _q in pieces)
        run = "".join(i for _r, i, _q in pieces)
        quoted = any(q for _r, _i, q in pieces)
        mention = len(pieces) == 1 and not (
            command_position and follower not in _DATA_FOLLOWERS
        )
        unquote = quoted and not mention and not any(c.isspace() for c in run)
        out.append(run if unquote else raw)
        pieces.clear()
        if redirect_target:
            redirect_target = False  # command position is unchanged
            return
        if command_position:
            m = _REDIRECTION_RE.fullmatch(run)
            if m is not None:
                redirect_target = not m.group(1)
                return
            if _ASSIGNMENT_RE.match(run) or run in _KEYWORDS:
                return
        command_position = False

    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                pieces.append((text[i : i + 2], text[i + 1], True))
            i += 2  # a backslash-newline is removed, and the word goes on
        elif ch == "'" or (ch == "$" and text[i + 1 : i + 2] == "'"):
            q = i + 1 if ch == "$" else i
            j = q + 1
            while j < n and text[j] != "'":
                j += 2 if ch == "$" and text[j] == "\\" else 1  # $'..' escapes
            if j >= n:  # unterminated: the rest is kept as written
                pieces.append((text[i:], text[i:], False))
                i = n
            else:
                pieces.append((text[i : j + 1], text[q + 1 : j], True))
                i = j + 1
        elif ch == '"' or (ch == "$" and text[i + 1 : i + 2] == '"'):
            q = i + 1 if ch == "$" else i
            j, inner = q + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] in _DQ_ESCAPABLE:
                    if text[j + 1] != "\n":
                        inner.append(text[j + 1])
                    j += 2
                else:
                    inner.append(text[j])
                    j += 1
            if j >= n:
                pieces.append((text[i:], text[i:], False))
                i = n
            else:
                pieces.append((text[i : j + 1], "".join(inner), True))
                i = j + 1
        elif ch == "#" and not pieces:
            flush("")
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(text[i:j])  # a comment: kept as written
            i = j
        elif ch.isspace() or ch in _WORD_BREAKS:
            flush(ch)
            if ch in _COMMAND_STARTERS:
                # `f(` right after a word is a call's text, not a subshell.
                glued = (
                    ch == "("
                    and bool(out)
                    and (out[-1][-1:].isalnum() or out[-1][-1:] == "_")
                )
                command_position = not glued
                redirect_target = False
            elif not ch.isspace():
                command_position = False
            out.append(ch)
            i += 1
        else:
            j = i + 1
            while j < n and not (
                text[j].isspace()
                or text[j] in _WORD_BREAKS
                or text[j] in "'\"\\"
                or (text[j] == "$" and text[j + 1 : j + 2] in ("'", '"'))
            ):
                j += 1
            pieces.append((text[i:j], text[i:j], False))
            i = j
    flush("")
    return "".join(out)


def _mention_views(text: str) -> tuple[str, ...]:
    """What the whole-text substring checks read: the text as written, and
    two quote-removed views of it, any of which may refuse. Backslash-newlines
    are removed first, as bash removes them. The whole text lexed at once
    pairs a quoted string that spans lines as bash does; each line lexed on
    its own keeps a stray quote on one line (in heredoc data, a comment)
    from shifting the pairing on the next. Heredoc bodies are never skipped:
    whether bash runs them is not decided here."""
    joined = text.replace(_LINE_CONTINUATION, "")
    views = [
        text,
        _unquote(joined),
        "\n".join(_unquote(line) for line in joined.split("\n")),
    ]
    return tuple(dict.fromkeys(views))


def _scan_texts(text: str, normalise=_quote_normalised) -> tuple[str, ...]:
    """The text as written, and its normalised copy when that differs."""
    normalised = normalise(text)
    return (text,) if normalised == text else (text, normalised)


def _scan_shell_fragment(fragment: str) -> ScanIssue | None:
    text = fragment.strip()
    if not text:
        return None
    # The allowance is decided on the text as written: the shlex split behind
    # it already applies bash's quoting rules.
    fleet = _fleet_allowed(text)
    issues = [i for t in _scan_texts(text) for i in scan_bash(t)]
    return worst(_blocking_issues(issues, fleet=fleet))


def _shell_fragments_from_task(task_text: str) -> list[str]:
    # `\n`-only split (never `.splitlines()`) — B4, Loki 6AA36297: this is
    # the upstream reconstruction `_fleet_allowed_block`'s own `\n`-only
    # split (below) depends on. `.splitlines()` here would already collapse
    # a `\r`-carrying or other splitlines()-break-char line before the
    # heredoc walker ever saw it, silently reproducing the same early-close
    # bug one layer up even with the walker itself fixed.
    lines = [
        ln
        for ln in (task_text or "").split("\n")
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


def _join_line_continuations(lines: list[str]) -> list[str]:
    """Join lines ending in an unescaped trailing `\\` into their next line —
    a literal continuation, so nothing is inserted between the pieces — so a
    command wrapped across physical lines scans as one logical line."""
    out: list[str] = []
    pending = ""
    for ln in lines:
        if ln.endswith("\\") and not ln.endswith("\\\\"):
            pending += ln[:-1]
            continue
        joined = pending + ln
        if joined.strip():
            out.append(joined)
        pending = ""
    if pending.strip():
        out.append(pending)
    return out


def _expand_shell_body(body: str) -> list[str]:
    """Split compound shell into chain-split fragments for every logical
    line (SECURITY: a multi-line body used to fragment to its first line
    only — gap 312a614188dc — so later lines were never scanned or
    cwd-tracked). `\\`-continuations are joined first. Heredoc / multiline
    blocks (a body containing a `<<` marker) are kept as one unit, unchanged
    from prior behavior."""
    lines = [
        ln
        for ln in body.split("\n")
        if ln.strip() and not ln.lstrip(" \t").startswith("#")
    ]
    if not lines:
        return []
    if any("<<" in ln for ln in lines):
        return [body]
    fragments: list[str] = []
    for line in _join_line_continuations(lines):
        fragments.extend(_CHAIN_SPLIT.split(line))
    return fragments


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


# Bash's own text model: the only line break is `\n`, and the only blanks
# are space and tab. Everything downstream (`_expand_shell_body`,
# `_heredoc_marker_on_line`, `_shell_fragments_from_task`) is now written to
# that model exactly — but Python's own line/blank primitives
# (`splitlines()`, `\s`, `.isspace()`, `.strip()`) accept strictly more than
# that, and three rounds of audit (918CFAD0, 6AA36297, 36CDF4A5) each found a
# fresh call site where the gap resurfaced. Rather than keep chasing sites,
# refuse the character class at the door: any of these can never reach a
# downstream scanner, by construction. Refused: C0 controls other than TAB
# (`\t`) and LF (`\n`) — i.e. NUL and `\x01`-`\x08`, `\x0b` (VT), `\x0c` (FF),
# `\x0e`-`\x1f`; DEL (`\x7f`); NEL (`\x85`); and the Unicode line/paragraph
# separators U+2028 and U+2029. CR (`\r`) is included (bash never treats it
# as a line break or blank; it is ordinary trailing text on the line) so a
# CRLF-terminated body is refused here too, rather than silently kept as
# part of the last word on each line downstream.
_CONTROL_CHARACTERS = frozenset(
    map(
        chr,
        [
            *range(0x09),  # C0 controls before TAB: NUL..BS
            *range(0x0B, 0x20),  # C0 controls after LF through US: VT, FF, SO..US
            0x7F,  # DEL
            0x85,  # NEL (NEXT LINE)
            0x2028,  # LINE SEPARATOR
            0x2029,  # PARAGRAPH SEPARATOR
        ],
    )
)


def _control_character_issue(text: str, *, where: str) -> dict | None:
    found = None
    for ch in text:
        if ch in _CONTROL_CHARACTERS:
            found = ch
            break
    if found is None:
        return None
    return {
        "error": (
            "[KART-SECURITY] Task text contains a control/line-break "
            f"character (U+{ord(found):04X}) that Python treats as a "
            "line break or blank but bash does not — normalise line "
            "endings to \\n and remove other control characters before "
            "resubmitting."
        ),
        "kart_scan": {
            "category": "control_characters",
            "severity": SEV_CRITICAL,
            "message": f"Disallowed control character U+{ord(found):04X}",
            "where": where,
        },
    }


def check_control_characters(
    task_text: str = "", *, script_body: str = ""
) -> dict | None:
    """Refuse any task/script_body text carrying a character Python treats as
    a line break or blank but bash does not (see `_CONTROL_CHARACTERS`).
    Structural fix for the whitespace-model class of bug (B4/B5, Loki
    918CFAD0/6AA36297/36CDF4A5): every downstream `splitlines()`/`\\s`/
    `.isspace()`/`.strip()` disagreement with bash is unreachable once none
    of these characters can be present at all."""
    for where, text in (("task", task_text or ""), ("script_body", script_body or "")):
        issue = _control_character_issue(text, where=where) if text else None
        if issue:
            return issue
    return None


# N1 (Loki F90182A5, pre-existing gap, not a regression): the runner wraps
# every multi-line fenced block in its own heredoc with a FIXED delimiter
# (`bash <<'KART_SH'` / `python3 - <<'KART_PY'`, kartikeya execute.py:203,
# 205), and this scanner has no way to model that wrapper — it is added
# after the scan, around a block the scanner already judged as a whole. A
# task-body line that happens to equal one of these delimiters exactly
# (trailing whitespace aside — bash's own `<<'WORD'` terminator match
# strips no leading/trailing whitespace from the terminator LINE itself,
# but the runner's `\n{body}\n{DELIM}` join guarantees the delimiter line
# is exactly `DELIM` with nothing but a possible trailing newline, so a
# task line matching `DELIM` plus only trailing whitespace is the one
# shape that reaches the runner as a bare terminator line) closes the
# RUNNER's own outer heredoc early, and bash then runs whatever follows in
# the task body as real commands — even lines the scanner classed as
# heredoc/data. Same class and impact bound as B4. Fix option (a) from the
# two named in the packet: refuse the collision outright. Option (b) (a
# per-task nonce delimiter in the runner, verified absent from the body) is
# an equally real fix but a larger surface change than this one-line guard.
_HEREDOC_WRAPPER_DELIMITERS = frozenset({"KART_SH", "KART_PY"})


def _wrapper_delimiter_collision(text: str) -> str | None:
    for line in (text or "").split("\n"):
        if line.rstrip() in _HEREDOC_WRAPPER_DELIMITERS:
            return line.rstrip()
    return None


def check_heredoc_wrapper_collision(
    task_text: str = "", *, script_body: str = ""
) -> dict | None:
    """Refuse task/script_body text carrying a line that collides with the
    runner's own outer heredoc delimiter (see `_HEREDOC_WRAPPER_DELIMITERS`
    and the N1 note above)."""
    for where, text in (("task", task_text or ""), ("script_body", script_body or "")):
        hit = _wrapper_delimiter_collision(text) if text else None
        if hit:
            return {
                "error": (
                    "[KART-SECURITY] Task text contains a line matching the "
                    f"runner's own heredoc wrapper delimiter ({hit!r}) — this "
                    "would close the runner's own wrapper heredoc early and "
                    "let bash run text this scanner treated as data. Rename "
                    "or remove the colliding line."
                ),
                "kart_scan": {
                    "category": "heredoc_wrapper_collision",
                    "severity": SEV_CRITICAL,
                    "message": f"Line collides with runner delimiter: {hit!r}",
                    "where": where,
                },
            }
    return None


def _hook_tamper_fragment(text: str) -> str | None:
    if not text:
        return None
    return next(
        (
            frag
            for frag in _hook_guard_fragments()
            if any(frag in t for t in _mention_views(text))
        ),
        None,
    )


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


def check_systemd_manager(task_text: str = "", *, script_body: str = "") -> dict | None:
    """Refuse systemctl/busctl in task or script_body — broker verbs only."""
    for where, text in (("task", task_text or ""), ("script_body", script_body or "")):
        if text and any(_SYSTEMD_MANAGER_RE.search(t) for t in _mention_views(text)):
            return {
                "error": _SYSTEMD_MANAGER_REFUSAL,
                "kart_scan": {
                    "category": "systemd_manager",
                    "severity": SEV_CRITICAL,
                    "message": "systemctl/busctl refused; use unit_install_execute / unit_reload_execute",
                    "where": where,
                },
            }
    return None


def check_kart_task(task_text: str = "", *, script_body: str = "") -> dict | None:
    """
    Return an error dict if the task should not run/queue, else None.
    """
    if not kart_scan_enabled():
        return None

    control = check_control_characters(task_text, script_body=script_body)
    if control:
        return control

    wrapper = check_heredoc_wrapper_collision(task_text, script_body=script_body)
    if wrapper:
        return wrapper

    tamper = check_hook_tamper(task_text, script_body=script_body)
    if tamper:
        return tamper

    systemd = check_systemd_manager(task_text, script_body=script_body)
    if systemd:
        return systemd

    rewrite = check_tree_rewrite(task_text)
    if rewrite:
        return rewrite

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
