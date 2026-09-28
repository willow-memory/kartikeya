# Design packet: a parser-based task scanner

Status: **proposal, revision 2** after Loki audit 2D7DCC5B (REVISE). Prior-art
survey item 3 (ratatosk `docs/prior-art.md:495-501`). **No code until this
packet is accepted.** The first code is bite B0 (section 9), which needs no new
dependency.

## 1. Where the scanner stands

`task_scan.check_kart_task` is a pre-flight gate, run at submit time and again
in the worker. Its pipeline:

1. `check_control_characters`: refuses 34 control characters at entry.
2. Structural refusals: `check_heredoc_wrapper_collision`, `check_hook_tamper`
   and `check_systemd_manager` (substring matches), and `check_tree_rewrite`.
3. `scan_write` over a Python `script_body`.
4. For each shell fragment from `_shell_fragments_from_task` (fenced blocks,
   heredoc bodies, line continuations):
   - an allowlist check, `_FLEET_ALLOWED`: 12 regexes anchored at the
     fragment start. The only variable form among them is
     `${WILLOW_PYTHON:-python3}`;
   - then `security_scan.scan_bash`: **53 regexes** (exfiltration 15,
     secret_access 9, destructive 12, resource_exhaustion 7,
     suspicious_install 5, obfuscation 5), plus the `rm -rf` target check.

   An allowed verb downgrades findings (`_blocking_issues`): on an allowed
   fragment only critical-severity findings, and high-severity findings in the
   always-block categories (exfiltration, obfuscation, secret_access,
   resource_exhaustion), still block. Destructive and suspicious_install
   findings at high severity are downgraded. The quote-aware `shlex` split added in #67
   decides which statements are allowed; it does not feed the 53 rules, which
   still see fragment text.

### What that misses: reproduced against master (2026-09-28)

Each row is a rewrite of a command the scanner **blocks** in its plain form:

| Shape | Example of the shape | Verdict |
|---|---|---|
| quotes inside a word | `c'u'rl …` | allow |
| command name from a variable | `c=curl; $c …` | allow |
| command name from a substitution | `$(printf cu)rl …` | allow |
| quotes inside a path | `cat ~/.s''sh/…` | allow |
| glob in a path | `cat ~/.ss?/…` | allow |

The opposite failure: `echo 'never run rm -rf / here'` is **blocked**, because
the pattern matches text inside a quoted argument that nothing executes.

Also measured: the entry check lets all **16 Unicode space characters**
(category Zs) through. bash treats them as ordinary word characters, not
separators, so any parser that treats them as whitespace would see different
words from the ones bash runs (section 5).

None of this is a sandbox escape. The OS boundary (bwrap, and Landlock with
#82) is what stops a task. The scanner is defence in depth, and its verdict
currently depends on spelling.

## 2. Goals and non-goals

**Goals**
- Judge each simple command's **command name and arguments after quote
  removal**, as bash will see them before expansion, in every unit the runner
  hands to an interpreter (section 3).
- **Name** what cannot be judged statically (dynamic command names, unhandled
  syntax) and refuse it by policy, instead of letting it pass by accident.
- Keep the contract: the refusal payload shape (`kart_scan`, category,
  severity, `where`), `scan_ledger` capture, and failing closed on any scanner
  error.
- Stop blocking text inside the quoted arguments of commands that provably do
  not execute them (a closed list, section 4.3).

**Non-goals**
- Being a security boundary. The OS is the chokepoint (the Codex CLI model).
- Expanding variables, aliases, functions or globs. The parser does not know
  runtime values, so it cannot promise "what bash will execute". It promises a
  quote-removed static view, and treats everything it cannot resolve as
  dynamic.
- Python `script_body` analysis. That stays `scan_write`.
- Removing the regex floor (section 8).

## 3. The parse unit

The scanner must parse **exactly the units the runner executes**, no more and
no less. Today's runner (`execute.run_shell_task`,
`execute._iter_fenced_blocks`):

| Task body | What runs |
|---|---|
| no fences | the whole body, as one `bash -c` |
| a fenced `python`/`python3` block | `python3 - <<'KART_PY' … KART_PY` |
| a multi-line fenced `bash`/`sh`/untyped block | `bash <<'KART_SH' … KART_SH` |
| a one-line fenced block | that line, as `bash -c` |
| prose between or around fences | **nothing** |

Parsing "the whole body" would either refuse every task with prose or a Python
fence, or, if it skipped them, stop scanning what `scan_bash` catches today.
So **bite B1** extracts one shared function,
`parse_units(task_text) -> list[Unit(kind, body)]`, that both the runner and the
scanner call. Shell units are parsed by the classifier. Python units keep
today's handling (`scan_write` for content, plus the regex floor over the
text). Prose units are not scanned as shell, because they never run, but the
regex floor still sees the full text (section 8).

## 4. The classifier

### 4.1 Per simple command

For every simple command, including those nested in pipelines, lists,
subshells, command and process substitutions, and heredoc or here-string
bodies fed to an interpreter, produce:

- `name`: the command word after **full** quote removal (section 5), or
  **DYNAMIC** if any part of it is not fully decoded: an expansion, a
  substitution, an unhandled escape, a brace expansion, or a glob.
- `path_name`: set when the name contains `/` (`/usr/bin/curl`, `./x`). The
  basename is used for matching, and the path is kept for the report. A
  leading backslash (`\curl`, which bypasses aliases) is removed with the other
  quoting.
- `args`: each argument after quote removal, marked DYNAMIC or GLOB as for the
  name.
- `redirects`: every redirect target, with its operator (`<`, `>`, `>>`, `<>`,
  `&>`, here-string, heredoc) and whether it is DYNAMIC.
- `cwd`: the statically known working directory, tracked through `cd` with a
  literal argument, as `check_tree_rewrite` does today. After a DYNAMIC `cd`
  it is unknown, and relative sensitive-path checks then treat every relative
  path as possibly sensitive.

### 4.2 Recursion into interpreters and wrappers

Arguments that are code are parsed, not skipped:

- **Interpreter arguments:** `bash|sh|zsh|dash -c STR`, `python* -c STR`,
  `perl -e STR`, `ruby -e STR`, `node -e STR`, `psql -c STR` (SQL, which gets
  the regex floor only), and an `ssh HOST CMD…` remote command. A string
  argument is parsed as a new shell unit when the interpreter is a shell, and
  otherwise gets the regex floor. A DYNAMIC code argument is refused.
- **Wrappers** that run their arguments as a command: `xargs`,
  `find … -exec/-execdir … ;`, `env`, `timeout`, `nohup`, `nice`, `sudo`,
  `doas`, `exec`, `command`, `builtin`, `time`, `stdbuf`, `setsid`, `chroot`,
  `flock`, `watch`. The wrapped command is classified as a simple command in
  its own right.
- **Staged payloads:** output piped into an interpreter (`… | sh`,
  `… | python3`) makes every upstream producer's literal text subject to the
  regex floor. A file written by the task (`>`, `tee`) and later executed
  (`sh FILE`, `bash FILE`, `./FILE`, `source FILE`) has its written content,
  when statically known, parsed as a shell unit. When the content is not
  known, running that file is refused.

### 4.3 Quoted arguments

The rules skip a command's quoted arguments **only** when the command is on a
closed list of commands that never execute them: `echo`, `printf`, `grep`,
`egrep`, `fgrep`, `rg`, `git commit -m/-F`, `git log --grep`, `test`, `[`,
`true`, `false`, `:`. Every other command's arguments are judged. Interpreters
and wrappers are recursed into (section 4.2), never skipped. That is what fixes
the `echo 'rm -rf /'` false positive without newly allowing `bash -c '…'`.

### 4.4 Rules by category

All six `scan_bash` categories are mapped. Section 8 governs what is not.

| Category | Structural rule | Regex floor |
|---|---|---|
| exfiltration | a network client, open-ended (any name matching the client list or a transfer-looking flag set, and **any redirect to `/dev/tcp` or `/dev/udp`**), with a sensitive source (`@file`, `-T`/`--upload-file`, a sensitive path or redirect), or output piped into an interpreter | kept |
| secret_access | any command, **or any `<` redirect**, whose resolved path (relative to `cwd`) falls under a sensitive root; a GLOB path is matched as a pattern against those roots | kept |
| destructive | `rm` with recursive and force flags on a root-like target, plus the existing destructive verbs, judged on arguments, not on others' quoted text | kept |
| resource_exhaustion | fork bombs (a function that calls itself in a pipeline in the background), `yes`/`dd` into devices, unbounded `while true` without I/O | kept, as the primary rule |
| suspicious_install | package managers installing from a URL, a local path or an unpinned source; `curl … \| sh` shapes | kept |
| obfuscation | base64, xxd or rev decoding piped into an interpreter; DYNAMIC command names | kept |

**Allowed-verb downgrade:** today's rule is kept. A simple command whose name
is on `_FLEET_ALLOWED` downgrades its own high-severity destructive and
suspicious_install findings, while critical findings and the always-block
categories still block. It never downgrades another command in the same unit.

### 4.5 Refusal policy for what cannot be judged

| Case | Policy |
|---|---|
| any ERROR or MISSING node | refuse, `scan_unparseable` |
| **any node type the walker does not explicitly handle** | refuse, `scan_unhandled_syntax` |
| DYNAMIC command name | refuse, unless it is exactly `${WILLOW_PYTHON:-python3}` (today's only allowlisted variable form) |
| `eval`, `source` or `.` with a DYNAMIC argument | refuse |
| a function definition whose name shadows a command name used elsewhere in the unit | refuse |
| `shopt -s expand_aliases`, or `alias` | refuse |
| DYNAMIC or GLOB argument or redirect to a network client or a sensitive root | refuse |
| DYNAMIC argument elsewhere | allow (the sandbox decides) |

These node types are **not handled in the first version**, so the "unhandled"
row refuses them:
- ANSI-C quoting `$'…'` and locale quoting `$"…"` in a command name;
- brace expansion in a command name;
- function definitions;
- compound statements used as a command's input or output (`{ …; } > f`)
  beyond a plain subshell;
- `declare`, `typeset`, `local` and `readonly` with `-f` or `-n`;
- arithmetic commands containing substitutions;
- coprocesses;
- `select`.

The list is kept in code as an explicit allow-set of node types. A tree-sitter
grammar upgrade that adds a node type therefore refuses it until it is handled.

## 5. Parser and bash divergences

Divergences are named, not assumed away.

- **Quote removal is ours, not the grammar's.** It decodes `'…'`, `"…"`
  (with its four escapes), backslash escapes, line continuations, `$'…'`
  (C escapes) and `$"…"`. Anything it cannot fully decode in a command name
  makes the name DYNAMIC.
- **Unicode spaces:** bash splits words only on space, tab and newline. The 16
  Zs characters are word characters to bash. If the grammar treats any of them
  as a separator, parser words and bash words diverge. So they are **refused
  at entry**, next to the 34 control characters, before parsing. That is a new
  refusal, measured in shadow mode before it ships.
- **`bash -n` agreement in CI:** a CI-only test runs `bash -n` over every
  corpus unit and asserts that parser-unparseable matches bash-syntax-error in
  both directions. It never runs in the broker.
- **Soundness rule:** any corpus case the parser allows while the regex floor
  blocks it is a parser bug, never an accepted difference. The regex floor
  still blocks it in production (section 8).

## 6. Dependency

| Option | Status |
|---|---|
| **tree-sitter-bash via py-tree-sitter** | recommended |
| bashlex | GPL-3.0 per memory; needs a licence decision |
| mvdan/sh `shfmt --to-json` | **dropped**: it would mean a subprocess per scan in the broker |

Conditions for tree-sitter:
- It is a C extension in the broker process. A crash or hang there is not a
  Python exception, so each unit gets a **size cap** (e.g. 64 KiB, refused
  above that) and the parse runs under a **timeout**. A timeout refuses.
- **Exact pins** of `tree-sitter` and `tree-sitter-bash`, identical at broker
  and worker, and asserted at start-up.
- An **import failure refuses** every task that the parser engine would
  judge. It never falls back to regex-only silently.
- An **optional extra** (`kartikeya[parser]`) until the engine switch is
  flipped.
- **Licences to be verified upstream** before adoption. Every licence here
  is from memory.

## 7. Migration

1. **B0 (no dependency, now):** a second regex pass over a quote-normalised
   copy of each fragment. It can only add blocks. The section 1 rewrite rows
   become tests.
2. **B1:** `parse_units()` shared by the runner and the scanner, with no
   behaviour change, proven by the full existing suite.
3. **B2:** the classifier behind `KART_SCAN_ENGINE` = `regex` (default) |
   `shadow` | `parser`:
   - `shadow` records **only agree/disagree** (plus the categories involved)
     in `scan_ledger`, not task bodies, until the operator answers question 3;
   - the rollback is setting `KART_SCAN_ENGINE=regex`, honoured at **both**
     broker and worker. `WILLOW_KART_SCAN=0` is not a rollback: it disables
     all scanning.
4. **B3:** the differential corpus and mutation proof (section 7.1). The switch
   to `parser` is gated on it: every regex-floor block is reproduced or
   explained, and every new block on allowed tasks is reviewed.
5. ~~Remove the text rules~~ **struck.** A rule may be retired only after a
   rule-by-rule mapping shows the structural rule covers it on the corpus, one
   rule at a time, each its own reviewed change.

### 7.1 Corpus categories

- every `tests/test_task_scan.py` case (154 collected), run through both
  engines;
- the section 1 rewrite rows and the `echo` false positive;
- interpreter arguments (`bash -c`, `python -c`, `perl -e`, `psql -c`, `ssh`);
- wrappers (`xargs`, `find -exec`, `env`, `timeout`, `nohup`, `sudo`, `exec`,
  `command`);
- staged payloads (pipe to an interpreter; write, then run);
- secret reads through redirects, and `/dev/tcp`;
- heredoc markers, including the runner's own `KART_SH`/`KART_PY`;
- Unicode spaces and control characters;
- every node type on the unhandled list;
- with the operator's consent (question 3), a sample of real task bodies.

(`tests/test_scans_fire.py` is a meta-test that every scan helper has a planted
violation. It holds no task cases, so it is not corpus.)

## 8. The regex floor stays

The 53 `scan_bash` rules, the rm check and the structural checks keep running
**in every engine**, as a floor that can only add a block. The parser engine
can refuse more than the floor, never less.

`check_hook_tamper` and `check_systemd_manager` keep their substring match and
**gain** a command-name check on top (e.g. a quote-split `sys''temctl`). The
new check is added to the substring match, never replacing it.

## 9. Bites

| Bite | Scope | Dependency |
|---|---|---|
| **B0** | quote-normalised second regex pass, add-only; the section 1 rows as tests. **Landed:** the quote-split rows block; the variable, substitution and glob rows (and `$'\x..'` escapes) stay as strict xfails for B2 | none |
| **B1** | shared `parse_units()` for the runner and the scanner, no behaviour change | none |
| **B2** | shadow classifier behind `KART_SCAN_ENGINE` (default `regex`): pinned optional extra, refuses unhandled node types, size cap and timeout, agree/disagree recording only | `kartikeya[parser]` |
| **B3** | differential corpus, `bash -n` agreement in CI, mutation proof | none new |

Each bite is its own PR, with its own audit.

## 10. Questions for the operator

1. **Dependency:** tree-sitter-bash as an optional extra (recommended), or
   bashlex (GPL-3.0)?
2. **DYNAMIC command names:** refuse by default, allowing only
   `${WILLOW_PYTHON:-python3}`? Shadow mode will count what this refuses.
3. **Corpus access:** may shadow mode store the bodies of allowed tasks, not
   only agree/disagree?
4. **B0 now:** go ahead with the quote-normalised second pass? It closes the
   quote-split rows of section 1 with no dependency.
