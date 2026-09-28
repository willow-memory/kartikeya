# Design packet: a parser-based task scanner

Status: **proposal, for audit before any code.** Prior-art survey item 3
(ratatosk `docs/prior-art.md:495-501`: "a bashlex AST-based command
classifier"). This packet is the "design packet first" the survey asked for.

## 1. Where the scanner stands

`task_scan.check_kart_task` is a pre-flight gate that runs before a task is
queued (submit time) and again before it runs (worker). Its pipeline:

1. `check_control_characters`: refuse control characters at entry.
2. `check_heredoc_wrapper_collision`, `check_hook_tamper`,
   `check_systemd_manager`, `check_tree_rewrite`: structural refusals.
3. `scan_write` over a Python `script_body`.
4. For each shell fragment (`_shell_fragments_from_task`: fenced blocks,
   heredoc bodies, line continuations, a quote-aware `shlex` split into
   statements and simple commands since #67): an allowlist check
   (`_FLEET_ALLOWED`, 12 regexes over the fragment start), then
   `security_scan.scan_bash`, about 119 regexes in categories exfiltration,
   secret_access, destructive, resource_exhaustion, suspicious_install and
   obfuscation.

Every rule matches **text**. Tokenization got better in #67, but the rules
still look at the command as written, not as bash will run it.

### What that misses: reproduced against master (2026-09-28)

Each row is a rewrite of a command the scanner **blocks** in its plain form:

| Shape | Example of the shape | Verdict |
|---|---|---|
| quotes inside a word | `c'u'rl …` | allow |
| command name from a variable | `c=curl; $c …` | allow |
| command name from a substitution | `$(printf cu)rl …` | allow |
| quotes inside a path | `cat ~/.s''sh/…` | allow |
| glob in a path | `cat ~/.ss?/…` | allow |

And the opposite failure, a false positive:

| Benign command | Verdict |
|---|---|
| `echo 'never run rm -rf / here'` | **block** (the pattern matches text inside a quoted argument) |

None of these is a sandbox escape. The OS boundary (bwrap, and Landlock with
#82) is what actually stops a task, and the scanner is defence in depth that
catches obvious misuse early and legibly. But the table is the survey's point:
the scanner's verdict depends on spelling, so a rewrite that bash reads
identically escapes it, and quoted text that bash never runs trips it.

## 2. Goals and non-goals

**Goals**
- Judge **what bash will execute**: the command name and arguments after
  quote removal, per simple command, including inside pipelines, `&&`/`||`
  lists, subshells, command substitutions, process substitutions, and
  heredoc or here-string bodies that are themselves fed to a shell.
- Name the thing that cannot be judged statically, and have a policy for
  it, instead of letting it pass by accident. Examples are a command name
  that comes from a variable, a substitution or `eval`, and a path with an
  unresolved glob or variable.
- Keep the current contract: the same refusal payload shape (`kart_scan`,
  category, severity, `where`), the same `WILLOW_KART_SCAN=0` switch, and
  the same fail-closed behaviour (a scanner exception fails the row).
- Cut false positives from text in quoted arguments to commands that do not
  execute them (`echo`, `printf`, `grep`, `git commit -m`).

**Non-goals**
- Being a security boundary. The OS is the chokepoint (the Codex CLI
  model); the scanner stays a pre-flight.
- Full bash semantics. No expansion of variables from the environment and
  no aliases or functions defined outside the task text. The worker never
  sources rc files.
- Python `script_body` analysis. That stays `scan_write` and is a separate
  item.

## 3. Parser options

| Option | Licence | Fit | Concerns |
|---|---|---|---|
| **bashlex** (Python port of bash's own parser) | GPL-3.0 (verify) | Pure Python, gives a bash-faithful AST | Licence: kartikeya is MIT, and a GPL runtime dependency needs an explicit decision. Maintenance activity to check. |
| **tree-sitter-bash** via `py-tree-sitter` | MIT (verify) | Fast, error-tolerant CST, prebuilt wheels | Error-tolerant means it parses garbage into *something*, so "unparseable" must be derived from ERROR nodes. It is a grammar, not bash's parser, so there are edge-case divergences. |
| **mvdan/sh** (`shfmt --to-json`) | BSD-3 (verify) | The most complete bash parser outside bash; JSON AST | Go binary as an external dependency; a subprocess per scan. |
| **Own recursive-descent subset** | MIT | No dependency; exactly the subset needed | Most code to own; its correctness is the whole risk. |

**Recommendation: tree-sitter-bash**, with its ERROR/MISSING nodes treated
as "unparseable", which is refused (section 4). Its licence matches
kartikeya's; it ships wheels, so it keeps a zero-infra install; and its CST
exposes exactly the node kinds the classifier needs (`command`,
`command_name`, `word`, `raw_string`, `string`, `concatenation`,
`command_substitution`, `process_substitution`, `simple_expansion`,
`expansion`, `heredoc_body`, `herestring_redirect`, `pipeline`, `list`,
`subshell`). bashlex is the fallback if the operator accepts GPL-3.0; mvdan/sh
if a Go binary is acceptable on workers.

*All licence cells are from memory and must be checked against each project
before adoption.*

## 4. The classifier

Parse the whole task body once, then walk every **simple command** (including
nested ones in substitutions and subshells). For each, produce:

- `name`: the command word after quote removal (`c'u'rl` becomes `curl`), or
  **DYNAMIC** when any part of it is an expansion or substitution
  (`$c`, `$(…)`, `${…}`) or when the command is `eval`, `source` or `.`.
- `args`: each argument after quote removal, marked **DYNAMIC** when it holds
  an unresolved expansion, and **GLOB** when it holds unquoted `*?[`.
- `feeds_shell`: true when stdin comes from a heredoc or here-string and the
  command is a shell (`bash`, `sh`, `zsh`, `dash`, `python3 -`, …). The body
  is then parsed and classified recursively; the existing heredoc handling
  moves into the walker.

Rules then match on **structure**, not text:

- *exfiltration*: a network client (`curl`, `wget`, `nc`, …) whose args
  reference a sensitive path or `@file`, or whose output is piped into a
  shell;
- *secret_access*: any command whose resolved path argument falls under a
  sensitive root (`~/.ssh`, `~/.gnupg`, credential files). Paths are
  normalised after quote removal (`~/.s''sh` becomes `~/.ssh`), and a GLOB
  path is tested against the sensitive roots as a pattern;
- *destructive*: `rm` with recursive and force flags on a root-like target,
  judged on the target argument, never on text inside another command's
  quoted argument (fixing the `echo 'rm -rf /'` false positive).

**Policy for what cannot be judged**, one row per case:

| Case | Proposed policy |
|---|---|
| unparseable (ERROR/MISSING nodes) | **refuse** (`scan_unparseable`) |
| DYNAMIC command name | refuse, unless the expansion is in a small allowlist of worker-provided variables (`$WILLOW_PYTHON`, `${WILLOW_PYTHON:-python3}`, `$PYTHON`), which already appear in `_FLEET_ALLOWED` |
| `eval`, `source`, `.` with a DYNAMIC argument | refuse |
| DYNAMIC or GLOB argument to a network client or into a sensitive root | refuse |
| DYNAMIC argument elsewhere | allow (the sandbox decides) |

Refusing DYNAMIC command names is the largest behaviour change. Section 6
measures it before it ships.

## 5. What stays

- The structural checks in step 2 of section 1 (control characters, heredoc
  wrapper collision, hook tamper, systemd, tree rewrite). The hook-tamper
  and systemd checks gain the same quote-aware command-name view, which
  closes the same bypass classes for them.
- The refusal payload and `scan_ledger.record_block` capture.
- `security_scan.scan_output` and `scan_write`, which are text scans of
  output and file content where regexes are the right tool.

## 6. Migration

1. **Shadow mode.** Add the parser classifier behind `KART_SCAN_ENGINE=shadow`.
   The regex verdict still decides, and the parser verdict is computed and
   recorded next to it in `scan_ledger` as `{regex, parser, agree}`. No
   behaviour change.
2. **Corpus.**
   - `scan_ledger` blocks, which are real refusals, plus false-positive
     annotations.
   - Today's `tests/test_task_scan.py` (82 tests) and `tests/test_scans_fire.py`
     (66 tests).
   - The bypass table from section 1.
   - A sample of real task bodies from the Postgres task table, allowed
     ones included, to measure new false positives. That is operator data
     and needs a go.
3. **Gate to switch.** On the corpus, the parser must block everything the
   regex blocks that is not an annotated false positive, and must block
   every bypass row. Every new block it adds on allowed tasks gets reviewed
   by hand. Then `KART_SCAN_ENGINE=parser` with the regex scan kept as a
   second opinion that can only *add* a block, never remove one.
4. **Remove the text rules** that the classifier covers, once a release has
   run with `parser` and the ledger shows no regressions.

## 7. Tests

- Golden cases per rule, with each bypass shape from section 1 written as a
  test that must block.
- False-positive cases (quoted mentions in `echo`/`grep`/`git commit -m`)
  that must allow.
- A differential test over the corpus in shadow mode.
- Mutation proof as for every Kart change: drop quote removal, treat DYNAMIC
  as static, skip nested substitutions, skip heredoc recursion. Each must
  turn a test red.
- A fuzz pass: random concatenations of quoting forms around the sensitive
  words must never flip a block to an allow.

## 8. Questions for the operator

1. **Dependency:** tree-sitter-bash (recommended), bashlex (GPL-3.0), or a Go
   `shfmt` binary?
2. **DYNAMIC command names:** refuse by default, with the worker-variable
   allowlist, as proposed? This is the change most likely to refuse
   existing tasks, and shadow mode will show how many.
3. **Corpus access:** may shadow mode sample real task bodies (allowed ones
   included) to measure false positives?
4. Should the bypass rows in section 1 be tightened in the **regex scanner
   now** as a stopgap (normalising quotes before matching closes the first
   and fourth rows cheaply), or left to the parser?
