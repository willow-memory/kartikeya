# kartikeya — idea pile

This repo's numbered idea pile, in the shape willow-reconciler reads: top-level
`N. ` items, optional legend tags, stable numbers. It is read by

```sh
reconciler run --repo ./ --doc docs/ideas.md --validate
```

and every `Idea-Id` trailer in this repo's history is resolved against it by
`reconciler verify --repo ./ --doc docs/ideas.md` (`.github/workflows/trailers.yml`).

Legend: ✅ shipped · 🟡 partial · (untagged) proposed

**Numbers are permanent join keys.** `reconciler/ids.py` derives
`<corpus>-ideas-<num>` from the number written on the line (`willow-ideas-NNN`
in willow-reconciler 0.6.0, the corpus being the fleet's), so a number is an
identity, not an ordinal. Never renumber; never write a markdown-auto-numbered
list (`1.` repeated) here — retire a number instead and leave the gap.

Every item below was carried from something this repo already recorded — the
staged plan in `docs/DESIGN.md`, a comment in the source that names deferred
work, a placeholder in the README, or a follow-up written on one of this
repo's pull requests — with its source named. Nothing here was invented for
the pile. A legend tag counts only where git history shows the landing.

---

## A. The lift (`docs/DESIGN.md` §8–9)

Stages 1–4 of the lift shipped and were released as PyPI 0.0.7 (DESIGN.md's
status line). What remains is what §8 numbered 5 and 6. (A line here must not
begin with digits and a dot: the parser would read it as an item.)

1. Stage 5: the legacy fleet monolith migration — point the monolith at the `kartikeya` package and delete its `core/kart_*` copy, ending the drift the shared-package decision was made to end. Deferred by design (§9, "ship willow-mcp value first"); tracked in willow-mcp#111. DESIGN.md §8.5.
2. Stage 6: the `kart[llm]` extra — the LLM/workflow task type behind an optional extra. Today `execute_task_row` routes those task types to a host-supplied handler and fails cleanly with none (`execute.py`); `pyproject.toml`'s `llm` extra is empty. DESIGN.md §7 and §8.6.
3. Stage 6: systemd worker-unit templates. The README quickstart documents the manual route (`systemctl --user set-environment KART_CGROUP_PARENT=…`, or an `Environment=` drop-in); a shipped unit template would replace the hand steps. DESIGN.md §8.6.
4. Stage 6: batch-lane polish. Recorded in DESIGN.md §8.6 without further detail; carried as written.

## B. Sandbox and scan

5. ✅ **shipped**: memory and PID caps for tasks through a delegated cgroup parent (`kartikeya setup-cgroup` installs `kart.slice` with `Delegate=memory pids`; `cgroup_setup.py`), with a task-scoped rlimit fallback when no parent is delegated. The setup path and the rlimit fallback were fixed in PR #9, the auto-detect and subtree delegation in PR #11. One comment lags it: `security_scan.py` above `_RESOURCE_EXHAUSTION` still says the sandbox "imposes no memory/CPU/PID cgroup limit" and leaves a memory hog "to a future cgroup cap".
6. A `--seccomp` syscall filter for the bwrap sandbox (audit item S13). Deferred pending a libseccomp/BPF toolchain decision; `--new-session` already covers the CVE-2017-5226 vector. `sandbox.py`, the bwrap-argument comment.
7. The task scan reads only the first line of a plain multi-line body: a benign line 1 lets a dangerous line 2 through the scan even though the worker runs both. Carried from the monolith and pinned as a visible gap by `test_multiline_plain_body_only_scans_first_line` ("tracked as a follow-up"). `tests/test_task_scan.py`.

## C. Docs and comments that lag the tree

8. The README quickstart still ends "Coming with stage 2 — once the worker core lands, this section documents `kartikeya worker` end to end (submit → worker runs → poll)". Stage 2 landed in July 2026; the section was never written. Write it. `README.md`.
9. `.github/workflows/release-please.yml`'s "Make the GitHub Release body" step comment still says "this has never run here, and cannot yet. There is no CHANGELOG.md and no release-please release commit in this repo's history". The same class of stale claim was corrected in the tests and the tool's docstring by #55 and #56; this is the one file they did not reach. A `ci:` fix.
10. `tools/changelog_dedup.py` lines 291–292, inside the body pinned byte-for-byte to Forge's, say "The normal state of this repo today: release-please has never written one" — stale here. The pin (`tests/test_vendor_pins.py`) goes red on a local edit, so the fix belongs upstream in Forge and then a re-sync. Noted on the Wave 2 pull request as seen-not-touched.

## D. The fleet plan in this repo

11. ✅ **shipped**: T1 canon — the README names no version literal and points at the manifest and willow-mcp's own pin; the changelog tool's docstring matches the tree; both guarded by tests with planted violations. PR #55.
12. ✅ **shipped**: the T1 residue in `tests/test_release_wiring.py` — two docstrings dated instead of stale, and the three tests that skipped on every run now stage the tool's pre-release states in a temporary repo root instead. PR #56.
13. ✅ **shipped**: the vendored `tools/changelog_dedup.py` body pinned to Forge's by sha256 in `tests/test_vendor_pins.py`, planted both ways (a one-byte body change moves the hash; a docstring change does not). PR #56.
14. ✅ **shipped**: the meta-scan, `tests/test_scans_fire.py` — every scan helper in `tests/` shown to fire by a planted violation, both halves, itself planted; four never-fired scans found on port and planted. PR #56.
15. ✅ **shipped**: this tree held to the fleet's published conventions — `tests/test_fleet_conventions.py` reads every rule from the vendored, sha256-pinned `tests/fleet_conventions.json`; `CONTRIBUTING.md` names the test command CI runs. PR #57.
16. ✅ **shipped**: a numbered idea pile in the reconciler's form — this file — so the fleet's evidence loop has a doc side here. Landed by the commit that introduced it, which carries this item's own trailer, the first resolvable `Idea-Id` in this repo's history.
17. ✅ **shipped**: adopt `Idea-Id` commit trailers (fleet CONVENTION, decision-2026-09-11): `.github/workflows/trailers.yml` runs `reconciler verify` on every push and pull request to `master`, and `CONTRIBUTING.md` carries the convention and the commands that emit a trailer.
18. `tests/test_release_wiring.py::test_only_types_that_change_the_installed_package_cut_a_release` restates the hidden and release-cutting type sets as literals; `tests/test_fleet_conventions.py` reads both from the published document. Make the older test read them from the same document, or retire the restatement. Noted on #57 as seen-not-touched.
19. `tests/test_cgroup_setup.py` imports `pytest` and never uses it (pyflakes). Hygiene, noted on #56.
