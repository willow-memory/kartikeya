# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Everything below was written by hand, after the fact.** Tags v0.0.1 through
v0.0.9 were cut manually between 2026-07-08 and 2026-08-02; release-please only
arrived on 2026-08-03, after the last of them, and every commit since has been
`ci:` — which is hidden and cuts no release. So this file starts as a
reconstruction from tags and commit subjects, not as a generated artifact, and
it is the reason the repository had no changelog at all until now.

From the first release release-please cuts, it maintains this file: each entry
built from the conventional-commit prefixes on `master`, prepended above this
line with a `## [x.y.z](…/compare/…)` header carrying a compare link. The
hand-written sections below deliberately have no such link, which is also how
`tools/changelog_dedup.py` tells the two apart — it only ever rebuilds a
generated section, and leaves this history alone.

Two gaps are real rather than typos:

* **0.0.4 and 0.0.6 were never tagged.** Work that would have carried those
  numbers shipped inside 0.0.5 and 0.0.7.
* **0.0.8 never reached PyPI.** The tag was cut on a commit whose version was
  still 0.0.7, the build produced 0.0.7, and PyPI rejected the duplicate — the
  failure that prompted moving to tag-derived versioning in 0.0.9 and to
  release-please afterwards. That version number is spent and cannot be reused.

Note what release-please will not list once it takes over: `docs:`, `test:`,
`ci:` and `chore:` are hidden. Those commits ship inside the next real release
rather than cutting one of their own — see `release-please-config.json`.

## [0.0.11](https://github.com/willow-memory/kartikeya/compare/v0.0.10...v0.0.11) (2026-08-24)


### Build

* **deps:** bump googleapis/release-please-action from 4 to 5 ([6dde1b6](https://github.com/willow-memory/kartikeya/commit/6dde1b6991246328e23f77cd6dcd5e104873eb26))

## [0.0.10](https://github.com/rudi193-cmd/kartikeya/compare/v0.0.9...v0.0.10) (2026-08-05)


### Fixed

* **queue:** drop the duplicate network_authorization on TaskRow ([e7a9ad1](https://github.com/rudi193-cmd/kartikeya/commit/e7a9ad1178ab615c9e2cac7319068e10e77c7583))
* **lanes:** restore the fast lane's own timeout ceiling ([eea5768](https://github.com/rudi193-cmd/kartikeya/commit/eea57683d7143a384d5f19821410e04ac1ef73c7))
* **queue:** reclaim tasks whose worker died mid-run ([79b81b9](https://github.com/rudi193-cmd/kartikeya/commit/79b81b90ad0a179bfeef44d2762f4a38d30f0ddc))

## 0.0.9 — 2026-08-02

### Build

* Derive the version from the git tag (hatch-vcs), so no file in the tree
  carries a version that can drift from the one being released. This is the
  direct answer to the 0.0.8 failure.

### Docs

* Close the documented-versus-actual drift: extraction had landed and shipped,
  and the DRAFT marker was lifted.

## 0.0.8 — 2026-07-22

**Not on PyPI** — see the note above.

### Added

* Report which sandbox policy was resolved, so a task's effective policy is
  visible rather than inferred.

## 0.0.7 — 2026-07-21

### Fixed

* cgroup auto-detection and slice subtree delegation.
* Greenfield resource caps: the cgroup setup path, and a task-safe rlimit
  fallback for hosts without cgroup v2.

### Security

* Gate the Postgres socket and `PG*` environment behind an explicit `allow_db`
  opt-in, rather than exposing them to every sandboxed task.

## 0.0.5 — 2026-07-21

### Security

* Require host authorization for network tasks.
* Gate `# allow_localhost` the same way as `# allow_net`, closing the gap where
  loopback was reachable without an explicit grant.
* Overlay `config/consent.json` — and the consent files generally — read-only
  inside the sandbox, so a task can read policy but not rewrite it.

### Changed

* Prefer willow-mcp over legacy fleet monolith when resolving mount policy.
* `KART_EXTRA_VENVS` injects fleet venv paths, unblocking legacy fleet monolith delegation.

## 0.0.3 — 2026-07-18

### Added

* The pre-launch network authorization seam.

## 0.0.2 — 2026-07-18

### Added

* Per-task memory and PID caps (cgroup v2, with an rlimit fallback).

### Security

* `security_scan` coverage for the resource-exhaustion class and the
  destructive-operation gaps it had been missing.

## 0.0.1 — 2026-07-08

### Added

* Initial extraction into a standalone package: the kartikeya skeleton and the
  `TaskQueue` seam, then lanes, `security_scan` and `task_scan` decoupled, the
  sandbox core with home/pyenv seams and neutral config, and finally execute and
  worker lifted over the queue seam with a standalone end-to-end run green.
* PyPI metadata plus Tests and Release CI.

### Build

* Publishing uses a `PYPI_API_TOKEN` secret rather than OIDC Trusted
  Publishing, and `release.yml` sets `attestations: false` to match. The two
  travel together — a token-authenticated upload cannot produce a PEP 740
  attestation — and `tests/test_release_wiring.py` checks they stay in step.
