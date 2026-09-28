# Kartikeya

> Skanda · Murugan — the six-faced commander of the divine armies, born to lead
> the devas. The engine that marshals and runs a fleet's tasks. Colloquially:
> **Kart**.

A standalone, host-agnostic **task queue + sandboxed worker**. Submit shell (or,
optionally, LLM-workflow) tasks to a queue; a worker claims them and runs each in
a [bubblewrap](https://github.com/containers/bubblewrap) sandbox with an explicit
mount/credential/network policy.

Kartikeya is the execution engine extracted from the Willow fleet
(`willow-2.0/core/kart_*` — historical path) and made to stand on its own — no fleet, no specific
host, no required database server.

## Status

**Extracted and published.** The sandbox/worker/execute core is fully landed
(`sandbox.py`, `worker.py`, `execute.py`, `queue.py`), tested, and released on
PyPI as `kartikeya` — `pip install kartikeya` gets whatever the latest tag
published (see `.release-please-manifest.json` for the version this tree
currently reports), or `pip install willow-mcp`, which depends on it and
floors it at whatever range willow-mcp's own `pyproject.toml` currently pins
— naming the number here would only go stale the next time either project
tags a release. The cap is a real
compatibility range rather than decoration: `bump-minor-pre-major` is **false**
here, so a breaking change cuts 1.0.0 instead of hiding in a minor. The staged lift in `docs/DESIGN.md` is done
through stage 4; stage 5 (legacy fleet monolith deleting its `core/kart_*` copy) is
tracked in willow-mcp#111.

## Design goals

- **Host-agnostic.** The only coupling — "where do tasks live" — is a small
  `TaskQueue` interface a host implements. Kartikeya owns the sandbox, worker
  loop, lanes, and command scan; the host owns storage and file roots.
- **Zero-infra by default.** Ships a reference `SqliteTaskQueue`, so
  `pip install kartikeya` can execute tasks with no Postgres and no fleet.
- **Backend-swappable.** SQLite (bundled), Postgres, or a custom backend behind
  the same interface.
- **Sandboxed and network-gated.** Tasks run network-isolated unless the stored
  task text carries a `# allow_net` directive; inference credentials reach only
  network-enabled tasks. GitHub credentials never enter the sandbox on any
  mode: a task that needs to push asks the host, which holds the key and
  performs the push under its own authorization. (Who is allowed to *write*
  that directive is the host's call — see the security note in `docs/DESIGN.md`.)

## Install

```
pip install kartikeya            # base: shell tasks, SQLite backend
pip install "kartikeya[postgres]"  # + Postgres backend helpers
pip install "kartikeya[llm]"       # + LLM-workflow task type
```

## Quickstart

Resource caps (memory + PID limits) prefer a delegated cgroup parent. On a fresh
install, run once:

```
kartikeya setup-cgroup    # installs ~/.config/systemd/user/kart.slice
kartikeya cgroup-status   # should print ready: /sys/fs/cgroup/...
```

**systemd worker (operative):** a shell profile `export` does not reach a
user-service kart worker. After `setup-cgroup` succeeds, wire the parent into the
worker environment and restart:

```
systemctl --user set-environment KART_CGROUP_PARENT=/sys/fs/cgroup/.../kart.slice
systemctl --user restart <your-kart-worker-unit>
```

(Or set `Environment=KART_CGROUP_PARENT=...` in a drop-in for the worker unit.)

The `export` line printed by `setup-cgroup` is for **CLI / interactive** runs
only. Without a delegated parent, Kart falls back to task-scoped `prlimit`/`ulimit` inside the
sandbox (PID cap by default; virtual-memory cap only with `KART_RLIMIT_USE_AS=1`).
`WILLOW_KART_NO_RLIMIT=1` disables caps entirely (escape hatch only).

With a delegated parent, each task gets its own cgroup leaf. If that leaf cannot
be created, configured or joined, the task is **refused**
(`cgroup_setup_failed` / `cgroup_join_failed`) rather than run without its
memory cap.

**Concurrency per worker process:** the `fast` lane runs up to
`KART_FAST_WORKERS` tasks at once (default 3) and the `batch` lane up to
`KART_BATCH_WORKERS` (default 1, since batch work is long and heavy). `kartikeya
worker --slots N` overrides either. Like `KART_CGROUP_PARENT`, set these in the
worker unit's `Environment=`, then restart it.

**Landlock (second filesystem lock):** `KART_LANDLOCK` puts a kernel Landlock
ruleset behind bwrap, allowing only the paths bwrap mounts: read-only binds
get read and execute, and read-write binds get full rights except where one
has to be carved around a read-only path (see below). In plain mode
(`WILLOW_KART_NO_BWRAP=1`) it is the only filesystem confinement, and the host's
`/tmp` is not granted, so give tasks a writable bind for scratch.

- `off` (default): unchanged.
- `auto`: apply when the kernel supports Landlock (5.13+); otherwise run without
  it, marked `landlock: "unsupported"` in the result and logged once.
- `enforce`: apply, and refuse the task (`landlock_unavailable`) when the kernel
  has no Landlock.

In both `auto` and `enforce`, a failure to apply the ruleset refuses the task
(`landlock_failed`); it never runs unconfined. The result's `landlock` field
records the ABI version that confined it. Try `auto` on one worker before
turning it on everywhere.

Landlock can only *add* rights, so a read-only path inside a read-write bind
(a repo's `.git/hooks` inside the writable repo, say) needs protecting from the
parent's read-write rule. **Under bwrap it already is**: every `--ro-bind` is a
read-only mount, which refuses writes whatever Landlock allows and cannot be
renamed or removed. The launcher checks the live mount flags, and leaves the
parent fully writable for such paths, so git works: it can create
`.git/index.lock` beside a read-only `.git/hooks` and `.git/config`.

A read-only path that is *not* on a read-only mount (every one in plain mode,
or under bwrap one shadowed by a later bind or a `--ro-bind-try` whose source
is missing) is protected by **carving**: the read-write parent gets read-only
rights at its own level, and each of its other entries gets read-write. The
cost is that nothing can be created or removed *directly in* a carved
directory. **In plain mode, a policy that nests read-only paths inside
writable repos is therefore not compatible with `KART_LANDLOCK` for git
work**: `git commit` cannot write `.git/index.lock`. The worker logs a warning
naming the carved directories the first time a policy carves any. Paths are
resolved through symlinks, and carving walks the tree by file descriptor
without following links.

_Coming with stage 2 — once the worker core lands, this section documents
`kartikeya worker` end to end (submit → worker runs → poll)._

## License

MIT © Sean Campbell
