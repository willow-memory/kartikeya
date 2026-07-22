# Kartikeya

> Skanda · Murugan — the six-faced commander of the divine armies, born to lead
> the devas. The engine that marshals and runs a fleet's tasks. Colloquially:
> **Kart**.

A standalone, host-agnostic **task queue + sandboxed worker**. Submit shell (or,
optionally, LLM-workflow) tasks to a queue; a worker claims them and runs each in
a [bubblewrap](https://github.com/containers/bubblewrap) sandbox with an explicit
mount/credential/network policy.

Kartikeya is the execution engine extracted from the Willow fleet
(`willow-2.0/core/kart_*`) and made to stand on its own — no fleet, no specific
host, no required database server.

## Status

**Extracted and published.** The sandbox/worker/execute core is fully landed
(`sandbox.py`, `worker.py`, `execute.py`, `queue.py`), tested, and released on
PyPI as `kartikeya` (0.0.7) — `pip install kartikeya`, or `pip install
willow-mcp` which depends on it. The staged lift in `docs/DESIGN.md` is done
through stage 4; stage 5 (willow-2.0 deleting its `core/kart_*` copy) is
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
  task text carries a `# allow_net` directive; credentials reach only network-
  enabled tasks. (Who is allowed to *write* that directive is the host's call —
  see the security note in `docs/DESIGN.md`.)

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

_Coming with stage 2 — once the worker core lands, this section documents
`kartikeya worker` end to end (submit → worker runs → poll)._

## License

MIT © Sean Campbell
