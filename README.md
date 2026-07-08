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

**Pre-alpha, under active extraction.** This repo is the target of a staged lift
described in `docs/DESIGN.md`. The scaffold and the `TaskQueue` interface are in
place; the sandbox/worker/execute core is being decoupled from its origin and
brought over next.

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

_Coming with stage 2 — once the worker core lands, this section documents
`kartikeya worker` end to end (submit → worker runs → poll)._

## License

MIT © Sean Campbell
