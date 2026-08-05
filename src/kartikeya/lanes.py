"""Kart execution lanes — separate interactive work from long batch jobs.

* ``fast`` — default; drained by ``kart_task_run`` / session ``kart_poll`` and
  ``kart-worker.service`` (``KART_WORKER_LANE=fast``).
* ``batch`` — long GPU/CPU work; ``kart-worker-batch.service``
  (``KART_WORKER_LANE=batch``) runs concurrently with fast workers.
"""
from __future__ import annotations

import os

KART_LANE_FAST = "fast"
KART_LANE_BATCH = "batch"
KART_LANES = (KART_LANE_FAST, KART_LANE_BATCH)
KART_WORKER_MODE_FAST = "fast"
KART_WORKER_MODE_BATCH = "batch"
KART_WORKER_MODE_ALL = "all"


def normalize_lane(lane: str | None) -> str:
    if lane is None or lane == "" or lane == KART_LANE_FAST:
        return KART_LANE_FAST
    if lane == KART_LANE_BATCH:
        return KART_LANE_BATCH
    raise ValueError(f"unknown kart lane: {lane!r} (expected fast|batch)")


def worker_mode() -> str:
    """Which lane(s) this kart-worker process claims.

    ``fast`` (default) — interactive shell/gh/git; may run N concurrent tasks.
    ``batch`` — one long job at a time (embeds, ingest, GPU).
    ``all`` — legacy single-threaded fast-then-batch (deprecated).
    """
    raw = (os.environ.get("KART_WORKER_LANE") or KART_WORKER_MODE_FAST).strip().lower()
    if raw in (KART_WORKER_MODE_FAST, KART_WORKER_MODE_BATCH, KART_WORKER_MODE_ALL):
        return raw
    raise ValueError(
        f"unknown KART_WORKER_LANE: {raw!r} (expected fast|batch|all)"
    )


def fast_worker_slots() -> int:
    return max(1, int(os.environ.get("KART_FAST_WORKERS", "3")))


def reaper_stale_seconds() -> int:
    return int(os.environ.get("KART_STALE_SECONDS", "3600"))


def daemon_timeout_seconds() -> int:
    return int(os.environ.get("KART_DAEMON_TIMEOUT", "1800"))


def fast_timeout_seconds() -> int:
    """Fast-lane subprocess ceiling. The fast lane is interactive and has only a
    few slots (``fast_worker_slots()``), so it gets a SHORT ceiling of its own
    (default 300s) rather than inheriting the 1800s daemon timeout — one hung
    task must not hold a third of the lane's capacity for half an hour. Batch
    keeps ``daemon_timeout_seconds()`` (1800s)."""
    return int(os.environ.get("KART_FAST_TIMEOUT", "300"))


_REAPER_BUFFER_SECONDS = 300


def reaper_alignment_warning() -> str | None:
    """The stale reaper is defence-in-depth, not the primary kill: every lane's
    task should die by its own timeout, never by the reaper. So the reaper must
    sit above the LARGEST per-lane timeout + buffer — covering both the
    batch/daemon ceiling and the fast ceiling, which flags e.g. a misconfigured
    fast timeout set at or above the reaper."""
    stale = reaper_stale_seconds()
    daemon = daemon_timeout_seconds()
    fast = fast_timeout_seconds()
    largest = max(daemon, fast)
    need = largest + _REAPER_BUFFER_SECONDS
    if stale < need:
        which = "KART_DAEMON_TIMEOUT" if daemon >= fast else "KART_FAST_TIMEOUT"
        return (
            f"KART_STALE_SECONDS ({stale}) < largest lane timeout"
            f" ({which}={largest}) + {_REAPER_BUFFER_SECONDS}s buffer —"
            " reaper may mark tasks stale before their own timeout kills them"
        )
    return None
