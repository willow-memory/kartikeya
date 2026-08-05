"""
worker.py — Kartikeya task-queue consumer.

Lifted from willow-2.0 core/kart_worker.py, decoupled: the Postgres bridge is
replaced by the `TaskQueue` seam, fleet telemetry (SOIL heartbeat, run-ledger)
becomes optional callbacks, and the Grove governance gate / hot-reload are
dropped. Two lanes:

  fast  — up to N concurrent slots (default $KART_FAST_WORKERS or 3).
  batch — one task at a time.

`main()` backs the `kartikeya` / `kart` console scripts: it constructs the
reference SqliteTaskQueue and drains it, so a zero-infra install runs tasks.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .cgroup_setup import cgroup_status, setup_cgroup
from .execute import (
    NetworkAuthorizer,
    TaskTypeHandler,
    execute_task_row,
    kart_timeout,
    trim_task_result,
)
from .home import willow_home
from .lanes import KART_LANE_BATCH, KART_LANE_FAST, fast_worker_slots, normalize_lane
from .queue import SqliteTaskQueue, TaskQueue, TaskRow

logger = logging.getLogger("kartikeya.worker")

# Optional telemetry seams (replace willow-2.0's loop_heartbeat / run_ledger).
HeartbeatFn = Callable[..., None]           # on_heartbeat(lane=..., tick_ok=...)
RunEventFn = Callable[..., None]            # on_run_event(event, row, status=None)


def _noop(*_a, **_k) -> None:
    return None


def _process_row(
    queue: TaskQueue,
    row: TaskRow,
    *,
    context: str,
    lane: str | None = None,
    handlers: dict[str, TaskTypeHandler] | None,
    network_authorizer: NetworkAuthorizer | None,
    on_run_event: RunEventFn,
) -> tuple[str, dict]:
    """Execute one claimed row and record terminal state via the queue.

    `lane` picks the subprocess ceiling: the fast lane is capped shorter than
    batch so a hung task cannot sit on one of its few slots (see kart_timeout).
    """
    on_run_event("open", row)
    try:
        status, result = execute_task_row(
            row,
            timeout=kart_timeout(context, lane=lane),
            context=context,
            handlers=handlers,
            network_authorizer=network_authorizer,
        )
    except Exception as e:  # defense in depth — execute_task_row already guards
        status, result = "failed", {"error": str(e), "context": f"{context}_exception"}
    try:
        queue.mark_done(
            row.task_id, status=status, result=json.dumps(trim_task_result(result, status))
        )
    except Exception as e:
        logger.error("mark_done failed for %s: %s", row.task_id, e)
    on_run_event("close", row, status=status)
    if status == "completed":
        logger.info("kart complete %s", row.task_id)
    else:
        logger.warning("kart failed %s: %s", row.task_id, result.get("error", result))
    return status, result


def _maybe_reap_and_prune(queue: TaskQueue) -> None:
    """Optional backend maintenance — only if the backend implements it.

    Runs on every poll, so the first pass is also the startup sweep: a worker
    that was killed mid-task leaves rows 'running' with nothing left to finish
    them, and the next worker to start recovers them. Whatever `reap_stale`
    returns is logged — a reclaim is never silent.
    """
    for name in ("reap_stale", "prune_completed"):
        fn = getattr(queue, name, None)
        if not callable(fn):
            continue
        try:
            outcome = fn()
        except Exception as e:
            logger.warning("%s failed: %s", name, e)
            continue
        if name == "reap_stale" and outcome:
            logger.warning(
                "kart reaped stale running task(s) — claim outlived its lease, "
                "worker presumed dead: %s",
                outcome,
            )


def run_worker(
    queue: TaskQueue,
    *,
    lane: str = KART_LANE_FAST,
    slots: int | None = None,
    interval: float = 5.0,
    agent: str = "kart",
    once: bool = False,
    handlers: dict[str, TaskTypeHandler] | None = None,
    network_authorizer: NetworkAuthorizer | None = None,
    on_heartbeat: HeartbeatFn | None = None,
    on_run_event: RunEventFn | None = None,
) -> None:
    """Drain `queue` until stopped (or, with once=True, until it is empty).

    lane: 'fast' runs up to `slots` tasks concurrently and caps each task at
    `KART_FAST_TIMEOUT` (300s); 'batch' runs one at a time under the longer
    `KART_DAEMON_TIMEOUT` (1800s). `once=True` claims and processes everything
    currently pending, waits for in-flight work, and returns — for tests and
    cron-style one-shot drains (which use the short 'poll' ceiling instead).

    `network_authorizer` is an optional host-supplied gate consulted just before
    a network-requesting task's sandbox launches (see execute_task_row). Left
    None, no gate runs and behavior is unchanged.
    """
    lane = normalize_lane(lane)
    on_heartbeat = on_heartbeat or _noop
    on_run_event = on_run_event or _noop
    context = "poll" if once else "daemon"
    max_workers = 1 if lane == KART_LANE_BATCH else (slots if slots is not None else fast_worker_slots())

    in_flight: set[str] = set()
    lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="kart")

    def _run(row: TaskRow) -> None:
        try:
            _process_row(
                queue,
                row,
                context=context,
                lane=lane,
                handlers=handlers,
                network_authorizer=network_authorizer,
                on_run_event=on_run_event,
            )
        finally:
            with lock:
                in_flight.discard(row.task_id)

    try:
        while True:
            on_heartbeat(lane=lane, tick_ok=True)
            _maybe_reap_and_prune(queue)
            with lock:
                free = max_workers - len(in_flight)
            claimed: list[TaskRow] = []
            if free > 0:
                try:
                    claimed = queue.claim_pending(agent, free, lane=lane)
                except Exception as e:
                    logger.error("claim_pending failed: %s", e)
                    claimed = []
                for row in claimed:
                    with lock:
                        in_flight.add(row.task_id)
                    pool.submit(_run, row)
            if once:
                with lock:
                    idle = not in_flight
                if idle and not claimed:
                    break
                time.sleep(0.05)
                continue
            with lock:
                busy = bool(in_flight)
            time.sleep(0.5 if busy else interval)
    finally:
        pool.shutdown(wait=True)


# ── console entry point ────────────────────────────────────────────────────

def _default_queue() -> TaskQueue:
    db = os.environ.get("KART_DB", "").strip()
    if not db:
        db = str(willow_home() / "kart.db")
    Path(db).expanduser().parent.mkdir(parents=True, exist_ok=True)
    return SqliteTaskQueue(db)


def _cmd_setup_cgroup(args: argparse.Namespace) -> int:
    result = setup_cgroup(start=not args.no_start)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result.get("export_line"):
            print(result["export_line"])
        print(result.get("hint", ""))
        for err in result.get("errors") or []:
            print(f"error: {err}", file=sys.stderr)
    return 0 if result.get("ok") else 1


def _cmd_cgroup_status(args: argparse.Namespace) -> int:
    status = cgroup_status()
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        if status.get("ready"):
            print(f"ready: {status['resolved_parent']}")
        else:
            print("not ready — run: kartikeya setup-cgroup")
            if status.get("systemd_parent"):
                print(f"  systemd path: {status['systemd_parent']} (invalid or busy)")
    return 0 if status.get("ready") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kartikeya",
        description="Kartikeya — sandboxed task queue worker (a.k.a. Kart).",
    )
    sub = parser.add_subparsers(dest="command")
    wp = sub.add_parser("worker", help="run the task queue worker (default)")
    wp.add_argument("--lane", default=KART_LANE_FAST, choices=[KART_LANE_FAST, KART_LANE_BATCH])
    wp.add_argument("--slots", type=int, default=None)
    wp.add_argument("--interval", type=float, default=5.0)
    wp.add_argument("--once", action="store_true", help="drain the queue and exit")
    wp.add_argument("--db", default=None,
                    help="SQLite queue path (default $KART_DB or $WILLOW_HOME/kart.db)")
    wp.add_argument("-v", "--verbose", action="store_true")

    cp = sub.add_parser(
        "setup-cgroup",
        help="provision kart.slice (Delegate=memory pids) for cgroup resource caps",
    )
    cp.add_argument("--no-start", action="store_true", help="install unit only, do not start")
    cp.add_argument("--json", action="store_true", help="emit machine-readable result")

    sp = sub.add_parser("cgroup-status", help="check delegated cgroup parent readiness")
    sp.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    command = args.command or "worker"

    if command == "setup-cgroup":
        return _cmd_setup_cgroup(args)
    if command == "cgroup-status":
        return _cmd_cgroup_status(args)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    queue = SqliteTaskQueue(args.db) if args.db else _default_queue()
    logger.info("kartikeya worker starting (lane=%s, once=%s)", args.lane, args.once)
    try:
        run_worker(queue, lane=args.lane, slots=args.slots,
                   interval=args.interval, once=args.once)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
