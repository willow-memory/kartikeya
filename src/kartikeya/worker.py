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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .execute import TaskTypeHandler, execute_task_row, kart_timeout, trim_task_result
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
    handlers: dict[str, TaskTypeHandler] | None,
    on_run_event: RunEventFn,
    network_authorizer: "Callable[[TaskRow, str], bool] | None" = None,
) -> tuple[str, dict]:
    """Execute one claimed row and record terminal state via the queue."""
    on_run_event("open", row)
    try:
        status, result = execute_task_row(
            row, timeout=kart_timeout(context), context=context, handlers=handlers,
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
    """Optional backend maintenance — only if the backend implements it."""
    for name in ("reap_stale", "prune_completed"):
        fn = getattr(queue, name, None)
        if callable(fn):
            try:
                fn()
            except Exception as e:
                logger.warning("%s failed: %s", name, e)


def run_worker(
    queue: TaskQueue,
    *,
    lane: str = KART_LANE_FAST,
    slots: int | None = None,
    interval: float = 5.0,
    agent: str = "kart",
    once: bool = False,
    handlers: dict[str, TaskTypeHandler] | None = None,
    on_heartbeat: HeartbeatFn | None = None,
    on_run_event: RunEventFn | None = None,
    network_authorizer: "Callable[[TaskRow, str], bool] | None" = None,
) -> None:
    """Drain `queue` until stopped (or, with once=True, until it is empty).

    lane: 'fast' runs up to `slots` tasks concurrently; 'batch' runs one at a
    time. `once=True` claims and processes everything currently pending, waits
    for in-flight work, and returns — for tests and cron-style one-shot drains.

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
            _process_row(queue, row, context=context,
                         handlers=handlers, on_run_event=on_run_event,
                         network_authorizer=network_authorizer)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kartikeya",
        description="Kartikeya — sandboxed task queue worker (a.k.a. Kart).",
    )
    parser.add_argument("command", nargs="?", default="worker", choices=["worker"])
    parser.add_argument("--lane", default=KART_LANE_FAST, choices=[KART_LANE_FAST, KART_LANE_BATCH])
    parser.add_argument("--slots", type=int, default=None)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--once", action="store_true", help="drain the queue and exit")
    parser.add_argument("--db", default=None,
                        help="SQLite queue path (default $KART_DB or $WILLOW_HOME/kart.db)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

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
