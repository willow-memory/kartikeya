"""
scan_ledger.py — persistent record of scan blocks + human false-positive capture.

GAP #2b of the self-training architecture: a self-training loop needs a
labeled corpus of "the scanner blocked this" plus "a human later said that
block was wrong" before it can learn anything. This module is that capture
seam. It is deliberately dumb: it writes down what `check_kart_task` already
decided, and later lets a human annotate a decision as a false positive. It
never decides anything itself.

CAPTURE ONLY — no runtime authority.
    `record_false_positive` writes an annotation keyed to a `block_id`. That
    annotation is training metadata, full stop. Nothing in `task_scan.py`,
    `security_scan.py`, or the sandbox reads this ledger, and nothing here is
    wired to change a verdict. A task that was blocked stays blocked forever,
    no matter how many humans later annotate it as a false positive. Any
    future feature that lets an annotation influence a live scan decision is
    a different, explicitly-authorized change — not this one.

Fail-closed, always.
    Every write in this module is best-effort: wrapped in try/except so a
    logging failure (disk full, bad permissions, a broken sink in a host
    integration) can never raise past the scan/refusal path. The scan verdict
    is computed and returned before this module is ever consulted; a failure
    here can at most mean a block goes unlogged, never that a block is
    downgraded to an allow.

Injectable sinks — same idiom as worker.py's `RunEventFn`.
    `record_block` and `record_false_positive` both take an optional `sink`
    callable (a function of one dict, the record to persist). Left at the
    default, they append to a bounded JSONL ledger under kartikeya's run dir
    (`$WILLOW_HOME/.kart-logs/`, the same root `sandbox.py` already uses for
    per-task forensic logs). Kartikeya is network-isolated and must not import
    willow-mcp or assume any particular store — a host wires its own store by
    passing a `sink`, exactly as a host wires `on_run_event` into `run_worker`.

Willow-mcp-side training adapter (documented here, implemented there).
    Kartikeya never imports willow-mcp. A willow-mcp-side adapter reads this
    ledger (via `iter_block_records`, or by reading the JSONL files directly —
    the shape is stable) and maps each merged record to a training example:

        input          <- record["fragment"] or record["task_id"]/context
                          (the offending shell/script text the scanner saw)
        model_output    <- {"category": record["category"],
                             "severity": record["severity"]}
                          (the verdict the scanner produced)
        human_label     <- record["false_positives"]
                          (empty => no human signal yet; non-empty => a
                          demoting/negative signal: humans said this verdict
                          was wrong for this input — never a positive label
                          that a block was *correct*, since silence about a
                          block is not consent)

    That mapping is the adapter's job, not this module's; kartikeya only
    guarantees the record shape stays stable.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

# A sink appends one record (a JSON-serializable dict) to storage. Mirrors
# worker.py's RunEventFn injection idiom: default to a real writer, let a
# host or test pass its own.
SinkFn = Callable[[dict], None]

# Bound the ledger like sandbox.py bounds .kart-logs: keep the newest N
# records, drop the rest, so an unattended box can't grow this file forever.
BLOCK_LEDGER_RETENTION = 5000
FP_LEDGER_RETENTION = 5000


def _ledger_root() -> Path:
    from .home import willow_home

    return Path(willow_home()) / ".kart-logs"


def _block_ledger_path() -> Path:
    return _ledger_root() / "scan-blocks.jsonl"


def _fp_ledger_path() -> Path:
    return _ledger_root() / "scan-false-positives.jsonl"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _append_bounded(path: Path, record: dict, *, keep: int) -> None:
    """Append one JSON line to `path`, then truncate to the newest `keep`
    lines if it has grown past that. Not atomic against concurrent writers —
    this is a best-effort ledger, not a database; losing a rotation race
    loses log fidelity, never scan correctness.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, default=str)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    # Cheap bound check: only pay the read-and-rewrite cost once we're
    # comfortably past the retention window, not on every single append.
    try:
        if path.stat().st_size < 200_000:
            return
    except OSError:
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > keep:
        path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")


def _default_block_sink(record: dict) -> None:
    _append_bounded(_block_ledger_path(), record, keep=BLOCK_LEDGER_RETENTION)


def _default_fp_sink(record: dict) -> None:
    _append_bounded(_fp_ledger_path(), record, keep=FP_LEDGER_RETENTION)


def _block_identity(payload: dict, *, task_id: str) -> tuple[str, str, str, str, str]:
    scan = payload.get("kart_scan") or {}
    return (
        str(scan.get("category", "")),
        str(scan.get("severity", "")),
        str(scan.get("message", "")),
        str(scan.get("where", "")),
        str(task_id or ""),
    )


def _compute_block_id(payload: dict, *, task_id: str) -> str:
    """Stable content hash of the refusal payload + task identity, so an
    identical re-block (the same fragment blocked again on a retried task)
    dedups to the same block_id instead of growing a new row every retry.
    """
    identity = _block_identity(payload, task_id=task_id)
    digest = hashlib.sha256(
        "\x1f".join(identity).encode("utf-8", "replace")
    ).hexdigest()
    return f"blk_{digest[:24]}"


def record_block(
    payload: dict,
    *,
    task_id: str = "",
    context: str = "",
    sink: SinkFn | None = None,
) -> str:
    """Append a block-decision record for an already-computed scan refusal.

    `payload` is exactly what `check_kart_task` returned (the refusal dict
    with `error` and `kart_scan`). This function only records that decision;
    it never re-scans and never changes it. Returns the record's `block_id`
    (deterministic from the refusal's category/severity/message/where plus
    `task_id`), computed and returned even if the write itself fails, so a
    caller can still hand it to `record_false_positive` later.

    Best-effort: any exception from the sink (or from building the record) is
    swallowed. This must NEVER be allowed to raise into the scan/refusal
    path — a logging failure is a missed log line, never a missed block.
    """
    block_id = ""
    with contextlib.suppress(Exception):
        block_id = _compute_block_id(payload, task_id=task_id)
    if not block_id:
        # Even hashing failed (e.g. payload wasn't a dict) — still return a
        # usable, if degenerate, id rather than raising.
        block_id = "blk_unknown"

    with contextlib.suppress(
        Exception
    ):  # capture-only; never let logging affect the block
        scan = payload.get("kart_scan") or {}
        record = {
            "block_id": block_id,
            "ts": _now_iso(),
            "category": scan.get("category"),
            "severity": scan.get("severity"),
            "message": scan.get("message"),
            "where": scan.get("where"),
            "task_id": str(task_id or ""),
            "context": str(context or ""),
            "fragment": scan.get("fragment") or scan.get("cwd") or "",
            "error": payload.get("error"),
        }
        write = sink or _default_block_sink
        write(record)
    return block_id


def record_false_positive(
    block_id: str,
    *,
    note: str = "",
    who: str = "",
    sink: SinkFn | None = None,
) -> None:
    """Append a human false-positive annotation keyed to `block_id`.

    CAPTURE ONLY — grants no runtime authority. This record is training
    metadata for a future willow-mcp-side adapter; it is never read by
    `check_kart_task`, `scan_bash`, `scan_write`, `scan_output`, or any other
    scan-path code, and it can never turn a block into an allow. A block a
    human annotates here stays blocked exactly as before, forever.

    Best-effort: any exception from the sink is swallowed, never raised.
    """
    with contextlib.suppress(Exception):  # capture-only, never allowed to raise
        record = {
            "block_id": str(block_id or ""),
            "ts": _now_iso(),
            "note": str(note or ""),
            "who": str(who or ""),
        }
        write = sink or _default_fp_sink
        write(record)


def _iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with contextlib.suppress(Exception), path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(Exception):
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj


def iter_block_records(
    *,
    block_path: Path | None = None,
    fp_path: Path | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield every block record merged with its false-positive annotations.

    Each yielded dict is a block record (see `record_block`) plus a
    `false_positives` list (possibly empty) of every annotation recorded
    against its `block_id`. This is the read side a willow-mcp-side training
    adapter (or a human review tool) consumes; see the module docstring for
    the field mapping into a training example.
    """
    fp_by_block: dict[str, list[dict]] = {}
    for fp in _iter_jsonl(fp_path or _fp_ledger_path()):
        fp_by_block.setdefault(str(fp.get("block_id", "")), []).append(fp)

    for block in _iter_jsonl(block_path or _block_ledger_path()):
        block_id = str(block.get("block_id", ""))
        yield {**block, "false_positives": fp_by_block.get(block_id, [])}


def _find_block(block_id: str, *, block_path: Path | None = None) -> dict | None:
    """Convenience lookup used mainly by tests/tools: the raw block record
    (without annotations) for one block_id, or None if not found."""
    for block in _iter_jsonl(block_path or _block_ledger_path()):
        if str(block.get("block_id")) == str(block_id):
            return block
    return None
