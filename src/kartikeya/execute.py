"""
execute.py — single-task execution for Kartikeya.

Lifted from willow-2.0 core/kart_execute.py, decoupled:
- The shell task path (the common case) is carried intact; its only deps are
  `.sandbox` and `.task_scan`.
- The workflow-phase and goal/routine task *types* (which coupled a Postgres
  bridge, an LLM edge, and an outcome runner in willow-2.0) are NOT in the base
  package. `execute_task_row` routes them to an optional host-supplied handler;
  with no handler they fail cleanly (never an import crash). See docs/DESIGN.md
  §7 — the LLM/workflow surface is a later optional extra.
- Result persistence goes through the `TaskQueue` seam, not a DB bridge.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Callable

from .queue import TaskQueue, TaskRow

_DEFAULT_WORKFLOW_MODEL = os.environ.get("KART_WORKFLOW_MODEL", "mistral:7b")
_FENCE_RE = re.compile(r"```(bash|sh|python3?|python)?\n?(.*?)```", re.DOTALL)

# Optional task-type handlers a host may register. Signature:
#   handler(row: TaskRow, *, timeout: int | None, context: str) -> tuple[str, dict]
TaskTypeHandler = Callable[..., "tuple[str, dict]"]


def kart_timeout(context: str = "poll") -> int:
    if context == "daemon":
        return int(os.environ.get("KART_DAEMON_TIMEOUT", "1800"))
    return int(os.environ.get("KART_POLL_TIMEOUT", "120"))


def _parse_task_network_directives(task_text: str) -> tuple[str, bool, bool]:
    from .sandbox import parse_task_network

    return parse_task_network(task_text)


def trim_task_result(result, status: str = ""):
    """Drop the bulky sandbox manifest from read surfaces for successful tasks.

    Failed tasks keep it for boundary debugging.
    """
    if not isinstance(result, dict) or "sandbox_manifest" not in result:
        return result
    if str(status).lower() in ("failed", "error"):
        return result
    out = dict(result)
    del out["sandbox_manifest"]
    return out


def _normalize_shell_result(raw: dict) -> dict:
    stdout = (raw.get("stdout") or "").strip()
    stderr = (raw.get("stderr") or "").strip()
    out: dict[str, Any] = {
        "returncode": raw.get("returncode"),
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_s": raw.get("elapsed_s"),
        "sandbox": raw.get("sandbox"),
        "provider": "shell",
    }
    if raw.get("error"):
        out["error"] = raw["error"]
    for _k in ("sandbox_manifest", "sandbox_setup"):
        if raw.get(_k) is not None:
            out[_k] = raw[_k]
    return out


def _iter_fenced_blocks(task_text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for lang, block in _FENCE_RE.findall(task_text):
        body = block.strip()
        if not body:
            continue
        kind = "python" if lang in ("python", "python3") else "script"
        if kind != "python":
            real_lines = [
                ln
                for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            if len(real_lines) == 1:
                kind = "shell"
                body = real_lines[0]
        blocks.append((kind, body))
    return blocks


def _run_one_shell(
    cmd: str,
    *,
    timeout: int,
    allow_net: bool,
    allow_localhost: bool,
) -> tuple[str, dict]:
    from .sandbox import bwrap_available, run_shell_result_for_task, use_bwrap

    if use_bwrap() and not bwrap_available():
        return "failed", {"error": "bwrap not found — install bubblewrap"}

    status, result = run_shell_result_for_task(
        cmd,
        timeout=timeout,
        allow_net=allow_net,
        allow_localhost=allow_localhost,
    )
    return status, _normalize_shell_result(result)


def run_shell_task(
    task_text: str,
    *,
    timeout: int | None = None,
    context: str = "poll",
) -> tuple[str, dict]:
    """Execute a shell-class task string. Returns (status, result)."""
    from .task_scan import check_kart_task

    blocked = check_kart_task(task_text)
    if blocked:
        return "failed", blocked

    timeout = timeout if timeout is not None else kart_timeout(context)
    cmd_body, allow_net, allow_localhost = _parse_task_network_directives(task_text)
    blocks = _iter_fenced_blocks(cmd_body)

    if blocks:
        outputs: list[str] = []
        steps = 0
        errors: list[str] = []
        for kind, body in blocks:
            steps += 1
            label = body.splitlines()[0][:80] if kind == "script" else body
            if kind == "python":
                cmd = f"python3 - <<'KART_PY'\n{body}\nKART_PY"
            elif kind == "script":
                cmd = f"bash <<'KART_SH'\n{body}\nKART_SH"
            else:
                cmd = body
            status, result = _run_one_shell(
                cmd,
                timeout=timeout,
                allow_net=allow_net,
                allow_localhost=allow_localhost,
            )
            chunk = result.get("stdout") or ""
            err = result.get("stderr") or result.get("error") or ""
            outputs.append(f"$ {label}\n{chunk}" + (f"\nSTDERR: {err}" if err else ""))
            if status != "completed":
                errors.append(result.get("error") or err or f"{label} failed")
        merged = _normalize_shell_result(
            {
                "returncode": 0 if not errors else 1,
                "stdout": "\n\n".join(outputs),
                "stderr": "; ".join(errors),
                "elapsed_s": None,
                "sandbox": blocks and "bwrap" or "none",
            }
        )
        merged["steps"] = steps
        if errors:
            merged["error"] = "; ".join(errors)
            return "failed", merged
        return "completed", merged

    if not cmd_body:
        return "failed", {"error": "empty command"}

    status, result = _run_one_shell(
        cmd_body,
        timeout=timeout,
        allow_net=allow_net,
        allow_localhost=allow_localhost,
    )
    result["steps"] = 1
    return status, result


def _task_type(cmd: str, row: TaskRow) -> str:
    """Classify a claimed row. Base kartikeya handles 'shell'; other types
    require a host-registered handler."""
    if cmd.startswith('{"type":"workflow_phase"'):
        return "workflow_phase"
    if getattr(row, "goal", None):
        return "goal"
    return "shell"


def execute_task_row(
    row: TaskRow,
    *,
    timeout: int | None = None,
    context: str = "poll",
    handlers: dict[str, TaskTypeHandler] | None = None,
    network_authorizer: "Callable[[TaskRow, str], bool] | None" = None,
) -> tuple[str, dict]:
    """Route one claimed task row. Returns (status, result).

    Shell tasks run in the bwrap sandbox. Non-shell task types are delegated to
    a matching entry in `handlers` (host/extra supplied); with none registered
    they fail cleanly rather than importing fleet/LLM code. On failure (or with
    WILLOW_KART_LOG_ALL=1) a forensic artifact is written and `log_dir` set.

    `network_authorizer` is an optional host-supplied pre-launch gate. When a
    shell task requests network (`# allow_net` / `# allow_localhost`), it is
    called as `network_authorizer(row, row.network_authorization)` BEFORE the
    sandbox launches; a falsy return denies the task (no shell runs). Kartikeya
    owns the seam and the timing; the host owns the policy. Tasks that request no
    network never consult it.
    """
    cmd = row.task or ""
    ttype = _task_type(cmd, row)

    if ttype == "shell":
        if network_authorizer is not None:
            _body, allow_net, allow_localhost = _parse_task_network_directives(cmd)
            if (allow_net or allow_localhost) and not network_authorizer(
                row, getattr(row, "network_authorization", "") or ""
            ):
                reason = getattr(network_authorizer, "last_error", "") or "denied"
                return "failed", {
                    "error": f"verifier refused: {reason}",
                    "context": "egress_denied",
                }
        try:
            status, result = run_shell_task(cmd, timeout=timeout, context=context)
        except Exception as e:
            status, result = "failed", {"error": str(e)}
    else:
        handler = (handlers or {}).get(ttype)
        if handler is None:
            status, result = "failed", {
                "error": (
                    f"unsupported task type '{ttype}' — base kartikeya runs shell "
                    "tasks; register a handler (execute_task_row(..., handlers=...)) "
                    "or install the optional extra"
                )
            }
        else:
            try:
                status, result = handler(row, timeout=timeout, context=context)
            except Exception as e:
                status, result = "failed", {"error": str(e)}

    full_stdout = result.pop("_full_stdout", None) if isinstance(result, dict) else None
    full_stderr = result.pop("_full_stderr", None) if isinstance(result, dict) else None
    if isinstance(result, dict) and (
        status != "completed" or os.environ.get("WILLOW_KART_LOG_ALL")
    ):
        from .sandbox import write_task_log

        log_dir = write_task_log(
            row.task_id, cmd, status, result,
            full_stdout=full_stdout, full_stderr=full_stderr,
        )
        if log_dir:
            result["log_dir"] = log_dir
    return status, result


def drain_claimed_tasks(
    queue: TaskQueue,
    rows: list[TaskRow],
    *,
    context: str = "poll",
    handlers: dict[str, TaskTypeHandler] | None = None,
    log_prefix: str = "kart",
) -> list[tuple[str, str, dict]]:
    """Execute claimed rows and record terminal state via the TaskQueue.

    Returns [(task_id, status, result), ...].
    """
    outcomes: list[tuple[str, str, dict]] = []
    for row in rows:
        status, result = execute_task_row(
            row, context=context, handlers=handlers
        )
        stored = trim_task_result(result, status)
        try:
            queue.mark_done(row.task_id, status=status, result=json.dumps(stored))
        except Exception as e:
            print(
                f"{log_prefix}: mark_done failed for {row.task_id}: {e}",
                file=sys.stderr,
            )
        print(
            f"{log_prefix}: {row.task_id} → {status} ({(row.task or '')[:60]})",
            file=sys.stderr,
        )
        outcomes.append((row.task_id, status, result))
    return outcomes
