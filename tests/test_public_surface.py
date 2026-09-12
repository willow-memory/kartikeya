"""What a kartikeya major bump is a promise about.

The docstring in `kartikeya/__init__.py` says "Public surface:" and lists names.
Prose does not fail a build, so this is the half that does: every name claimed
there must exist, with the shape callers hold it by.

The sandbox seam is the reason this file exists. `kartikeya.sandbox` was in
neither column — not exported from `__init__`, not documented as internal — while
willow-mcp imported `resolve_sandbox_config` and `is_vendored_default` at module
scope and refused to start a worker without them, and pinned
`collect_mcp_trust_ro_overlays` and `ensure_work_root` from its own suite
(its B-33 and B-65 floors). A consumer depending on names this package never
promised is a break waiting to be nobody's fault; declaring them makes it ours.
"""

from __future__ import annotations

import inspect

import pytest

import kartikeya

#: Re-exported at the top level, and in `__all__`.
TOP_LEVEL = (
    "TaskQueue",
    "TaskRow",
    "QueueStats",
    "SqliteTaskQueue",
    "lanes",
    "check_kart_task",
    "run_shell_task",
    "NetworkAuthorizer",
    "execute_task_row",
    "drain_claimed_tasks",
    "run_worker",
)

#: Promised, but imported by path rather than re-exported — `__all__` would
#: invent a top-level spelling no caller uses.
SANDBOX_SEAM = (
    "resolve_sandbox_config",
    "is_vendored_default",
    "collect_mcp_trust_ro_overlays",
    "ensure_work_root",
)


@pytest.mark.parametrize("name", TOP_LEVEL)
def test_the_top_level_surface_is_importable(name):
    assert hasattr(kartikeya, name), f"kartikeya.{name} is declared public and missing"


def test_all_matches_what_is_declared():
    """`__all__` and the docstring must not drift apart."""
    assert set(kartikeya.__all__) - {"__version__"} == set(TOP_LEVEL)


@pytest.mark.parametrize("name", SANDBOX_SEAM)
def test_the_sandbox_seam_is_importable(name):
    from kartikeya import sandbox

    assert hasattr(sandbox, name), (
        f"kartikeya.sandbox.{name} is declared public and missing — willow-mcp holds it"
    )


def test_the_sandbox_seam_is_reachable_by_the_path_callers_use():
    """willow-mcp does `from kartikeya.sandbox import ...`, not `from kartikeya import`."""
    from kartikeya.sandbox import (  # noqa: F401
        collect_mcp_trust_ro_overlays,
        ensure_work_root,
        is_vendored_default,
        resolve_sandbox_config,
    )


def test_run_worker_keeps_the_keywords_its_callers_pass():
    """willow-mcp's worker.py and gates_actions.py both call run_worker with these.

    Narrow on purpose: only the arguments a caller outside this package actually
    passes. `agent`, `handlers` and `on_run_event` exist and are deliberately not
    asserted — nothing outside holds them yet.
    """
    params = inspect.signature(kartikeya.run_worker).parameters
    assert "queue" in params
    for name in (
        "lane",
        "slots",
        "interval",
        "once",
        "on_heartbeat",
        "network_authorizer",
    ):
        assert name in params, f"run_worker lost the {name} keyword"
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_the_declared_surface_is_stated_in_the_package_docstring():
    """The list above and the docstring are two copies; keep them honest."""
    doc = kartikeya.__doc__ or ""
    assert "Public surface:" in doc
    for name in SANDBOX_SEAM:
        assert name in doc, (
            f"{name} is tested as public but not declared in the docstring"
        )
