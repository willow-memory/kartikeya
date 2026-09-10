"""Gap 5fd840cb5000: a tree-rewriting git verb under a read-only WILLOW_ROOT
half-succeeds — refs move in the writable .git, the checkout cannot follow.
The scanner refuses it up front and names the writable lane.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import sandbox, task_scan  # noqa: E402


@pytest.fixture
def ro_root(monkeypatch):
    monkeypatch.setattr(task_scan, "_root_read_only", lambda: True)


@pytest.fixture
def rw_root(monkeypatch):
    monkeypatch.setattr(task_scan, "_root_read_only", lambda: False)


@pytest.mark.parametrize("task", [
    "git checkout -b feat/x origin/master",
    "git checkout master",
    "git checkout -- src/willow_mcp/gate.py",
    "git switch master",
    "git merge origin/master",
    "git rebase origin/master",
    "git reset --hard HEAD~1",
    "git stash pop",
    "git restore .",
    "git clean -fd",
    "cd /home/x/repo && git checkout feat/y",
])
def test_tree_rewrites_are_refused_under_a_read_only_root(ro_root, task):
    out = task_scan.check_kart_task(task)
    assert out is not None, task
    assert out["kart_scan"]["category"] == "tree_rewrite_on_read_only_root"
    assert "worktrees" in out["error"]


@pytest.mark.parametrize("task", [
    "git status",
    "git log --oneline -5",
    "git diff",
    "git add src/x.py",
    "git commit -m 'msg'",
    "git checkout -b feat/new-branch",
    "git switch -c feat/new-branch",
    "git stash list",
    "git reset src/x.py",
    "git branch --show-current",
])
def test_reads_commits_and_branch_creation_at_head_pass(ro_root, task):
    assert task_scan.check_kart_task(task) is None, task


@pytest.mark.parametrize("task", [
    "git checkout master",
    "git merge origin/master",
    "git stash pop",
])
def test_nothing_is_refused_under_a_read_write_root(rw_root, task):
    """(`reset --hard` is absent here: the destructive scan already refuses it
    on every root, before this gate is consulted.)"""
    assert task_scan.check_kart_task(task) is None


def test_work_root_read_only_reads_the_resolved_policy(monkeypatch, tmp_path):
    import json

    cfg_path = tmp_path / "kart-sandbox.json"
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(cfg_path))
    cfg_path.write_text(json.dumps({
        "bind_read_only": ["{{WILLOW_ROOT}}"], "bind_read_write": ["{{WILLOW_ROOT}}/worktrees"],
    }))
    assert sandbox.work_root_read_only() is True
    cfg_path.write_text(json.dumps({"bind_read_only": [], "bind_read_write": ["{{WILLOW_ROOT}}"]}))
    assert sandbox.work_root_read_only() is False


def test_vendored_default_binds_the_root_read_only(monkeypatch, tmp_path):
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    assert sandbox.work_root_read_only() is True
