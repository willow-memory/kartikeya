"""Gap 5fd840cb5000: a tree-rewriting git verb under a read-only checkout with a
writable .git half-succeeds — refs move, the working tree cannot follow. The
scanner refuses it up front and names the lane that is writable.

Gap bd6284e3496d: the refusal is judged per directory, not policy-wide. A
verb inside a checkout the policy binds read-write passes; branch creation at
HEAD passes whatever the flag order.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import sandbox, task_scan  # noqa: E402

RO_ROOT = "/srv/product"           # the read-only WILLOW_ROOT shape
RW_REPO = "/srv/org/other-repo"    # a checkout bound read-write by a parent entry


@pytest.fixture
def policy(monkeypatch):
    """A fake mount policy answering per directory, and a fixed task cwd."""
    table = {
        RO_ROOT: True,
        RO_ROOT + "/worktrees": False,
        RO_ROOT + "/.git": False,
        RW_REPO: False,
    }

    def read_only(path):
        best, best_len = None, -1
        for prefix, ro in table.items():
            if path == prefix or path.startswith(prefix + "/"):
                if len(prefix) > best_len:
                    best, best_len = ro, len(prefix)
        return best

    monkeypatch.setattr(task_scan, "_dir_read_only", read_only)
    monkeypatch.setattr(task_scan, "_task_cwd", lambda: RO_ROOT)
    return table


# ── inside the read-only root: refused ───────────────────────────────────────

@pytest.mark.parametrize("task", [
    "git checkout -b feat/x origin/master",
    "git checkout -q -b feat/x origin/master",
    "git checkout master",
    "git checkout -- src/willow_mcp/gate.py",
    "git switch master",
    "git merge origin/master",
    "git rebase origin/master",
    "git reset --hard HEAD~1",
    "git stash pop",
    "git stash apply",
    "git restore .",
    "git clean -fd",
    f"cd {RO_ROOT} && git checkout feat/y",
    f"cd {RO_ROOT}/src && git checkout feat/y",
])
def test_tree_rewrites_in_the_read_only_root_are_refused(policy, task):
    out = task_scan.check_kart_task(task)
    assert out is not None, task
    assert out["kart_scan"]["category"] == "tree_rewrite_on_read_only_root"
    assert "worktrees" in out["error"]
    assert out["kart_scan"]["cwd"].startswith(RO_ROOT)


# ── the same verbs where the half-write cannot happen: allowed ───────────────

@pytest.mark.parametrize("task", [
    f"cd {RW_REPO} && git checkout master",
    f"cd {RW_REPO} && git checkout -- docs/derived.json",
    f"cd {RW_REPO} && git stash pop",
    f"cd {RW_REPO} && git merge origin/master",
    f"cd {RO_ROOT}/worktrees/feat-x && git checkout -- README.md",
    f"cd {RO_ROOT}/worktrees/feat-x && git merge origin/master",
])
def test_tree_rewrites_in_a_read_write_checkout_pass(policy, task):
    assert task_scan.check_kart_task(task) is None, task


def test_cd_prefix_is_followed_across_the_chain(policy):
    # cd into the rw repo, then back into the ro root: the last cd wins.
    assert task_scan.check_kart_task(f"cd {RW_REPO} && cd {RO_ROOT} && git checkout master") is not None
    assert task_scan.check_kart_task(f"cd {RO_ROOT} && cd {RW_REPO} && git checkout master") is None


def test_relative_cd_resolves_against_the_current_directory(policy):
    assert task_scan.check_kart_task("cd worktrees/feat-x && git checkout -- x") is None
    assert task_scan.check_kart_task("cd src && git checkout -- x") is not None


# ── reads, commits and branch creation at HEAD: always fine ──────────────────

@pytest.mark.parametrize("task", [
    "git status",
    "git log --oneline -5",
    "git diff",
    "git add src/x.py",
    "git commit -m 'msg'",
    "git checkout -b feat/new-branch",
    "git checkout -q -b feat/new-branch",
    "git switch -c feat/new-branch",
    "git switch -q -c feat/new-branch",
    "git stash list",
    "git stash push -m keep -- docs/x.json",
    "git reset src/x.py",
    "git branch --show-current",
])
def test_reads_commits_and_branch_creation_at_head_pass(policy, task):
    assert task_scan.check_kart_task(task) is None, task


def test_unknown_policy_does_not_refuse(monkeypatch):
    monkeypatch.setattr(task_scan, "_dir_read_only", lambda _p: None)
    monkeypatch.setattr(task_scan, "_task_cwd", lambda: RO_ROOT)
    assert task_scan.check_kart_task("git checkout master") is None


# ── the verb classifier on its own ───────────────────────────────────────────

@pytest.mark.parametrize("fragment,expected", [
    ("git checkout -b x", False),
    ("git checkout -q -b x", False),
    ("git checkout -b x origin/master", True),
    ("git checkout -q -b x origin/master", True),
    ("git switch -c x", False),
    ("git switch x", True),
    ("git checkout -- f", True),
    ("git reset --hard", True),
    ("git reset --soft HEAD~1", False),
    ("git reset f", False),
    ("git stash", False),
    ("git stash pop", True),
    ("git push origin x", False),
    ("echo git checkout", False),
])
def test_tree_rewrite_verb_classifier(fragment, expected):
    assert task_scan._tree_rewrite_verb(fragment) is expected


# ── the policy resolver, against a real config ───────────────────────────────

def _mcp_repo(base: Path) -> Path:
    repo = base / "willow-mcp"
    (repo / "src" / "willow_mcp").mkdir(parents=True)
    (repo / "src" / "willow_mcp" / "__init__.py").write_text("")
    (repo / ".git").mkdir()
    return repo


def test_path_read_only_in_policy_resolves_longest_bind(tmp_path, monkeypatch):
    repo = _mcp_repo(tmp_path)
    other = tmp_path / "org" / "other-repo"
    other.mkdir(parents=True)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "bind_read_only": ["{{WILLOW_ROOT}}"],
        "bind_read_write": ["{{WILLOW_ROOT}}/worktrees", "{{WILLOW_ROOT}}/.git", str(tmp_path / "org")],
        "env_prefixes": ["WILLOW_"],
    }))
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(cfg))
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    assert sandbox.path_read_only_in_policy(repo) is True
    assert sandbox.path_read_only_in_policy(repo / "src") is True
    assert sandbox.path_read_only_in_policy(repo / "worktrees") is False
    assert sandbox.path_read_only_in_policy(repo / ".git") is False
    assert sandbox.path_read_only_in_policy(other) is False
    assert sandbox.path_read_only_in_policy(tmp_path / "nowhere") is None


def test_vendored_default_binds_the_root_read_only(monkeypatch, tmp_path):
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    assert sandbox.work_root_read_only() is True
