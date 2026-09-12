"""Operator ruling 2026-09-10: no GitHub credential enters the sandbox on any
network mode, and the installed willow_mcp tree is never writable from a task.

Who holds the key and who initiates a push are two questions. The task
initiates; the host-side broker holds the credential. So ~/.netrc and
~/.config/gh, which used to ride in read-only under allow_net, are not bound at
all, and the shipped policy no longer promises a GITHUB_ prefix.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kartikeya import sandbox  # noqa: E402


def _mcp_repo(base: Path) -> Path:
    repo = base / "willow-mcp"
    (repo / "src" / "willow_mcp").mkdir(parents=True)
    (repo / "src" / "willow_mcp" / "__init__.py").write_text("")
    return repo


@pytest.fixture
def vendored_default(monkeypatch, tmp_path):
    """Resolve to the shipped default: an empty WILLOW_HOME and no override.
    Same shape as test_sandbox.py's fixture of the same name."""
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    empty = tmp_path / "empty-home"
    empty.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(empty))


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A HOME that HAS both credential files, so their absence from the argv is
    a decision and not an accident of the test box."""
    home = tmp_path / "home"
    (home / ".config" / "gh").mkdir(parents=True)
    (home / ".config" / "gh" / "hosts.yml").write_text("github.com: {}\n")
    (home / ".netrc").write_text("machine github.com login x password y\n")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "known_hosts").write_text("github.com ssh-ed25519 AAAA\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(sandbox.Path, "home", classmethod(lambda cls: home))
    return home


def _net_args(monkeypatch, tmp_path, fake_home):
    repo = _mcp_repo(tmp_path)
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "wh"))
    (tmp_path / "wh").mkdir()
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.setattr(sandbox.os.path, "isdir", lambda _p: True)
    return sandbox.build_bwrap_argv(allow_net=True)


def test_allow_net_binds_neither_netrc_nor_gh_config(monkeypatch, tmp_path, fake_home):
    argv = _net_args(monkeypatch, tmp_path, fake_home)
    joined = " ".join(argv)
    assert ".netrc" not in joined
    assert ".config/gh" not in joined


def test_allow_net_does_not_bind_the_ssh_agent_socket(monkeypatch, tmp_path, fake_home):
    """Operator 2026-09-10, "include SSH as well": an agent socket is a
    credential in effect. It is not bound even when the host has one."""
    sock = tmp_path / "agent.sock"
    sock.write_text("")
    repo = _mcp_repo(tmp_path)
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "wh"))
    (tmp_path / "wh").mkdir()
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.setenv("SSH_AUTH_SOCK", str(sock))
    monkeypatch.setattr(sandbox.os.path, "isdir", lambda _p: True)
    argv = sandbox.build_bwrap_argv(allow_net=True)
    assert str(sock) not in argv


def test_allow_net_still_binds_known_hosts_read_only(monkeypatch, tmp_path, fake_home):
    """Host-key verification is not a credential; it stays."""
    argv = _net_args(monkeypatch, tmp_path, fake_home)
    kh = str(fake_home / ".ssh" / "known_hosts")
    assert kh in argv
    assert argv[argv.index(kh) - 1] == "--ro-bind"


def test_vendored_default_promises_no_github_or_publishing_prefix(vendored_default):
    # `vendored_default` points WILLOW_HOME at an empty tmp dir. Merely unsetting
    # it is not isolation: willow_home() then falls back to ~/.willow, which on
    # this box is the tombstoned pre-migration home carrying its own stale
    # kart-sandbox.json (gap 8f791068c1a4), and the test reads that instead.
    cfg = sandbox.load_sandbox_config()
    for prefix in (
        "GITHUB_",
        "TWINE_",
        "PYPI_",
        "NPM_",
        "AWS_",
        "DISCORD_",
        "SSH_AUTH",
    ):
        assert prefix not in cfg["env_prefixes"], prefix
        assert prefix not in cfg["credential_env_prefixes"], prefix
    # Inference keys remain the credential lane, in the file and in the code
    # default a config without the key falls back to.
    assert "GROQ_" in cfg["credential_env_prefixes"]
    assert set(sandbox._DEFAULT_CREDENTIAL_PREFIXES) == set(
        cfg["credential_env_prefixes"]
    )


# ── the installed tree is never writable ─────────────────────────────────────


def test_installed_tree_under_a_rw_bind_is_overlaid_read_only(
    tmp_path, monkeypatch, caplog
):
    """A user-site install lives under ~/.local, which the shipped policy binds
    read-write. Measured on paper for a consumer box: a task could edit
    gate.py. The overlay closes it without touching the policy."""
    repo = _mcp_repo(tmp_path)
    local = tmp_path / "local"
    installed = local / "lib" / "python3.14" / "site-packages" / "willow-mcp"
    (installed / "willow_mcp").mkdir(parents=True)
    (installed / "willow_mcp" / "__init__.py").write_text("")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps(
            {
                "bind_read_only": ["{{WILLOW_ROOT}}"],
                "bind_read_write": [str(local)],
                "env_prefixes": ["WILLOW_"],
            }
        )
    )
    monkeypatch.setenv("KART_SANDBOX_CONFIG", str(cfg))
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.setattr(
        sandbox, "_installed_willow_mcp_root", lambda: installed.resolve()
    )
    with caplog.at_level("WARNING"):
        mounts = {str(h): ro for h, _c, ro in sandbox.collect_bind_mounts(repo)}
    assert mounts[str(local.resolve())] is False, "the parent stays as configured"
    assert mounts[str(installed.resolve())] is True, "the installed tree is read-only"
    order = [str(h) for h, _c, _ro in sandbox.collect_bind_mounts(repo)]
    assert order.index(str(local.resolve())) < order.index(str(installed.resolve()))
    assert any("overlaying it read-only" in r.getMessage() for r in caplog.records)


def test_installed_tree_already_read_only_is_left_alone(tmp_path, monkeypatch, caplog):
    """The fleet shape: an editable install resolves to the checkout, which is
    WILLOW_ROOT and already read-only. No overlay, no warning."""
    repo = _mcp_repo(tmp_path)
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.setattr(sandbox, "_installed_willow_mcp_root", lambda: repo.resolve())
    with caplog.at_level("WARNING"):
        mounts = {str(h): ro for h, _c, ro in sandbox.collect_bind_mounts(repo)}
    assert mounts[str(repo.resolve())] is True
    assert not any("overlaying it read-only" in r.getMessage() for r in caplog.records)
