"""Suite-wide isolation from the host's systemd user configuration.

cgroup_setup reads $XDG_CONFIG_HOME/systemd/user/kart.slice (default
~/.config/...): an installed kart.slice counts as "cgroup mode configured",
and a task is refused when the slice is not usable. Without this, any test
that runs a task would see the real unit file on a host that has one and
start refusing. Tests that need a unit file set XDG_CONFIG_HOME themselves,
which overrides this.
"""

import pytest


@pytest.fixture(autouse=True)
def _no_host_systemd_user_config(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg-config")))
