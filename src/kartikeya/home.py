"""Home/root resolution — the filesystem seam.

Standalone replacement for willow-2.0's `willow.fylgja.willow_home`. Kartikeya
only needs "where does the fleet/app keep its state" for a few sandbox concerns
(the nsswitch shim, an optional `env` file, the `.kart-logs` dir). A host may
point this anywhere via $WILLOW_HOME; otherwise it defaults to ~/.willow.

Signatures accept an optional `package_root` for drop-in compatibility with the
call sites lifted from willow-2.0; it is ignored here.
"""
from __future__ import annotations

import os
from pathlib import Path


def willow_home(package_root: Path | None = None) -> Path:
    """Resolve the app home. $WILLOW_HOME if set, else the ~/.willow alias."""
    env = os.environ.get("WILLOW_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return willow_home_alias()


def willow_home_alias() -> Path:
    """The conventional per-user home used for legacy ~/.willow paths."""
    return Path.home() / ".willow"
