"""Worker entry point.

Stage 2 lands the real poll/claim/execute loop (lifted from willow-2.0
`core/kart_worker.py`, decoupled per docs/DESIGN.md). For now this is a stub so
the `kartikeya` / `kart` console scripts resolve and the package is importable.
"""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kartikeya",
        description="Kartikeya — sandboxed task queue worker (a.k.a. Kart).",
    )
    parser.add_argument("command", nargs="?", default="worker",
                        choices=["worker"], help="subcommand")
    parser.add_argument("--lane", default="fast", choices=["fast", "batch"])
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--once", action="store_true",
                        help="drain the queue and exit (for tests/cron)")
    parser.parse_args(argv)

    print(
        "kartikeya: worker core not yet extracted — see docs/DESIGN.md stage 2.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
