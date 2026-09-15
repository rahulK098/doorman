"""Entry point for the ``doorman-bench`` console script.

The benchmark itself is Phase 3 of docs/implementation-plan.md. Until then
this entry point exists so the package installs cleanly and tells the user
what is (not yet) here.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    sys.stderr.write(
        "doorman-bench is not implemented yet (Phase 3 in docs/implementation-plan.md).\n"
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
