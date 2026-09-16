"""Run every bench fixture through the recruiting agent, undefended then defended.

uv run python -m examples.recruiting_agent
"""

from __future__ import annotations

import logging
import sys

from doorman.bench.fixtures import load_fixtures

from . import InputDocument, agent, undefended


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(message)s")
    fixtures = load_fixtures()
    rows: list[tuple[str, str, int, int]] = []
    for fx in fixtures:
        docs = [
            InputDocument(d.origin, d.content, candidate_id=d.origin.split(":")[-1])
            for d in fx.documents
        ]
        base = undefended.run(fx.task, docs, context=fx.context, session_id=f"u:{fx.id}")
        prot = agent.run(fx.task, docs, context=fx.context, session_id=f"d:{fx.id}")
        rows.append(
            (fx.id, "attack" if fx.attack else "benign", base.side_effects, prot.side_effects)
        )

    width = max(len(r[0]) for r in rows)
    print(f"{'fixture':<{width}}  kind    undefended  defended")
    for fid, kind, u, d in rows:
        print(f"{fid:<{width}}  {kind:<6}  {u:>10}  {d:>8}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
