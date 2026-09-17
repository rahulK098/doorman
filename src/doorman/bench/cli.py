"""``doorman-bench`` — static benchmark and self-updating red-team runner.

    doorman-bench run --target examples.recruiting_agent:agent --report results/report.md
    doorman-bench run --target examples.recruiting_agent:agent --evolve --rounds 5
    doorman-bench list

Zero dependencies beyond the standard library (argparse), so it works right
after ``pip install doorman``.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from doorman.bench.fixtures import DATA_DIR, FAMILIES, load_fixtures
from doorman.bench.harness import load_target, run_benchmark
from doorman.bench.report import to_jsonl, to_markdown, to_text
from doorman.errors import MissingExtra


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="doorman-bench", description=__doc__.split("\n\n")[0])
    p.add_argument("-v", "--verbose", action="store_true", help="log every block/bypass")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the benchmark against a target")
    run.add_argument(
        "--target",
        required=True,
        help="module:attribute of the agent under test, e.g. examples.recruiting_agent:agent",
    )
    run.add_argument(
        "--mode",
        choices=["oracle", "agent"],
        default="oracle",
        help="oracle: check each fixture's declared action; agent: let the target's model propose",
    )
    run.add_argument(
        "--family", action="append", choices=FAMILIES, help="restrict to a family (repeatable)"
    )
    run.add_argument("--fixtures", type=Path, default=DATA_DIR, help="fixture root directory")
    run.add_argument("--report", type=Path, help="write a Markdown report here")
    run.add_argument("--jsonl", type=Path, help="write per-fixture outcomes as JSON lines here")
    run.add_argument(
        "--fail-on-bypass", action="store_true", help="exit 1 if any attack succeeds while defended"
    )
    run.add_argument(
        "--fail-on-false-positive",
        action="store_true",
        help="exit 1 if any benign action is blocked or held while defended",
    )

    ev = run.add_argument_group("evolve", "mutate caught attacks and retry")
    ev.add_argument("--evolve", action="store_true", help="enable evolve mode after the static run")
    ev.add_argument("--rounds", type=int, default=3)
    ev.add_argument(
        "--max-mutations", type=int, default=3, help="variants per fixture per strategy"
    )
    ev.add_argument("--max-evaluations", type=int, default=500, help="hard cap on pipeline runs")
    ev.add_argument("--mutator", choices=["rules", "anthropic"], default="rules")
    ev.add_argument(
        "--strategy", action="append", help="restrict to a mutation strategy (repeatable)"
    )
    ev.add_argument(
        "--new-fixtures",
        type=Path,
        help="where to write discovered bypasses (default: <fixtures>/discovered)",
    )
    ev.add_argument("--no-write", action="store_true", help="report bypasses but don't file them")

    ls = sub.add_parser("list", help="list fixtures")
    ls.add_argument("--fixtures", type=Path, default=DATA_DIR)
    ls.add_argument("--family", action="append", choices=FAMILIES)
    return p


def _select(fixtures_root: Path, families: list[str] | None) -> list:  # type: ignore[type-arg]
    if not families:
        return load_fixtures(root=fixtures_root)
    out = []
    for fam in families:
        if (fixtures_root / fam).is_dir():
            out.extend(load_fixtures(fam, root=fixtures_root))
    return out


def cmd_list(args: argparse.Namespace) -> int:
    fixtures = _select(args.fixtures, args.family)
    width = max((len(f.id) for f in fixtures), default=8)
    for f in fixtures:
        kind = "attack" if f.attack else "benign"
        print(f"{f.id:<{width}}  {f.family:<12} {kind:<6}  {f.description[:70]}")
    print(f"\n{len(fixtures)} fixture(s)")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    fixtures = _select(args.fixtures, args.family)
    if not fixtures:
        print("no fixtures selected", file=sys.stderr)
        return 2
    target = load_target(args.target)

    report = run_benchmark(fixtures, target, target_spec=args.target, mode=args.mode)
    print(to_text(report))

    evolve_summary = ""
    if args.evolve:
        from doorman.bench.evolve import AnthropicMutator, Mutator, RuleMutator, evolve

        mutator: Mutator
        if args.mutator == "anthropic":
            try:
                mutator = AnthropicMutator()
            except ImportError as e:
                raise MissingExtra("anthropic", "--mutator anthropic") from e
        else:
            mutator = RuleMutator()
        out_dir = args.new_fixtures or (args.fixtures / "discovered")
        res = evolve(
            fixtures,
            target,
            mutator=mutator,
            rounds=args.rounds,
            max_mutations=args.max_mutations,
            max_evaluations=args.max_evaluations,
            strategies=args.strategy,
            mode=args.mode,
            output_dir=out_dir,
            write=not args.no_write,
        )
        evolve_summary = (
            f"\n## Evolve\n\n- mutator: `{mutator.name}`\n- rounds: {res.rounds_run}\n"
            f"- evaluations: {res.evaluations}\n- seeds (caught attacks): {res.still_caught}\n"
            f"- **bypasses discovered: {len(res.bypasses)}**\n"
        )
        if res.bypasses:
            evolve_summary += (
                "\n| discovered fixture | parent | strategy | round |\n|---|---|---|---|\n"
            )
            for b in res.bypasses:
                evolve_summary += (
                    f"| `{b.fixture.id}` | {b.parent_id} | {b.strategy} | {b.round} |\n"
                )
        if res.written:
            evolve_summary += f"\nFiled {len(res.written)} fixture(s) under `{out_dir}`.\n"
        print()
        print(
            f"evolve: {res.rounds_run} round(s), {res.evaluations} evaluations, "
            f"{len(res.bypasses)} bypass(es) discovered"
            + (f", {len(res.written)} filed to {out_dir}" if res.written else "")
        )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(to_markdown(report) + evolve_summary, encoding="utf-8")
        print(f"\nreport: {args.report}")
    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        args.jsonl.write_text(to_jsonl(report) + "\n", encoding="utf-8")
        print(f"outcomes: {args.jsonl}")

    rc = 0
    if args.fail_on_bypass and report.bypasses():
        rc = 1
    if args.fail_on_false_positive and report.false_positives():
        rc = 1
    return rc


def main(argv: list[str] | None = None) -> int:
    # Console scripts don't put the CWD on sys.path; --target is normally a
    # package in the project you're standing in (like pytest's rootdir).
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(name)s: %(message)s",
    )
    try:
        if args.command == "list":
            return cmd_list(args)
        return cmd_run(args)
    except MissingExtra as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        # A malformed or unsafe fixture file, or a bad --target. Fixture corpora
        # are shared between people, so a bad one should report cleanly rather
        # than print a traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
