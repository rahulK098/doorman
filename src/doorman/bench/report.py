"""Render a ``BenchReport`` as Markdown (for files/PRs) or plain text (for terminals)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from doorman import __version__
from doorman.bench.harness import BenchReport, FamilyStats, Outcome


def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x:.0%}"


def _family_rows(families: Iterable[FamilyStats]) -> list[list[str]]:
    rows = []
    for fs in families:
        rows.append(
            [
                fs.family,
                str(fs.attacks),
                _pct(fs.asr_undefended),
                _pct(fs.asr_defended),
                str(fs.benign),
                _pct(fs.fpr_defended),
                _pct(fs.held_rate_defended),
            ]
        )
    return rows


FAMILY_HEADER = [
    "family",
    "attacks",
    "ASR undefended",
    "ASR defended",
    "benign",
    "FPR defended",
    "held (benign)",
]
TEXT_HEADER = ["family", "attacks", "ASR undef", "ASR def", "benign", "FPR def", "held"]


def _md_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def _layer_breakdown(total: FamilyStats) -> str:
    if not total.blocked_by:
        return "_no blocks recorded_"
    rows = [[k, str(v)] for k, v in total.blocked_by.most_common()]
    return _md_table(["layer/rule", "blocks"], rows)


def to_markdown(report: BenchReport, *, title: str = "doorman-bench report") -> str:
    families = list(report.families().values())
    total = report.totals()
    lines = [
        f"# {title}",
        "",
        f"- generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- doorman: {__version__}",
        f"- target: `{report.target or '?'}`",
        f"- mode: `{report.mode}`",
        f"- fixtures: {total.attacks} attack, {total.benign} benign",
        "",
        "## Results by family",
        "",
        _md_table(FAMILY_HEADER, _family_rows(families) + _family_rows([total])),
        "",
        "ASR = attack success rate (lower is better for *defended*). "
        "FPR = benign actions *blocked* (lower is better). "
        "held = benign actions paused for human confirmation by design "
        "(irreversible tools); not counted as false positives.",
        "",
        "## Blocks by layer and rule (defended)",
        "",
        _layer_breakdown(total),
        "",
    ]

    bypasses = report.bypasses()
    lines += ["## Bypasses (attack succeeded while defended)", ""]
    if bypasses:
        for o in bypasses:
            lines.append(f"- **{o.fixture_id}** ({o.family}) — held by: {o.held_by or 'nothing'}")
    else:
        lines.append("_none_")
    lines.append("")

    fps = report.false_positives()
    lines += ["## False positives (benign action blocked or held while defended)", ""]
    if fps:
        for o in fps:
            lines.append(f"- **{o.fixture_id}** — {o.blocked_by or o.held_by}: {o.rationale}")
    else:
        lines.append("_none_")
    lines.append("")

    lines += ["## Per-fixture detail (defended)", ""]
    detail_rows = []
    for o in report.outcomes:
        if not o.defended:
            continue
        if o.attack:
            status = "BYPASS" if o.succeeded else "caught"
        elif o.succeeded:
            status = "ok"
        else:
            status = "held" if o.held else "FALSE POSITIVE"
        where = (
            ", ".join(o.blocked_by)
            or ", ".join(o.held_by)
            or ("quarantined" if o.quarantined else "")
        )
        detail_rows.append([o.fixture_id, o.family, status, where])
    lines.append(_md_table(["fixture", "family", "result", "by"], detail_rows))
    lines.append("")
    return "\n".join(lines)


def to_text(report: BenchReport) -> str:
    families = list(report.families().values())
    total = report.totals()
    header = TEXT_HEADER
    rows = _family_rows(families) + _family_rows([total])
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(header)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*header), fmt.format(*("-" * w for w in widths))]
    out += [fmt.format(*r) for r in rows]
    if report.bypasses():
        out.append("")
        out.append("BYPASSES: " + ", ".join(o.fixture_id for o in report.bypasses()))
    if report.false_positives():
        out.append("")
        out.append("FALSE POSITIVES: " + ", ".join(o.fixture_id for o in report.false_positives()))
    return "\n".join(out)


def outcome_to_dict(o: Outcome) -> dict[str, Any]:
    return {
        "fixture_id": o.fixture_id,
        "family": o.family,
        "attack": o.attack,
        "defended": o.defended,
        "mode": o.mode,
        "succeeded": o.succeeded,
        "blocked_by": o.blocked_by,
        "held_by": o.held_by,
        "quarantined": o.quarantined,
        "rationale": o.rationale,
        "executed": [{"tool": c.tool, "args": c.plain_args} for c in o.executed],
    }


def to_jsonl(report: BenchReport) -> str:
    return "\n".join(json.dumps(outcome_to_dict(o), default=str) for o in report.outcomes)
