"""OutputScanner: scrutinize a proposed tool call before it executes.

Three independent checks, in order of certainty:

1. **Canary leak** — deterministic. Any of this session's canary tokens in an
   argument means untrusted content was copied verbatim into an outbound
   action. Always ``BLOCK``.
2. **Provenance-aware injection scan** — each string argument is scored with
   the shared heuristic backend, against a threshold chosen by the argument's
   declared provenance (``Tagged``): untrusted arguments face a stricter
   threshold than trusted ones.
3. **Custom predicates** — host-supplied callables for domain rules (e.g.
   "recipient must be on our domain").

Every verdict names the offending argument and a redacted excerpt of its value.
See docs/adr/0002, 0005 and 0007.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from doorman.canary import CanaryRegistry
from doorman.scoring import ClassifierBackend, HeuristicBackend
from doorman.types import (
    Decision,
    Source,
    Tagged,
    ToolCall,
    Verdict,
    most_severe,
    source_of,
    truncate,
)

LAYER = "output_scanner"

# A predicate receives the tool call and returns a rationale string if it
# objects, or None to pass.
Predicate = Callable[[ToolCall], str | None]


@dataclass(frozen=True)
class _Arg:
    path: str  # "args.body" or "args.recipients[1]"
    value: str
    source: Source
    origin: str | None


def _walk(value: Any, path: str, source: Source, origin: str | None) -> Iterator[_Arg]:
    """Yield every string reachable inside ``value`` with its provenance."""
    if isinstance(value, Tagged):
        yield from _walk(value.value, path, value.source, value.origin)
    elif isinstance(value, str):
        yield _Arg(path, value, source, origin)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, f"{path}.{k}", source, origin)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}[{i}]", source, origin)


class OutputScanner:
    """
    Parameters
    ----------
    canary_tokens:
        Check outbound arguments for canary tokens. Needs a ``CanaryRegistry``
        shared with the ``Isolator`` that minted them.
    thresholds:
        Injection score at which an argument is blocked, per provenance.
        Untrusted arguments are held to a stricter standard than trusted ones.
    predicates:
        Extra host-defined checks.
    """

    DEFAULT_THRESHOLDS: dict[Source, float] = {
        Source.UNTRUSTED: 0.3,
        Source.UNKNOWN: 0.5,
        Source.TRUSTED: 0.8,
    }

    def __init__(
        self,
        *,
        canary_tokens: bool = True,
        registry: CanaryRegistry | None = None,
        backend: ClassifierBackend | None = None,
        thresholds: dict[Source, float] | None = None,
        predicates: list[Predicate] | None = None,
    ) -> None:
        self.canary_tokens = canary_tokens
        self.registry = registry if registry is not None else CanaryRegistry()
        self.backend = backend if backend is not None else HeuristicBackend()
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.predicates = list(predicates or [])

    def scan(self, call: ToolCall, *, session_id: str | None = None) -> Verdict:
        """Governing verdict for the call; ``scan_all`` returns every finding."""
        verdicts = self.scan_all(call, session_id=session_id)
        governing = most_severe(verdicts)
        assert governing is not None  # scan_all always returns at least one
        return governing

    def scan_all(self, call: ToolCall, *, session_id: str | None = None) -> list[Verdict]:
        verdicts: list[Verdict] = []
        args = list(_walk(call.args, "args", Source.UNKNOWN, None))

        if self.canary_tokens:
            verdicts.extend(self._check_canaries(call, args, session_id))

        verdicts.extend(self._check_injection(call, args))

        for predicate in self.predicates:
            objection = predicate(call)
            if objection:
                verdicts.append(
                    Verdict(
                        decision=Decision.BLOCK,
                        layer=LAYER,
                        rule_id="OUT-PRED-001",
                        rationale=f"Tool '{call.tool}' rejected by host predicate: {objection}",
                        metadata={
                            "tool": call.tool,
                            "predicate": getattr(predicate, "__name__", "?"),
                        },
                    )
                )

        if not verdicts:
            verdicts.append(
                Verdict(
                    decision=Decision.ALLOW,
                    layer=LAYER,
                    rule_id="OUT-000",
                    rationale=(
                        f"Tool '{call.tool}': {len(args)} string argument(s) scanned; "
                        "no canary leaks, injection patterns or predicate objections."
                    ),
                    metadata={"tool": call.tool, "scanned": len(args)},
                )
            )
        return verdicts

    # -- checks -------------------------------------------------------------

    def _check_canaries(
        self, call: ToolCall, args: list[_Arg], session_id: str | None
    ) -> list[Verdict]:
        out: list[Verdict] = []
        for arg in args:
            for hit in self.registry.find(arg.value):
                same_session = session_id is None or hit.session_id == session_id
                out.append(
                    Verdict(
                        decision=Decision.BLOCK,
                        layer=LAYER,
                        rule_id="OUT-CAN-001" if same_session else "OUT-CAN-002",
                        rationale=(
                            f"Tool '{call.tool}' argument {arg.path} contains a canary token "
                            f"minted for {hit.origin or 'an isolated document'}"
                            f"{'' if same_session else ' in a DIFFERENT session'}: "
                            f"untrusted content is being exfiltrated verbatim. "
                            f"Value: {truncate(self.registry.redact(arg.value))!r}"
                        ),
                        provenance=Source.UNTRUSTED,
                        metadata={
                            "tool": call.tool,
                            "path": arg.path,
                            "canary_origin": hit.origin,
                            "canary_session": hit.session_id,
                        },
                    )
                )
        return out

    def _check_injection(self, call: ToolCall, args: list[_Arg]) -> list[Verdict]:
        out: list[Verdict] = []
        for arg in args:
            if not arg.value.strip():
                continue
            result = self.backend.score(arg.value)
            threshold = self.thresholds[arg.source]
            if result.score < threshold:
                continue
            evidence = self.registry.redact(
                "; ".join(result.details.get(r, r) for r in result.matched[:3])
            )
            why_strict = (
                f" (untrusted-sourced from {arg.origin or 'unknown origin'}, so the stricter "
                f"{threshold:.2f} threshold applies)"
                if arg.source is Source.UNTRUSTED
                else f" (threshold {threshold:.2f} for {arg.source.value} provenance)"
            )
            out.append(
                Verdict(
                    decision=Decision.BLOCK,
                    layer=LAYER,
                    rule_id="OUT-INJ-001",
                    rationale=(
                        f"Tool '{call.tool}' argument {arg.path} scores {result.score:.2f} for "
                        f"injection{why_strict}. Signals: {evidence}. "
                        f"Value: {truncate(self.registry.redact(arg.value))!r}"
                    ),
                    score=result.score,
                    provenance=arg.source,
                    metadata={
                        "tool": call.tool,
                        "path": arg.path,
                        "matched": result.matched,
                        "threshold": threshold,
                        "origin": arg.origin,
                    },
                )
            )
        return out

    # -- helpers for hosts --------------------------------------------------

    @staticmethod
    def provenance_summary(call: ToolCall) -> dict[str, str]:
        """``{"args.body": "untrusted", ...}`` — handy for logs and tests."""
        return {a.path: a.source.value for a in _walk(call.args, "args", Source.UNKNOWN, None)}


__all__ = ["OutputScanner", "Predicate", "source_of"]
