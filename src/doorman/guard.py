"""Guard: composes layers into a protected pipeline.

``Guard`` is the only object that knows the order of layers and passes one
layer's output to another (docs/adr/0001-layer-composition-model.md). Every
layer is optional. Two entry points:

* ``ingest()`` — run untrusted content through the Classifier, charge the
  session risk budget, and Isolate it for the prompt.
* ``check_tool_call()`` / ``protect()`` — run a proposed tool call through
  ToolPolicy, OutputScanner and ConfirmationGate with the current session risk.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from doorman.canary import CanaryRegistry
from doorman.errors import ActionBlocked, ConfirmationRequired, ContentQuarantined
from doorman.events import EventLog
from doorman.layers.classifier import Classifier
from doorman.layers.confirmation_gate import ConfirmationGate
from doorman.layers.isolator import IsolatedBlock, Isolator
from doorman.layers.output_scanner import OutputScanner
from doorman.layers.tool_policy import ToolPolicy
from doorman.session import SessionRiskTracker
from doorman.types import Decision, ToolCall, Verdict, most_severe

R = TypeVar("R")


@dataclass(frozen=True)
class Ingested:
    """Result of ``Guard.ingest``."""

    block: IsolatedBlock | None  # None when quarantined
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def quarantined(self) -> bool:
        return self.block is None

    @property
    def text(self) -> str:
        if self.block is None:
            raise ContentQuarantined(self.governing)
        return self.block.text

    @property
    def governing(self) -> Verdict:
        v = most_severe(self.verdicts)
        assert v is not None
        return v


@dataclass(frozen=True)
class GuardDecision:
    """Result of ``Guard.check_tool_call``."""

    call: ToolCall
    verdicts: list[Verdict]

    @property
    def governing(self) -> Verdict:
        v = most_severe(self.verdicts)
        assert v is not None
        return v

    @property
    def decision(self) -> Decision:
        return self.governing.decision

    @property
    def permits(self) -> bool:
        return self.decision.permits

    @property
    def rationale(self) -> str:
        return self.governing.rationale

    def raise_for_decision(self) -> None:
        if self.decision is Decision.BLOCK:
            raise ActionBlocked(self.governing, self.verdicts)
        if self.decision is Decision.CONFIRM:
            raise ConfirmationRequired(self.governing, self.verdicts)


class Guard:
    """
    Parameters
    ----------
    classifier, isolator, tool_policy, output_scanner, confirmation_gate, risk_tracker:
        Layers to compose. All optional.
    event_log:
        Where verdicts are recorded. A fresh ``EventLog`` if not given.
    quarantine_on_block:
        If the Classifier blocks ingested content, do not isolate it at all
        (``Ingested.block`` is ``None``). If False, content is still isolated
        and the block verdict is merely logged.
    risk_per_block:
        Risk charged to the session each time a tool call is blocked. A
        blocked exfiltration attempt is strong evidence the session is
        compromised, so later calls face a higher bar.
    """

    def __init__(
        self,
        *,
        classifier: Classifier | None = None,
        isolator: Isolator | None = None,
        tool_policy: ToolPolicy | None = None,
        output_scanner: OutputScanner | None = None,
        confirmation_gate: ConfirmationGate | None = None,
        risk_tracker: SessionRiskTracker | None = None,
        event_log: EventLog | None = None,
        quarantine_on_block: bool = True,
        risk_per_block: float = 0.5,
    ) -> None:
        self.classifier = classifier
        self.isolator = isolator
        self.tool_policy = tool_policy
        self.output_scanner = output_scanner
        self.confirmation_gate = confirmation_gate
        self.risk_tracker = risk_tracker
        self.events = event_log if event_log is not None else EventLog()
        self.quarantine_on_block = quarantine_on_block
        self.risk_per_block = risk_per_block

        # The Isolator mints canaries and the OutputScanner checks for them;
        # they must share one registry. The isolator's wins if both exist.
        self.canaries: CanaryRegistry = (
            isolator.registry
            if isolator is not None
            else output_scanner.registry
            if output_scanner is not None
            else CanaryRegistry()
        )
        if output_scanner is not None:
            output_scanner.registry = self.canaries

    # -- ingestion ----------------------------------------------------------

    def ingest(self, content: str, session_id: str, *, origin: str | None = None) -> Ingested:
        """Classify, charge risk, and isolate one piece of untrusted content."""
        verdicts: list[Verdict] = []
        quarantine = False

        if self.classifier is not None:
            v = self.classifier.check(content, origin=origin)
            verdicts.append(self._emit(v, session_id, origin=origin))
            if self.risk_tracker is not None:
                verdicts.append(
                    self._emit(
                        self.risk_tracker.record(
                            session_id, v.score or 0.0, label=origin or "ingest"
                        ),
                        session_id,
                        origin=origin,
                    )
                )
            quarantine = self.quarantine_on_block and v.decision is Decision.BLOCK

        if quarantine:
            return Ingested(block=None, verdicts=verdicts)

        if self.isolator is not None:
            block = self.isolator.isolate(content, session_id, origin=origin)
            for v in block.verdicts:
                verdicts.append(self._emit(v, session_id, origin=origin))
            if self.risk_tracker is not None and block.forgery_detected:
                verdicts.append(
                    self._emit(
                        self.risk_tracker.record(session_id, 0.4, label=f"forgery:{origin}"),
                        session_id,
                        origin=origin,
                    )
                )
            return Ingested(block=block, verdicts=verdicts)

        # No isolator configured: hand the content back untouched but tagged.
        if not verdicts:
            verdicts.append(self._emit(_no_layers_verdict("ingested content"), session_id))
        return Ingested(
            block=IsolatedBlock(
                text=content, raw=content, nonce="", session_id=session_id, origin=origin
            ),
            verdicts=verdicts,
        )

    def system_prompt_fragment(self, session_id: str) -> str:
        """Text to add to the host's system prompt (empty if no isolator)."""
        return "" if self.isolator is None else self.isolator.system_prompt_fragment(session_id)

    # -- tool calls ---------------------------------------------------------

    def check_tool_call(
        self, call: ToolCall, session_id: str, *, context: str | None = None
    ) -> GuardDecision:
        risk = self.risk_tracker.risk(session_id) if self.risk_tracker is not None else 0.0
        verdicts: list[Verdict] = []

        if self.tool_policy is not None:
            verdicts.append(
                self._emit(
                    self.tool_policy.check(call, context=context, risk=risk),
                    session_id,
                    tool=call.tool,
                )
            )

        if self.output_scanner is not None:
            for v in self.output_scanner.scan_all(call, session_id=session_id):
                verdicts.append(self._emit(v, session_id, tool=call.tool))

        blocked = any(v.blocked for v in verdicts)

        # Don't bother a human approver with something already blocked.
        if self.confirmation_gate is not None and not blocked:
            verdicts.append(
                self._emit(
                    self.confirmation_gate.check(call, risk=risk), session_id, tool=call.tool
                )
            )
            blocked = any(v.blocked for v in verdicts)

        if blocked and self.risk_tracker is not None and self.risk_per_block > 0:
            verdicts.append(
                self._emit(
                    self.risk_tracker.record(
                        session_id, self.risk_per_block, label=f"blocked:{call.tool}"
                    ),
                    session_id,
                    tool=call.tool,
                )
            )

        if not verdicts:
            verdicts.append(self._emit(_no_layers_verdict(f"tool call '{call.tool}'"), session_id))

        return GuardDecision(call=call, verdicts=verdicts)

    def protect(
        self,
        fn: Callable[..., R],
        session_id: str,
        *,
        context: str | None = None,
    ) -> Callable[..., R]:
        """Wrap an agent step so any ``ToolCall`` it returns is checked.

        ``fn`` may return a ``ToolCall``, an iterable of them, or anything else
        (passed through untouched). Blocked calls raise ``ActionBlocked``;
        calls needing approval with no approver raise ``ConfirmationRequired``.
        """

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> R:
            result = fn(*args, **kwargs)
            for call in _tool_calls_in(result):
                self.check_tool_call(call, session_id, context=context).raise_for_decision()
            return result

        return wrapper

    # -- lifecycle ----------------------------------------------------------

    def end_session(self, session_id: str) -> None:
        if self.isolator is not None:
            self.isolator.end_session(session_id)
        if self.risk_tracker is not None:
            self.risk_tracker.reset(session_id)
        self.canaries.forget(session_id)

    # -- internals ----------------------------------------------------------

    def _emit(self, verdict: Verdict, session_id: str, **context: Any) -> Verdict:
        self.events.emit(verdict, session_id, **context)
        return verdict


def _no_layers_verdict(what: str) -> Verdict:
    return Verdict(
        decision=Decision.ALLOW,
        layer="guard",
        rule_id="GUARD-000",
        rationale=f"No layers are configured to examine {what}; allowed by default.",
    )


def _tool_calls_in(result: Any) -> list[ToolCall]:
    if isinstance(result, ToolCall):
        return [result]
    if isinstance(result, (list, tuple)):
        return [r for r in result if isinstance(r, ToolCall)]
    return []
