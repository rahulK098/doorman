"""ConfirmationGate: hold irreversible actions for human approval.

The gate never executes anything. It decides whether a call needs approval,
and if an ``approver`` callback is configured it asks; otherwise it returns a
``CONFIRM`` verdict and lets the host handle the pause.

Session risk can *lower* the bar: above ``escalate_at`` (a fraction of the
risk budget) every non-exempt tool needs confirmation, not only the
irreversible ones.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from doorman.types import Decision, ToolCall, Verdict

LAYER = "confirmation_gate"

# Receives the call and the verdict explaining why approval is needed.
# Returns True to approve.
Approver = Callable[[ToolCall, Verdict], bool]


class ConfirmationGate:
    """
    Parameters
    ----------
    irreversible_tools:
        Tools that always need confirmation.
    exempt_tools:
        Tools that never need confirmation, even under elevated risk.
    approver:
        Optional callback. If present, the gate calls it and returns ``ALLOW``
        (approved) or ``BLOCK`` (declined). If absent, returns ``CONFIRM`` and
        the host must pause.
    escalate_at:
        Session-risk fraction above which *all* non-exempt tools need
        confirmation. ``None`` disables risk-based escalation.
    """

    def __init__(
        self,
        irreversible_tools: Iterable[str] = (),
        *,
        exempt_tools: Iterable[str] = (),
        approver: Approver | None = None,
        escalate_at: float | None = 0.5,
    ) -> None:
        self.irreversible_tools = frozenset(irreversible_tools)
        self.exempt_tools = frozenset(exempt_tools)
        self.approver = approver
        self.escalate_at = escalate_at

    def needs_confirmation(self, tool: str, *, risk: float = 0.0) -> tuple[bool, str, str]:
        """(needs?, rule_id, reason)."""
        if tool in self.exempt_tools:
            return False, "GATE-000", f"Tool '{tool}' is exempt from confirmation."
        if tool in self.irreversible_tools:
            return True, "GATE-001", f"Tool '{tool}' is irreversible"
        if self.escalate_at is not None and risk >= self.escalate_at:
            return (
                True,
                "GATE-002",
                f"Tool '{tool}' is normally reversible, but session risk is elevated "
                f"({risk:.0%} of budget, escalation at {self.escalate_at:.0%})",
            )
        return (
            False,
            "GATE-000",
            f"Tool '{tool}' is reversible and session risk is low ({risk:.0%}).",
        )

    def check(self, call: ToolCall, *, risk: float = 0.0) -> Verdict:
        needs, rule_id, reason = self.needs_confirmation(call.tool, risk=risk)
        meta = {"tool": call.tool, "risk": risk}
        if not needs:
            return Verdict(
                decision=Decision.ALLOW,
                layer=LAYER,
                rule_id=rule_id,
                rationale=reason,
                metadata=meta,
            )

        pending = Verdict(
            decision=Decision.CONFIRM,
            layer=LAYER,
            rule_id=rule_id,
            rationale=f"{reason}; human approval required before executing.",
            score=risk,
            metadata=meta,
        )
        if self.approver is None:
            return pending

        approved = self.approver(call, pending)
        if approved:
            return Verdict(
                decision=Decision.ALLOW,
                layer=LAYER,
                rule_id=rule_id + "-APPROVED",
                rationale=f"{reason}; approved by the configured approver.",
                score=risk,
                metadata={**meta, "approved": True},
            )
        return Verdict(
            decision=Decision.BLOCK,
            layer=LAYER,
            rule_id=rule_id + "-DECLINED",
            rationale=f"{reason}; the approver declined.",
            score=risk,
            metadata={**meta, "approved": False},
        )
