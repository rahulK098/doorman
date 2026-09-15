"""ToolPolicy: per-context tool allowlist, risk-budget aware.

A *context* is the phase the agent is in ("scoring", "outreach"). Each context
has an allowlist of tools. When the session risk (a fraction of budget, from
``SessionRiskTracker``) rises, the policy can shrink the allowed set to the
tools marked ``always_safe`` or deny everything once the budget is exhausted.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from doorman.types import Decision, ToolCall, Verdict

LAYER = "tool_policy"


class ToolPolicy:
    """
    Parameters
    ----------
    contexts:
        ``{"scoring": ["read_document"], "outreach": ["send_email"]}``.
        Use ``"*"`` in a tool list to allow every tool in that context.
    always_safe:
        Tools that remain allowed even when the session risk budget is spent
        (typically read-only tools like ``read_document``).
    default_context:
        Used when ``check`` is called without a context.
    escalate_at:
        Session-risk fraction at which non-``always_safe`` tools switch from
        ``ALLOW`` to ``CONFIRM``. ``None`` disables risk awareness.
    deny_at:
        Session-risk fraction at which non-``always_safe`` tools are blocked
        outright.
    """

    def __init__(
        self,
        contexts: Mapping[str, Iterable[str]],
        *,
        always_safe: Iterable[str] = (),
        default_context: str | None = None,
        escalate_at: float | None = 0.6,
        deny_at: float | None = 1.0,
    ) -> None:
        if not contexts:
            raise ValueError("ToolPolicy needs at least one context")
        self.contexts: dict[str, frozenset[str]] = {
            name: frozenset(tools) for name, tools in contexts.items()
        }
        self.always_safe = frozenset(always_safe)
        self.default_context = default_context or next(iter(self.contexts))
        if self.default_context not in self.contexts:
            raise ValueError(f"default_context {self.default_context!r} is not a known context")
        self.escalate_at = escalate_at
        self.deny_at = deny_at

    def allowed_tools(self, context: str | None = None) -> frozenset[str]:
        return self.contexts[context or self.default_context]

    def is_allowed(self, tool: str, context: str | None = None) -> bool:
        allowed = self.allowed_tools(context)
        return tool in allowed or "*" in allowed

    def check(
        self,
        call: ToolCall | str,
        *,
        context: str | None = None,
        risk: float = 0.0,
    ) -> Verdict:
        tool = call.tool if isinstance(call, ToolCall) else call
        ctx = context or self.default_context
        if ctx not in self.contexts:
            return Verdict(
                decision=Decision.BLOCK,
                layer=LAYER,
                rule_id="POL-003",
                rationale=(
                    f"Tool '{tool}' proposed in unknown context '{ctx}'; "
                    f"known contexts are {sorted(self.contexts)}."
                ),
                metadata={"tool": tool, "context": ctx},
            )

        meta = {"tool": tool, "context": ctx, "risk": risk}
        if not self.is_allowed(tool, ctx):
            return Verdict(
                decision=Decision.BLOCK,
                layer=LAYER,
                rule_id="POL-001",
                rationale=(
                    f"Tool '{tool}' is not permitted in the '{ctx}' context; "
                    f"allowed: {sorted(self.allowed_tools(ctx))}."
                ),
                metadata=meta,
            )

        if tool in self.always_safe:
            return Verdict(
                decision=Decision.ALLOW,
                layer=LAYER,
                rule_id="POL-000",
                rationale=f"Tool '{tool}' is allowed in '{ctx}' and marked always-safe.",
                metadata=meta,
            )

        if self.deny_at is not None and risk >= self.deny_at:
            return Verdict(
                decision=Decision.BLOCK,
                layer=LAYER,
                rule_id="POL-002",
                rationale=(
                    f"Tool '{tool}' is normally allowed in '{ctx}', but the session risk "
                    f"budget is exhausted ({risk:.0%}); only always-safe tools "
                    f"{sorted(self.always_safe)} remain available."
                ),
                score=risk,
                metadata=meta,
            )
        if self.escalate_at is not None and risk >= self.escalate_at:
            return Verdict(
                decision=Decision.CONFIRM,
                layer=LAYER,
                rule_id="POL-004",
                rationale=(
                    f"Tool '{tool}' is allowed in '{ctx}', but session risk is elevated "
                    f"({risk:.0%} of budget); requiring confirmation."
                ),
                score=risk,
                metadata=meta,
            )
        return Verdict(
            decision=Decision.ALLOW,
            layer=LAYER,
            rule_id="POL-000",
            rationale=f"Tool '{tool}' is allowed in the '{ctx}' context (risk {risk:.0%}).",
            score=risk,
            metadata=meta,
        )
