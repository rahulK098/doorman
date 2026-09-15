"""Session-level risk budget.

Individual documents may each stay under a classifier threshold while together
they add up to an attack. ``SessionRiskTracker`` accumulates risk across a
session so ``ToolPolicy`` and ``ConfirmationGate`` can escalate once the budget
is spent — even if no single message tripped anything.

The tracker is a cross-cutting object: it is handed to layers by ``Guard`` and
never discovered by them (docs/adr/0001-layer-composition-model.md).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from doorman.types import Decision, Verdict


@dataclass
class SessionRisk:
    total: float = 0.0
    contributions: list[tuple[str, float]] = field(default_factory=list)  # (label, amount)

    @property
    def count(self) -> int:
        return len(self.contributions)


class SessionRiskTracker:
    """Accumulates risk per session against a fixed budget.

    ``budget`` is the cumulative score at which the session is considered
    compromised. ``decay`` is subtracted per recorded event to let long,
    benign sessions breathe; set it to 0 for a strict budget.
    """

    LAYER = "risk_tracker"

    def __init__(self, *, budget: float = 1.5, decay: float = 0.0) -> None:
        if budget <= 0:
            raise ValueError("budget must be positive")
        self.budget = budget
        self.decay = decay
        self._sessions: dict[str, SessionRisk] = {}
        self._lock = threading.Lock()

    def record(self, session_id: str, amount: float, label: str = "") -> Verdict:
        """Add ``amount`` of risk and return a verdict describing the budget state."""
        with self._lock:
            state = self._sessions.setdefault(session_id, SessionRisk())
            state.total = max(0.0, state.total - self.decay) + max(0.0, amount)
            state.contributions.append((label, amount))
            total, n = state.total, state.count

        fraction = total / self.budget
        if fraction >= 1.0:
            return Verdict(
                decision=Decision.BLOCK,
                layer=self.LAYER,
                rule_id="RISK-001",
                rationale=(
                    f"Session risk budget exhausted: {total:.2f} of {self.budget:.2f} "
                    f"accumulated over {n} event(s); latest '{label}' added {amount:.2f}."
                ),
                score=fraction,
                metadata={"total": total, "budget": self.budget, "events": n},
            )
        if fraction >= 0.5:
            return Verdict(
                decision=Decision.WARN,
                layer=self.LAYER,
                rule_id="RISK-002",
                rationale=(
                    f"Session risk at {total:.2f} of {self.budget:.2f} budget "
                    f"({fraction:.0%}) after {n} event(s)."
                ),
                score=fraction,
                metadata={"total": total, "budget": self.budget, "events": n},
            )
        return Verdict(
            decision=Decision.ALLOW,
            layer=self.LAYER,
            rule_id="RISK-000",
            rationale=f"Session risk {total:.2f} of {self.budget:.2f} budget after {n} event(s).",
            score=fraction,
            metadata={"total": total, "budget": self.budget, "events": n},
        )

    def risk(self, session_id: str) -> float:
        """Current risk as a fraction of budget (0.0 = clean, >=1.0 = exhausted)."""
        with self._lock:
            state = self._sessions.get(session_id)
            return 0.0 if state is None else state.total / self.budget

    def exhausted(self, session_id: str) -> bool:
        return self.risk(session_id) >= 1.0

    def state(self, session_id: str) -> SessionRisk:
        with self._lock:
            s = self._sessions.get(session_id, SessionRisk())
            return SessionRisk(total=s.total, contributions=list(s.contributions))

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
