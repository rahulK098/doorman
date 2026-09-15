"""Core value types shared by every layer.

These are deliberately plain frozen dataclasses with no behaviour beyond
convenience accessors, so that any layer (or a host application) can construct
and inspect them without importing anything else from Doorman.

See docs/adr/0002-provenance-as-wrapper-type.md and
docs/adr/0005-verdicts-carry-rationale.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class Source(str, Enum):
    """Where a value came from. The unit of provenance."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Tagged(Generic[T]):
    """A value carrying its provenance.

    Wrap any tool-call argument in ``Tagged`` to tell the ``OutputScanner`` how
    much to trust it. ``origin`` is a free-form label used in rationale text,
    e.g. ``"resume:cand_42"``.
    """

    value: T
    source: Source
    origin: str | None = None

    def __str__(self) -> str:  # so f-strings of a Tagged[str] give the raw text
        return str(self.value)


def untag(value: Any) -> Any:
    """Recursively strip ``Tagged`` wrappers, returning plain Python values."""
    if isinstance(value, Tagged):
        return untag(value.value)
    if isinstance(value, dict):
        return {k: untag(v) for k, v in value.items()}
    if isinstance(value, list):
        return [untag(v) for v in value]
    if isinstance(value, tuple):
        return tuple(untag(v) for v in value)
    return value


def source_of(value: Any) -> Source:
    """The provenance of a value: the tag if wrapped, else ``UNKNOWN``."""
    return value.source if isinstance(value, Tagged) else Source.UNKNOWN


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation the agent *proposes* to make.

    ``args`` values may be plain Python values or ``Tagged`` wrappers. Use
    ``plain_args`` to get what should actually be sent to the tool.
    """

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    id: str | None = None

    @property
    def plain_args(self) -> dict[str, Any]:
        return untag(self.args)  # type: ignore[no-any-return]


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"  # allowed, but noteworthy — always logged
    CONFIRM = "confirm"  # needs human approval before proceeding
    BLOCK = "block"

    @property
    def permits(self) -> bool:
        """True if the action may proceed without further intervention."""
        return self in (Decision.ALLOW, Decision.WARN)


# Ordering used when merging verdicts: the most restrictive wins.
_SEVERITY = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.CONFIRM: 2, Decision.BLOCK: 3}


@dataclass(frozen=True)
class Verdict:
    """The result of one layer examining one thing.

    Every verdict — including ``ALLOW`` — carries a human-readable
    ``rationale`` naming the specific value that produced it.
    """

    decision: Decision
    layer: str
    rule_id: str
    rationale: str
    score: float | None = None
    provenance: Source | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def permits(self) -> bool:
        return self.decision.permits

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "layer": self.layer,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
            "score": self.score,
            "provenance": self.provenance.value if self.provenance else None,
            "metadata": self.metadata,
        }


def most_severe(verdicts: list[Verdict]) -> Verdict | None:
    """Pick the verdict that should govern when several layers have spoken."""
    if not verdicts:
        return None
    return max(verdicts, key=lambda v: _SEVERITY[v.decision])


def truncate(text: str, limit: int = 120) -> str:
    """Shorten a value for inclusion in a rationale string."""
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
