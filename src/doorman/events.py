"""Structured event log.

Every verdict any layer produces inside a ``Guard`` is recorded here with the
session id and a timestamp. The log can be dumped as JSON lines for the bench
reports and is mirrored to the stdlib ``doorman`` logger so hosts see
rationales with zero setup.

See docs/adr/0005-verdicts-carry-rationale.md.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from doorman.types import Decision, Verdict

log = logging.getLogger("doorman")

_LEVELS = {
    Decision.ALLOW: logging.DEBUG,
    Decision.WARN: logging.WARNING,
    Decision.CONFIRM: logging.WARNING,
    Decision.BLOCK: logging.ERROR,
}


@dataclass(frozen=True)
class Event:
    verdict: Verdict
    session_id: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.timestamp.isoformat(),
            "session_id": self.session_id,
            **self.verdict.to_dict(),
            "context": self.context,
        }


class EventLog:
    """Thread-safe append-only record of verdicts."""

    def __init__(self, *, mirror_to_logging: bool = True, max_events: int | None = None) -> None:
        self._events: list[Event] = []
        self._lock = threading.Lock()
        self._mirror = mirror_to_logging
        self._max = max_events

    def emit(self, verdict: Verdict, session_id: str | None = None, **context: Any) -> Event:
        event = Event(verdict=verdict, session_id=session_id, context=context)
        with self._lock:
            self._events.append(event)
            if self._max is not None and len(self._events) > self._max:
                del self._events[: len(self._events) - self._max]
        if self._mirror:
            log.log(
                _LEVELS[verdict.decision],
                "%s %s/%s session=%s: %s",
                verdict.decision.value.upper(),
                verdict.layer,
                verdict.rule_id,
                session_id,
                verdict.rationale,
            )
        return event

    def __iter__(self) -> Iterator[Event]:
        with self._lock:
            return iter(list(self._events))

    def __len__(self) -> int:
        return len(self._events)

    def for_session(self, session_id: str) -> list[Event]:
        return [e for e in self if e.session_id == session_id]

    def blocks(self) -> list[Event]:
        return [e for e in self if e.verdict.decision is Decision.BLOCK]

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e.to_dict(), default=str) for e in self)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
