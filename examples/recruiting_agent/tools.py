"""Fake side-effecting tools for the recruiting agent.

Everything writes to in-memory records so a benchmark run can inspect exactly
which side effects happened. Nothing here touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from doorman.types import ToolCall


@dataclass(frozen=True)
class Email:
    to: list[str]
    subject: str
    body: str


@dataclass(frozen=True)
class ScoreRecord:
    candidate: str
    score: int
    notes: str


@dataclass
class World:
    """Observable side effects of a run."""

    outbox: list[Email] = field(default_factory=list)
    ats: dict[str, ScoreRecord] = field(default_factory=dict)
    advanced: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)

    def execute(self, call: ToolCall) -> str:
        """Perform the side effect for ``call`` and return the tool's text result."""
        args = call.plain_args
        if call.tool == "read_document":
            self.reads.append(str(args.get("document_id", "")))
            return "ok"
        if call.tool == "write_ats_score":
            rec = ScoreRecord(
                candidate=str(args.get("candidate", "")),
                score=int(args.get("score", 0)),
                notes=str(args.get("notes", "")),
            )
            self.ats[rec.candidate] = rec
            return f"scored {rec.candidate} = {rec.score}"
        if call.tool == "send_email":
            to = args.get("to", [])
            to_list = [to] if isinstance(to, str) else [str(t) for t in to]
            email = Email(
                to=to_list, subject=str(args.get("subject", "")), body=str(args.get("body", ""))
            )
            self.outbox.append(email)
            return f"sent to {', '.join(to_list)}"
        if call.tool == "advance_status":
            self.advanced.append(str(args.get("candidate", "")))
            return "advanced"
        raise ValueError(f"unknown tool {call.tool!r}")


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_document",
        "description": "Read a candidate document by id.",
        "input_schema": {
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
            "required": ["document_id"],
        },
    },
    {
        "name": "write_ats_score",
        "description": "Record a 0-100 score and notes for a candidate in the ATS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "string"},
                "score": {"type": "integer", "minimum": 0, "maximum": 100},
                "notes": {"type": "string"},
            },
            "required": ["candidate", "score"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "advance_status",
        "description": "Move a candidate to the next pipeline stage.",
        "input_schema": {
            "type": "object",
            "properties": {"candidate": {"type": "string"}},
            "required": ["candidate"],
        },
    },
]
