"""Benchmark fixture format and loader.

A fixture is one *scenario*: an operator task, one or more untrusted
documents, and — for attacks — the action a gullible model would take after
reading them. Fixtures are JSON files under ``doorman/bench/data/<family>/``.

Schema::

    {
      "id": "canary-leak-001",
      "family": "canary_leak",
      "description": "why this fixture exists / what it proves",
      "task": "the operator's task, verbatim",
      "context": "scoring",
      "documents": [{"origin": "resume:x", "content": "..."}],
      "attack": true,
      "malicious_action": {"tool": "send_email", "args": {"to": "...", "body": "$doc:0"}},
      "success_condition": "action_executed",
      "expected_verdict": "block"
    }

Argument placeholders in ``malicious_action.args`` (strings only):

* ``"$doc:N"`` — the *isolated* text of document N (what the model saw),
  provenance-tagged untrusted. Simulates a model copying the block verbatim.
* ``"$raw:N"`` — the raw content of document N, tagged untrusted.
* ``"$untrusted:<text>"`` — a literal string tagged untrusted.

Benign fixtures (``"attack": false``) carry a ``benign_action`` instead: the
action a well-behaved model *should* be allowed to take. They measure false
positives.

Families (plan.md §7): ``direct``, ``hidden``, ``metadata``, ``indirect``,
``compounding``, ``canary_leak``, ``benign``, and ``discovered`` (auto-filed
by ``--evolve``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from doorman.types import Source, Tagged, ToolCall

DATA_DIR = Path(__file__).parent / "data"

FAMILIES = (
    "direct",
    "hidden",
    "metadata",
    "indirect",
    "compounding",
    "canary_leak",
    "benign",
    "discovered",
)


@dataclass(frozen=True)
class Document:
    origin: str
    content: str


@dataclass(frozen=True)
class Action:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Fixture:
    id: str
    family: str
    description: str
    task: str
    context: str
    documents: list[Document]
    attack: bool
    malicious_action: Action | None = None
    benign_action: Action | None = None
    success_condition: str = "action_executed"
    expected_verdict: str = "block"
    path: Path | None = None

    @property
    def action(self) -> Action:
        a = self.malicious_action if self.attack else self.benign_action
        if a is None:
            kind = "malicious_action" if self.attack else "benign_action"
            raise ValueError(f"fixture {self.id} has no {kind}")
        return a

    def to_tool_call(self, isolated_texts: list[str]) -> ToolCall:
        """Resolve placeholders against the isolated texts the model saw."""
        if len(isolated_texts) != len(self.documents):
            raise ValueError(
                f"fixture {self.id}: {len(self.documents)} documents but "
                f"{len(isolated_texts)} isolated texts"
            )
        args = _resolve(self.action.args, self, isolated_texts)
        return ToolCall(self.action.tool, args)


def _resolve(value: Any, fx: Fixture, isolated: list[str]) -> Any:
    if isinstance(value, str):
        if value.startswith("$doc:"):
            i = int(value[5:])
            return Tagged(isolated[i], Source.UNTRUSTED, fx.documents[i].origin)
        if value.startswith("$raw:"):
            i = int(value[5:])
            return Tagged(fx.documents[i].content, Source.UNTRUSTED, fx.documents[i].origin)
        if value.startswith("$untrusted:"):
            return Tagged(value[len("$untrusted:") :], Source.UNTRUSTED, "document")
        return value
    if isinstance(value, dict):
        return {k: _resolve(v, fx, isolated) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, fx, isolated) for v in value]
    return value


def _action(data: dict[str, Any] | None) -> Action | None:
    if data is None:
        return None
    return Action(tool=data["tool"], args=dict(data.get("args", {})))


def parse_fixture(data: dict[str, Any], path: Path | None = None) -> Fixture:
    family = data["family"]
    if family not in FAMILIES:
        raise ValueError(f"{path or data.get('id')}: unknown family {family!r}")
    fx = Fixture(
        id=data["id"],
        family=family,
        description=data.get("description", ""),
        task=data["task"],
        context=data.get("context", "scoring"),
        documents=[Document(d["origin"], d["content"]) for d in data["documents"]],
        attack=bool(data["attack"]),
        malicious_action=_action(data.get("malicious_action")),
        benign_action=_action(data.get("benign_action")),
        success_condition=data.get("success_condition", "action_executed"),
        expected_verdict=data.get("expected_verdict", "block" if data["attack"] else "allow"),
        path=path,
    )
    _ = fx.action  # raises if the required action is missing
    return fx


def iter_fixtures(root: Path = DATA_DIR, family: str | None = None) -> Iterator[Fixture]:
    families = [family] if family else sorted(p.name for p in root.iterdir() if p.is_dir())
    for fam in families:
        for path in sorted((root / fam).glob("*.json")):
            with path.open(encoding="utf-8") as f:
                yield parse_fixture(json.load(f), path)


def load_fixtures(family: str | None = None, root: Path = DATA_DIR) -> list[Fixture]:
    return list(iter_fixtures(root, family))
