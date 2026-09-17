"""Adapter for the Anthropic Messages API tool-use loop.

Wrap an existing tool-use loop in three calls:

    from doorman.adapters.anthropic import AnthropicGuard

    ag = AnthropicGuard(guard, session_id="sess_1", context="outreach")
    system = ag.system_prompt(BASE_SYSTEM)          # adds the isolation notice
    block  = ag.ingest(resume_text, "resume:42")    # classify + isolate

    response = client.messages.create(..., system=system, tools=TOOLS, messages=msgs)
    results  = ag.handle(response, execute=my_tool_executor)   # checks, then executes
    msgs.append({"role": "assistant", "content": response.content})
    msgs.append({"role": "user", "content": results})

``handle`` converts every ``tool_use`` block into a ``ToolCall``, runs it
through the ``Guard``, and returns the ``tool_result`` blocks to send back —
including ``is_error`` results carrying the block rationale, so the model
learns why it was refused instead of silently retrying.

Requires ``doorman[anthropic]`` only for type checking; at runtime it works on
any object with the right shape (the SDK's ``Message``), so it is importable
without the SDK installed.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from doorman.guard import Guard, GuardDecision
from doorman.types import Decision, Source, Tagged, ToolCall

# A host executor: given an approved ToolCall, do the thing and return a result.
Executor = Callable[[ToolCall], Any]

REFUSAL_PREFIX = "Blocked by policy"


@dataclass
class HandledCall:
    call: ToolCall
    decision: GuardDecision
    executed: bool
    result: Any = None

    @property
    def permitted(self) -> bool:
        return self.decision.permits


@dataclass
class AnthropicGuard:
    """
    Parameters
    ----------
    guard:
        The composed ``Guard``.
    session_id:
        Session key for the nonce, canaries, risk budget and task.
    context:
        Tool-policy context for calls in this phase of the agent.
    tag_model_strings:
        Tag every string the model writes into tool arguments as untrusted.
        Correct for any turn after the model has read untrusted content, which
        is why it defaults to on.
    """

    guard: Guard
    session_id: str
    context: str | None = None
    tag_model_strings: bool = True
    handled: list[HandledCall] = field(default_factory=list)

    # -- setup ---------------------------------------------------------------

    def begin(self, task: str) -> None:
        """Register the operator's task for the IntentAligner."""
        self.guard.begin_session(self.session_id, task=task)

    def system_prompt(self, base: str) -> str:
        """``base`` plus the isolation notice for this session."""
        fragment = self.guard.system_prompt_fragment(self.session_id)
        return f"{base}\n\n{fragment}" if fragment else base

    def ingest(self, content: str, origin: str | None = None) -> str:
        """Classify, charge risk and isolate; returns the text to put in the prompt.

        Raises ``ContentQuarantined`` if the classifier blocked it — catch that
        to skip the document rather than feeding it to the model.
        """
        return self.guard.ingest(content, self.session_id, origin=origin).text

    def end(self) -> None:
        self.guard.end_session(self.session_id)

    # -- the loop ------------------------------------------------------------

    def to_tool_calls(self, response: Any, *, origin: str | None = None) -> list[ToolCall]:
        """Every ``tool_use`` block in a Messages API response, as ``ToolCall``s."""
        calls: list[ToolCall] = []
        for block in getattr(response, "content", []):
            if getattr(block, "type", None) != "tool_use":
                continue
            args = dict(block.input or {})
            if self.tag_model_strings:
                args = _tag(args, origin or "model output")
            calls.append(ToolCall(block.name, args, id=block.id))
        return calls

    def check(self, call: ToolCall) -> GuardDecision:
        return self.guard.check_tool_call(call, self.session_id, context=self.context)

    def handle(
        self,
        response: Any,
        *,
        execute: Executor | None = None,
        origin: str | None = None,
    ) -> list[dict[str, Any]]:
        """Check every proposed call, execute the permitted ones, return tool_result blocks.

        Blocked and confirmation-pending calls come back as ``is_error`` results
        whose text is the layer's rationale. All results are returned together,
        which is what the API expects for parallel tool use.
        """
        blocks: list[dict[str, Any]] = []
        for call in self.to_tool_calls(response, origin=origin):
            decision = self.check(call)
            handled = HandledCall(call=call, decision=decision, executed=False)

            if decision.decision is Decision.BLOCK:
                blocks.append(_result(call, f"{REFUSAL_PREFIX}: {decision.rationale}", error=True))
            elif decision.decision is Decision.CONFIRM:
                blocks.append(
                    _result(
                        call,
                        f"Awaiting human approval: {decision.rationale}",
                        error=True,
                    )
                )
            elif execute is None:
                blocks.append(_result(call, "Approved (no executor configured)."))
            else:
                handled.result = execute(call)
                handled.executed = True
                blocks.append(_result(call, handled.result))

            self.handled.append(handled)
        return blocks

    # -- reporting -----------------------------------------------------------

    @property
    def blocked(self) -> list[HandledCall]:
        return [h for h in self.handled if h.decision.decision is Decision.BLOCK]

    @property
    def held(self) -> list[HandledCall]:
        return [h for h in self.handled if h.decision.decision is Decision.CONFIRM]

    @property
    def executed(self) -> list[HandledCall]:
        return [h for h in self.handled if h.executed]


def _result(call: ToolCall, content: Any, *, error: bool = False) -> dict[str, Any]:
    block: dict[str, Any] = {
        "type": "tool_result",
        "tool_use_id": call.id or "",
        "content": content if isinstance(content, str) else str(content),
    }
    if error:
        block["is_error"] = True
    return block


def _tag(value: Any, origin: str) -> Any:
    if isinstance(value, str):
        return Tagged(value, Source.UNTRUSTED, origin)
    if isinstance(value, dict):
        return {k: _tag(v, origin) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_tag(v, origin) for v in value]
    return value


def tool_definitions_from_policy(
    guard: Guard, context: str, schemas: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Filter tool schemas down to what the policy allows in ``context``.

    Not a security control — the ``Guard`` still checks every call — but it
    keeps the model from proposing actions it will only be refused for, which
    saves tokens and avoids confusing retry loops.
    """
    if guard.tool_policy is None:
        return list(schemas)
    return [s for s in schemas if guard.tool_policy.is_allowed(s["name"], context)]
