"""Anthropic-backed ``AlignmentBackend`` for the ``IntentAligner``.

Install with ``pip install "doorman[anthropic]"``. Credentials are resolved by
the SDK from the environment (``ANTHROPIC_API_KEY``, ``ANTHROPIC_AUTH_TOKEN``
or an ``ant auth login`` profile); nothing is read or stored here.

The prompt this backend receives has already been stripped of untrusted
content by ``IntentAligner`` — this module must not add any.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

import anthropic
from anthropic.types import MessageParam, OutputConfigParam

from doorman.layers.intent_aligner import AlignmentJudgement

DEFAULT_MODEL = "claude-opus-5"

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_JSON_RE = re.compile(r"\{.*\}", re.S)

SYSTEM = (
    "You are a careful, literal security judge. Reply with exactly one JSON object and "
    "nothing else."
)


class AnthropicAlignmentBackend:
    """
    Parameters
    ----------
    model:
        Any current Claude model id. Defaults to ``claude-opus-5``.
    effort:
        ``output_config.effort``; this is a short classification so ``low``
        is the default. Raise it if you see inconsistent judgements.
    client:
        A pre-built ``anthropic.Anthropic`` (e.g. for a proxy or provider
        client). One is created from the environment if omitted.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        effort: Effort = "low",
        max_tokens: int = 512,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.client = client if client is not None else anthropic.Anthropic()

    def judge(self, prompt: str) -> AlignmentJudgement:
        output_config: OutputConfigParam = {"effort": self.effort}
        messages: list[MessageParam] = [{"role": "user", "content": prompt}]
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM,
            output_config=output_config,
            messages=messages,
        )
        if response.stop_reason == "refusal":
            return AlignmentJudgement(False, 1.0, "the judge model refused to evaluate the action")
        text = "".join(block.text for block in response.content if block.type == "text")
        return parse_judgement(text)


def parse_judgement(text: str) -> AlignmentJudgement:
    """Tolerant parse: the model is asked for bare JSON but may wrap it in prose."""
    match = _JSON_RE.search(text)
    if not match:
        raise ValueError(f"judge returned no JSON object: {text[:120]!r}")
    data: dict[str, Any] = json.loads(match.group(0))
    aligned = bool(data.get("aligned", False))
    confidence = float(data.get("confidence", 0.0))
    confidence = max(0.0, min(1.0, confidence))
    reasoning = str(data.get("reasoning", "")).strip() or "no reasoning given"
    return AlignmentJudgement(aligned, confidence, reasoning)
