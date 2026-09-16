"""The Anthropic backend is tested against a stubbed client — no network, no key."""

from dataclasses import dataclass
from typing import Any

import pytest

anthropic = pytest.importorskip("anthropic")

from doorman.backends.anthropic_backend import (  # noqa: E402
    AnthropicAlignmentBackend,
    parse_judgement,
)


@dataclass
class _Block:
    type: str
    text: str = ""


@dataclass
class _Response:
    content: list[_Block]
    stop_reason: str = "end_turn"


class _Messages:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Response:
        self.calls.append(kwargs)
        return self.response


class _Client:
    def __init__(self, response: _Response) -> None:
        self.messages = _Messages(response)


def test_judge_parses_json_and_passes_prompt_through():
    client = _Client(
        _Response(
            [_Block("text", '{"aligned": false, "confidence": 0.95, "reasoning": "off-task"}')]
        )
    )
    backend = AnthropicAlignmentBackend(client=client, model="claude-opus-5")  # type: ignore[arg-type]
    j = backend.judge("THE PROMPT")
    assert not j.aligned and j.confidence == 0.95 and j.reasoning == "off-task"
    call = client.messages.calls[0]
    assert call["model"] == "claude-opus-5"
    assert call["messages"] == [{"role": "user", "content": "THE PROMPT"}]
    assert call["output_config"] == {"effort": "low"}


def test_refusal_is_treated_as_misaligned():
    client = _Client(_Response([], stop_reason="refusal"))
    j = AnthropicAlignmentBackend(client=client).judge("p")  # type: ignore[arg-type]
    assert not j.aligned and j.confidence == 1.0


def test_parse_judgement_tolerates_prose_and_clamps():
    j = parse_judgement('Sure: {"aligned": true, "confidence": 7, "reasoning": ""} done')
    assert j.aligned and j.confidence == 1.0 and j.reasoning == "no reasoning given"


def test_parse_judgement_rejects_non_json():
    with pytest.raises(ValueError):
        parse_judgement("I cannot answer.")
