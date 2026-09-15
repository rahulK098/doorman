"""Shared injection-likelihood scoring.

Both the ``Classifier`` layer (on ingested content) and the ``OutputScanner``
layer (on outbound tool-call arguments) need to score text. Keeping the backend
protocol and the default heuristic here lets both use it without importing each
other (docs/adr/0001-layer-composition-model.md).

The default backend is dependency-free heuristics — a *floor*, not a ceiling.
See docs/adr/0004-pluggable-classifier-with-heuristic-default.md.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ClassificationResult:
    score: float  # 0.0 (benign) .. 1.0 (certain injection)
    matched: list[str] = field(default_factory=list)  # rule ids / labels that fired
    details: dict[str, str] = field(default_factory=dict)  # rule id -> evidence snippet


@runtime_checkable
class ClassifierBackend(Protocol):
    name: str

    def score(self, text: str) -> ClassificationResult: ...


@dataclass(frozen=True)
class HeuristicRule:
    rule_id: str
    label: str
    pattern: re.Pattern[str]
    weight: float


def _r(rule_id: str, label: str, pattern: str, weight: float) -> HeuristicRule:
    return HeuristicRule(rule_id, label, re.compile(pattern, re.IGNORECASE | re.DOTALL), weight)


# Weights are calibrated so that one strong signal (~0.6) alone crosses the
# default 0.5 threshold, while two or three weak signals together also do.
DEFAULT_RULES: tuple[HeuristicRule, ...] = (
    _r(
        "CLS-H-001",
        "instruction override",
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|"
        r"your)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?)\b",
        0.65,
    ),
    _r(
        "CLS-H-002",
        "role reassignment",
        r"\b(you are now|from now on you|act as|pretend (to be|you are)|"
        r"your new (role|task|instructions?) (is|are))\b",
        0.45,
    ),
    _r(
        "CLS-H-003",
        "system prompt exfiltration",
        r"\b(reveal|print|show|repeat|output|display)\b.{0,30}\b(system prompt|"
        r"initial prompt|hidden instructions|your instructions)\b",
        0.6,
    ),
    _r(
        "CLS-H-004",
        "addressed to the model",
        r"\b(attention|note|important|message|hey|dear)\b[\s,:]*((to|for)\s+)?(the\s+)?"
        r"(ai|llm|assistant|model|gpt|claude|chatbot|system|language model)\b",
        0.5,
    ),
    _r(
        "CLS-H-005",
        "fake system/role marker",
        r"(^|\n)\s*(system|assistant|user|human|ai)\s*:\s*\S|\[/?(system|inst)\]|<\|im_start\|>|"
        r"<\|system\|>|###\s*(system|instruction)",
        0.5,
    ),
    _r(
        "CLS-H-006",
        "delimiter forgery",
        r"</?\s*(document|context|untrusted[^>]*|resume|email|user_input|data)\s*>",
        0.35,
    ),
    _r(
        "CLS-H-007",
        "action coercion",
        r"\b(you must|you should|you need to|make sure (to|you))\b.{0,40}\b(send|email|forward|"
        r"transfer|delete|approve|advance|score|rate|mark|call|execute|run)\b",
        0.4,
    ),
    _r(
        "CLS-H-008",
        "grading manipulation",
        r"\b(highest|maximum|perfect|top)\s+(score|rating|grade|marks?)\b|"
        r"\b(score|rate|grade)\b.{0,20}\b(this|me|the candidate)\b.{0,15}\b(100|10/10|\d{2,3}%)",
        0.45,
    ),
    _r(
        "CLS-H-009",
        "base64/hex blob",
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/])|\b(?:[0-9a-f]{2}\s?){40,}\b",
        0.25,
    ),
    _r(
        "CLS-H-010",
        "tool-call coercion",
        r"\b(call|invoke|use|run)\s+(the\s+)?(tool|function)\s+[`'\"]?\w+|"
        r"\b\w+\(\s*[\"'][^\"']*@[^\"']*[\"']",
        0.4,
    ),
    _r(
        "CLS-H-011",
        "exfiltration target",
        r"\b(send|forward|email|post|upload|transmit)\b.{0,60}"
        r"\b(to|at)\b.{0,20}[\w.+-]+@[\w-]+\.[\w.]+|https?://[^\s]{6,}",
        0.3,
    ),
    _r(
        "CLS-H-012",
        "secrecy instruction",
        r"\b(do not|don't|never)\s+(mention|tell|reveal|disclose|show|say)\b.{0,40}"
        r"\b(this|these|user|recruiter|human|anyone|instruction)",
        0.4,
    ),
)

# Zero-width and bidi-control characters are the standard tools for hiding text.
# Written as escapes on purpose: the literal characters are invisible in editors.
_HIDDEN_CODEPOINTS: tuple[int, ...] = (
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0x2061,  # FUNCTION APPLICATION
    0x2062,  # INVISIBLE TIMES
    0x2063,  # INVISIBLE SEPARATOR
    0x2064,  # INVISIBLE PLUS
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
)
_HIDDEN_CHARS = frozenset(chr(cp) for cp in _HIDDEN_CODEPOINTS)
_TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")  # Unicode "tag" characters


class HeuristicBackend:
    """Weighted-regex classifier. Zero dependencies. Stable rule ids."""

    name = "heuristic"

    def __init__(
        self,
        rules: Sequence[HeuristicRule] = DEFAULT_RULES,
        *,
        hidden_char_weight: float = 0.5,
        max_evidence: int = 80,
    ) -> None:
        self.rules = tuple(rules)
        self.hidden_char_weight = hidden_char_weight
        self._max_evidence = max_evidence

    def score(self, text: str) -> ClassificationResult:
        matched: list[str] = []
        details: dict[str, str] = {}
        weights: list[float] = []

        hidden = sum(1 for ch in text if ch in _HIDDEN_CHARS) + len(_TAG_CHARS_RE.findall(text))
        if hidden:
            matched.append("CLS-H-000")
            details["CLS-H-000"] = f"{hidden} hidden/zero-width/bidi/tag character(s)"
            # One stray char is often a copy-paste artifact; three or more is deliberate.
            weights.append(self.hidden_char_weight if hidden >= 3 else self.hidden_char_weight / 2)

        # Normalize so homoglyph / fullwidth tricks don't dodge the regexes.
        normalized = unicodedata.normalize("NFKC", text)
        normalized = "".join(ch for ch in normalized if ch not in _HIDDEN_CHARS)
        normalized = _TAG_CHARS_RE.sub("", normalized)

        for rule in self.rules:
            m = rule.pattern.search(normalized)
            if m:
                matched.append(rule.rule_id)
                snippet = m.group(0).replace("\n", " ")
                details[rule.rule_id] = f"{rule.label}: {snippet[: self._max_evidence]!r}"
                weights.append(rule.weight)

        # Saturating combination: 1 - Π(1 - w) keeps the score in [0, 1] and
        # rewards multiple independent signals without exceeding 1.
        survival = 1.0
        for w in weights:
            survival *= 1.0 - min(w, 0.99)
        return ClassificationResult(
            score=round(1.0 - survival, 4), matched=matched, details=details
        )
