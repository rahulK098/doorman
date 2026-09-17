"""Shared injection-likelihood scoring.

Both the ``Classifier`` layer (on ingested content) and the ``OutputScanner``
layer (on outbound tool-call arguments) need to score text. Keeping the backend
protocol and the default heuristic here lets both use it without importing each
other (docs/adr/0001-layer-composition-model.md).

The default backend is dependency-free heuristics — a *floor*, not a ceiling.
See docs/adr/0004-pluggable-classifier-with-heuristic-default.md.
"""

from __future__ import annotations

import base64
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
        r"\b(ignore|disregard|forget|override|set aside|put aside|overlook|look past)\b.{0,40}"
        r"\b(previous|prior|above|earlier|all|your|the|this)\b.{0,30}"
        r"\b(instructions?|prompts?|rules?|guidelines?|guidance|directives?|rubric)\b|"
        r"\b(what you were told|guidance above|earlier guidance)\b.{0,30}"
        r"\b(before|no longer applies|superseded|is void)\b|"
        r"\bno longer applies\b",
        0.65,
    ),
    _r(
        "CLS-H-002",
        "role reassignment",
        r"\b(you are now|from now on you|act as|pretend (to be|you are)|consider yourself|"
        r"from this point you (act|are)|your new (role|task|instructions?) (is|are))\b",
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
        r"\b(attention|note|important|message|hey|dear|instructions?)\b[\s,:]*((to|for)\s+)?"
        r"(the\s+|any\s+)?(ai|llm|assistant|model|gpt|claude|chatbot|system|language model|"
        r"reviewer ai|ai reviewer|ai reading)\b|"
        r"\b(with|by|from|to) the (ai|assistant|model|reader|reviewer|screening tool)\b|"
        r"\[(ai|assistant)[: ]",
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
        # "be certain to" / "remember to" / "kindly" added after --evolve found
        # that paraphrasing "make sure you" bypassed this rule (discovered/*).
        r"\b(you must|you should|you need to|make sure (to|you)|be (certain|sure) to|"
        r"remember to|kindly|please|"
        r"(the )?(assistant|ai|model|reviewer|reader|screening tool) "
        r"(must|should|will|needs? to|ought to|will want to|is to))"
        r"\b.{0,40}\b(send|email|forward|transfer|delete|approve|advance|score|rate|mark|call|"
        r"execute|run)\b",
        0.4,
    ),
    _r(
        "CLS-H-008",
        "grading manipulation",
        r"\b(highest|maximum|perfect|top)\s+(score|rating|grade|marks?)\b|"
        r"\b(score|rate|grade)\b.{0,20}\b(this|me|the candidate)\b.{0,15}\b(100|10/10|\d{2,3}%)|"
        r"\b(rate|score|grade|mark|rank)\b.{0,30}\b(generously|favou?rably|highly|leniently)\b|"
        r"\bstrong hire\b|\btop of the (batch|list|pile)\b|"
        r"\b(already|has been|is) (pre-?)?approved\b|"
        # statements of a pre-decided score, found by the base benchmark
        r"\b(score|rating|grade)\b.{0,25}\b(is|=|:|at|of)\s*(100|10/10|100%)\b|"
        r"\b(scored|rated|graded)\s+(100|10/10|a perfect)\b|\bfinal score is\b|"
        r"\bcorrect score is\b|\bscore\s*=\s*\d{2,3}\b",
        0.45,
    ),
    _r(
        "CLS-H-013",
        "letter spacing evasion",
        # "I g n o r e" / "S.c.o.r.e" — four or more single letters separated by spaces/dots.
        r"(?:\b[A-Za-z][ .\-]){4,}[A-Za-z]\b",
        0.5,
    ),
    _r(
        "CLS-H-014",
        "skip-the-check instruction",
        r"\b(skip|bypass|without)\b.{0,20}\b(scoring|the score|review|screening|approval)\b|"
        r"\b(override|overrid(e|ing)) (the )?(scoring|rubric|review)\b|"
        r"\b(advance|promote|move)\b.{0,30}\b(without|before|instead of)\b.{0,15}\b(scor|review)",
        0.5,
    ),
    _r(
        "CLS-H-009",
        "base64/hex blob",
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])|\b(?:[0-9a-f]{2}\s?){40,}\b",
        0.3,
    ),
    _r(
        "CLS-H-015",
        "decode-and-follow",
        r"\b(base64|rot13|hex|encoded)\b.{0,30}\b(decode|decipher)\b|"
        r"\bdecode\b.{0,20}\b(and|then)\b.{0,10}\b(follow|act|execute|apply|obey|comply)\b",
        0.5,
    ),
    _r(
        "CLS-H-016",
        "score dictation",
        r"\b(score|rating|grade|mark)\b.{0,40}\b(pre-?approved|already (set|decided|agreed|fixed)|"
        r"is (fixed|final|settled)|non-?negotiable)\b",
        0.5,
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
_BIDI_OVERRIDES = frozenset(chr(cp) for cp in (0x202D, 0x202E))  # LRO, RLO

# Cyrillic / Greek letters that render identically to Latin ones. NFKC does not
# fold these; we do, before the regexes run, and count mixed-script words as a
# signal in their own right (a resume has no reason to mix scripts mid-word).
_CONFUSABLES = str.maketrans(
    {
        0x0430: "a",
        0x0435: "e",
        0x043E: "o",
        0x0440: "p",
        0x0441: "c",
        0x0445: "x",
        0x0443: "y",
        0x0456: "i",
        0x0455: "s",
        0x0458: "j",
        0x04BB: "h",
        0x0432: "b",
        0x043A: "k",
        0x043C: "m",
        0x043D: "h",
        0x0442: "t",
        0x0410: "A",
        0x0412: "B",
        0x0415: "E",
        0x041A: "K",
        0x041C: "M",
        0x041D: "H",
        0x041E: "O",
        0x0420: "P",
        0x0421: "C",
        0x0422: "T",
        0x0425: "X",
        0x03B1: "a",
        0x03BF: "o",
        0x03C1: "p",
        0x0391: "A",
        0x0392: "B",
        0x0395: "E",
        0x0397: "H",
        0x0399: "I",
        0x039A: "K",
        0x039C: "M",
        0x039D: "N",
        0x039F: "O",
        0x03A1: "P",
        0x03A4: "T",
        0x03A5: "Y",
        0x03A7: "X",
        0x03B9: "i",
        0x03BD: "v",
    }
)
# A "word" containing both a Latin letter and a Cyrillic (U+0400..U+04FF) or
# Greek (U+0370..U+03FF) letter.
_MIXED_SCRIPT_RE = re.compile("\\b(?=\\w*[A-Za-z])(?=\\w*[\u0400-\u04ff\u0370-\u03ff])\\w+\\b")
_TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")  # Unicode "tag" characters


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


def normalize(text: str) -> str:
    """Fold away the standard evasion tricks before any rule sees the text.

    NFKC (fullwidth, ligatures) -> confusable letters -> drop zero-width, bidi
    and Unicode tag characters. Applied to decoded base64 as well, since
    ``--evolve`` found payloads that combined both.
    """
    out = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)
    out = "".join(ch for ch in out if ch not in _HIDDEN_CHARS)
    return _TAG_CHARS_RE.sub("", out)


def _decode_blobs(text: str, *, limit: int = 8) -> list[str]:
    """Base64 substrings that decode to mostly-printable text, normalized."""
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            plain = normalize(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in plain)
        if plain and printable / len(plain) > 0.95 and any(ch.isalpha() for ch in plain):
            out.append(plain)
            if len(out) >= limit:
                break
    return out


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
        bidi = sum(1 for ch in text if ch in _BIDI_OVERRIDES)
        if hidden:
            matched.append("CLS-H-000")
            details["CLS-H-000"] = f"{hidden} hidden/zero-width/bidi/tag character(s)"
            # One stray zero-width char is often a copy-paste artifact; three or
            # more is deliberate. A single bidi *override* is always deliberate.
            deliberate = hidden >= 3 or bidi > 0
            weights.append(self.hidden_char_weight if deliberate else self.hidden_char_weight / 2)

        mixed = _MIXED_SCRIPT_RE.findall(text)
        if len(mixed) >= 2:
            matched.append("CLS-H-017")
            details["CLS-H-017"] = (
                f"mixed-script words (Latin + Cyrillic/Greek): {', '.join(mixed[:4])!r}"
            )
            weights.append(0.5)

        # Normalize so homoglyph / fullwidth tricks don't dodge the regexes.
        normalized = normalize(text)

        # Base64 blobs are decoded and appended so the rules see the plaintext.
        # Found by --evolve: an encoded instruction with no "decode this" hint
        # scored only the blob rule. Rules matching inside decoded text are
        # reported with a "(decoded)" marker.
        decoded = _decode_blobs(normalized)
        if decoded:
            matched.append("CLS-H-018")
            details["CLS-H-018"] = f"{len(decoded)} base64 blob(s) decoded to readable text"
            weights.append(0.3)

        for rule in self.rules:
            m = rule.pattern.search(normalized)
            where = ""
            if not m and decoded:
                m = rule.pattern.search("\n".join(decoded))
                where = " (decoded)"
            if m:
                matched.append(rule.rule_id)
                snippet = m.group(0).replace("\n", " ")
                details[rule.rule_id] = f"{rule.label}{where}: {snippet[: self._max_evidence]!r}"
                weights.append(rule.weight)

        # Saturating combination: 1 - Π(1 - w) keeps the score in [0, 1] and
        # rewards multiple independent signals without exceeding 1.
        survival = 1.0
        for w in weights:
            survival *= 1.0 - min(w, 0.99)
        return ClassificationResult(
            score=round(1.0 - survival, 4), matched=matched, details=details
        )
