"""Classifier: score ingested text for injection likelihood.

Thin layer over ``doorman.scoring``; turns a score into a ``Verdict``.
See docs/adr/0004-pluggable-classifier-with-heuristic-default.md.
"""

from __future__ import annotations

import importlib

from doorman.errors import MissingExtra
from doorman.scoring import ClassificationResult, ClassifierBackend, HeuristicBackend
from doorman.types import Decision, Source, Verdict

LAYER = "classifier"

_NAMED_BACKENDS: dict[str, tuple[str, str]] = {
    # name -> (extra, "module:Class"); resolved lazily so core stays dependency-free
    "prompt-guard-2": ("prompt-guard", "doorman.backends.prompt_guard:PromptGuardBackend"),
}


def _load_named(name: str) -> ClassifierBackend:
    if name not in _NAMED_BACKENDS:
        raise ValueError(
            f"unknown classifier model {name!r}; known: {sorted(_NAMED_BACKENDS)} "
            "or pass backend=<your ClassifierBackend>"
        )
    extra, path = _NAMED_BACKENDS[name]
    module_name, _, attr = path.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        raise MissingExtra(extra, f"Classifier(model={name!r})") from e
    backend: ClassifierBackend = getattr(module, attr)()
    return backend


class Classifier:
    """Scores text for injection likelihood and turns the score into a ``Verdict``.

    ``threshold`` is the score at or above which text is blocked;
    ``warn_threshold`` produces a ``WARN`` verdict below that.
    """

    def __init__(
        self,
        backend: ClassifierBackend | None = None,
        *,
        model: str | None = None,
        threshold: float = 0.5,
        warn_threshold: float = 0.25,
    ) -> None:
        if backend is not None and model is not None:
            raise ValueError("pass either backend= or model=, not both")
        if backend is None:
            backend = _load_named(model) if model else HeuristicBackend()
        self.backend = backend
        self.threshold = threshold
        self.warn_threshold = warn_threshold

    def classify(self, text: str) -> ClassificationResult:
        return self.backend.score(text)

    def check(self, text: str, *, origin: str | None = None) -> Verdict:
        result = self.classify(text)
        where = f" in {origin}" if origin else ""
        evidence = "; ".join(result.details.get(r, r) for r in result.matched[:3])
        meta = {
            "backend": self.backend.name,
            "matched": result.matched,
            "threshold": self.threshold,
            "origin": origin,
        }
        if result.score >= self.threshold:
            return Verdict(
                decision=Decision.BLOCK,
                layer=LAYER,
                rule_id="CLS-001",
                rationale=(
                    f"Injection likelihood {result.score:.2f} >= {self.threshold:.2f}{where}. "
                    f"Signals: {evidence}"
                ),
                score=result.score,
                provenance=Source.UNTRUSTED,
                metadata=meta,
            )
        if result.score >= self.warn_threshold:
            return Verdict(
                decision=Decision.WARN,
                layer=LAYER,
                rule_id="CLS-002",
                rationale=(
                    f"Injection likelihood {result.score:.2f} is suspicious but under "
                    f"{self.threshold:.2f}{where}. Signals: {evidence}"
                ),
                score=result.score,
                provenance=Source.UNTRUSTED,
                metadata=meta,
            )
        return Verdict(
            decision=Decision.ALLOW,
            layer=LAYER,
            rule_id="CLS-000",
            rationale=(
                f"No injection patterns of concern{where} "
                f"(score {result.score:.2f} < {self.warn_threshold:.2f})."
            ),
            score=result.score,
            provenance=Source.UNTRUSTED,
            metadata=meta,
        )
