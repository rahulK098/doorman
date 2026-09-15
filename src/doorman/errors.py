"""Exceptions raised at the Guard boundary.

Layers return ``Verdict`` values and never raise for policy reasons; ``Guard``
converts blocking verdicts into these exceptions so ``protect()``-wrapped code
has a normal control-flow story.
"""

from __future__ import annotations

from doorman.types import Verdict


class DoormanError(Exception):
    """Base class for all Doorman exceptions."""


class ActionBlocked(DoormanError):
    """A proposed tool call was blocked by one or more layers."""

    def __init__(self, verdict: Verdict, all_verdicts: list[Verdict] | None = None) -> None:
        self.verdict = verdict
        self.all_verdicts = all_verdicts or [verdict]
        super().__init__(f"[{verdict.layer}/{verdict.rule_id}] {verdict.rationale}")


class ConfirmationRequired(DoormanError):
    """A proposed tool call needs human approval and no approver granted it."""

    def __init__(self, verdict: Verdict, all_verdicts: list[Verdict] | None = None) -> None:
        self.verdict = verdict
        self.all_verdicts = all_verdicts or [verdict]
        super().__init__(f"[{verdict.layer}/{verdict.rule_id}] {verdict.rationale}")


class ContentQuarantined(DoormanError):
    """Ingested content was blocked by the classifier and never isolated."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(f"[{verdict.layer}/{verdict.rule_id}] {verdict.rationale}")


class PrivilegeViolation(DoormanError):
    """Untrusted content was about to reach a privileged component."""


class MissingExtra(DoormanError):
    """An optional dependency is required for the requested feature."""

    def __init__(self, extra: str, feature: str) -> None:
        self.extra = extra
        super().__init__(f"{feature} requires the '{extra}' extra: pip install 'doorman[{extra}]'")
