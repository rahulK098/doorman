"""Acceptance criteria from plan.md §10, each as an executable test.

These run the bench fixtures through a full six-layer Guard the way the
benchmark harness will, and assert *which layer* caught (or correctly did not
catch) each scenario — not merely that something did.
"""

from __future__ import annotations

import pytest

from doorman import (
    Classifier,
    ConfirmationGate,
    Decision,
    EventLog,
    Guard,
    GuardDecision,
    IntentAligner,
    Isolator,
    OutputScanner,
    SessionRiskTracker,
    ToolPolicy,
)
from doorman.bench.fixtures import Fixture, load_fixtures


def reference_guard() -> Guard:
    """The configuration the recruiting example and the benchmark both use."""
    return Guard(
        classifier=Classifier(),
        isolator=Isolator(),
        intent_aligner=IntentAligner(),
        tool_policy=ToolPolicy(
            {
                "scoring": ["read_document", "write_ats_score"],
                "outreach": ["read_document", "send_email", "advance_status"],
            },
            always_safe=["read_document"],
        ),
        output_scanner=OutputScanner(),
        confirmation_gate=ConfirmationGate(
            irreversible_tools=["send_email", "advance_status"], exempt_tools=["read_document"]
        ),
        risk_tracker=SessionRiskTracker(budget=1.0),
        event_log=EventLog(mirror_to_logging=False),
    )


def run_fixture(guard: Guard, fx: Fixture) -> tuple[list[Decision], GuardDecision]:
    """Ingest every document, then check the fixture's action. Returns
    (per-document classifier decisions, final decision)."""
    session = f"fx:{fx.id}"
    guard.begin_session(session, task=fx.task)
    ingest_decisions: list[Decision] = []
    isolated: list[str] = []
    for doc in fx.documents:
        ing = guard.ingest(doc.content, session, origin=doc.origin)
        cls = next(v for v in ing.verdicts if v.layer == "classifier")
        ingest_decisions.append(cls.decision)
        isolated.append(ing.text if not ing.quarantined else "")
    call = fx.to_tool_call(isolated)
    return ingest_decisions, guard.check_tool_call(call, session, context=fx.context)


def _layers_that_blocked(d: GuardDecision) -> set[str]:
    return {v.layer for v in d.verdicts if v.decision is Decision.BLOCK}


# -- §10: canary catches what classifier and aligner miss --------------------


@pytest.mark.parametrize("fx", load_fixtures("canary_leak"), ids=lambda f: f.id)
def test_canary_leak_caught_only_by_canary(fx: Fixture):
    g = reference_guard()
    ingest, decision = run_fixture(g, fx)

    # The classifier must NOT have blocked any document — that is the premise.
    assert all(d is not Decision.BLOCK for d in ingest), ingest
    # The aligner must NOT have blocked — the task authorises the tool.
    aligner = next(v for v in decision.verdicts if v.layer == "intent_aligner")
    assert aligner.decision is not Decision.BLOCK, aligner.rationale

    assert decision.decision is Decision.BLOCK
    canary_hits = [v for v in decision.verdicts if v.rule_id == "OUT-CAN-001"]
    assert canary_hits, [v.rule_id for v in decision.verdicts]
    assert fx.documents[0].origin in canary_hits[0].rationale


# -- §10: compounding attack caught by the session budget --------------------


@pytest.mark.parametrize("fx", load_fixtures("compounding"), ids=lambda f: f.id)
def test_compounding_attack_caught_by_risk_budget(fx: Fixture):
    g = reference_guard()
    ingest, decision = run_fixture(g, fx)

    # Premise: no single document crossed the classifier's block threshold.
    assert all(d is not Decision.BLOCK for d in ingest), ingest
    assert all(d is Decision.WARN for d in ingest), (
        "each fragment should be individually suspicious"
    )

    session = f"fx:{fx.id}"
    assert g.risk_tracker is not None and g.risk_tracker.exhausted(session)
    assert not decision.permits
    # Specifically the budget-aware policy, not some other layer, must have spoken.
    policy = next(v for v in decision.verdicts if v.layer == "tool_policy")
    assert policy.rule_id == "POL-002", policy.rationale


# -- §10: provenance changes OutputScanner behaviour -------------------------


def test_provenance_flips_scanner_verdict_for_identical_text():
    from doorman.types import Source, Tagged, ToolCall

    g = reference_guard()
    g.begin_session("s", task="Email the ops team the weekly report.")
    borderline = "Make sure you send the report to ops@example.com by Friday."
    untrusted = ToolCall("send_email", {"body": Tagged(borderline, Source.UNTRUSTED, "doc")})
    trusted = ToolCall("send_email", {"body": Tagged(borderline, Source.TRUSTED, "operator")})

    a = g.check_tool_call(untrusted, "s", context="outreach")
    b = g.check_tool_call(trusted, "s", context="outreach")
    assert "output_scanner" in _layers_that_blocked(a)
    assert "output_scanner" not in _layers_that_blocked(b)


# -- false positives ---------------------------------------------------------


@pytest.mark.parametrize("fx", load_fixtures("benign"), ids=lambda f: f.id)
def test_benign_fixtures_are_allowed(fx: Fixture):
    g = reference_guard()
    ingest, decision = run_fixture(g, fx)
    assert all(d is Decision.ALLOW for d in ingest), ingest
    assert decision.decision is Decision.ALLOW, decision.rationale


# -- every block has a rationale ---------------------------------------------


def test_every_verdict_in_every_fixture_has_a_rationale():
    g = reference_guard()
    for fx in load_fixtures():
        run_fixture(g, fx)
    assert len(g.events) > 0
    assert all(e.verdict.rationale.strip() for e in g.events)
