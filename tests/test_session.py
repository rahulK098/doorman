import pytest

from doorman.session import SessionRiskTracker
from doorman.types import Decision


def test_accumulates_across_events():
    t = SessionRiskTracker(budget=1.0)
    assert t.record("s", 0.3, "doc1").decision is Decision.ALLOW
    assert t.record("s", 0.3, "doc2").decision is Decision.WARN
    v = t.record("s", 0.45, "doc3")
    assert v.decision is Decision.BLOCK and v.rule_id == "RISK-001"
    assert "3 event(s)" in v.rationale and "doc3" in v.rationale
    assert t.exhausted("s") and t.risk("s") == pytest.approx(1.05)


def test_sessions_are_independent():
    t = SessionRiskTracker(budget=1.0)
    t.record("a", 0.9)
    assert t.risk("b") == 0.0


def test_decay():
    t = SessionRiskTracker(budget=1.0, decay=0.1)
    t.record("s", 0.5)
    t.record("s", 0.0)
    assert t.risk("s") == pytest.approx(0.4)


def test_negative_amounts_ignored():
    t = SessionRiskTracker(budget=1.0)
    t.record("s", -5.0)
    assert t.risk("s") == 0.0


def test_state_snapshot_and_reset():
    t = SessionRiskTracker(budget=2.0)
    t.record("s", 0.5, "x")
    snap = t.state("s")
    assert snap.total == 0.5 and snap.contributions == [("x", 0.5)]
    t.reset("s")
    assert t.risk("s") == 0.0


def test_budget_must_be_positive():
    with pytest.raises(ValueError):
        SessionRiskTracker(budget=0)
