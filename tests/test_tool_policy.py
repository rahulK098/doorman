import pytest

from doorman.layers.tool_policy import ToolPolicy
from doorman.types import Decision, ToolCall


@pytest.fixture
def policy() -> ToolPolicy:
    return ToolPolicy(
        {"scoring": ["read_document", "write_ats_score"], "outreach": ["send_email", "*"]},
        always_safe=["read_document"],
    )


def test_allowed_in_context(policy):
    v = policy.check(ToolCall("write_ats_score"), context="scoring")
    assert v.decision is Decision.ALLOW and v.rule_id == "POL-000"


def test_denied_outside_context(policy):
    v = policy.check("send_email", context="scoring")
    assert v.decision is Decision.BLOCK and v.rule_id == "POL-001"
    assert "send_email" in v.rationale and "scoring" in v.rationale
    assert "read_document" in v.rationale  # lists what *is* allowed


def test_wildcard_context(policy):
    assert policy.check("anything", context="outreach").decision is Decision.ALLOW


def test_default_context_is_first(policy):
    assert policy.default_context == "scoring"
    assert policy.check("send_email").decision is Decision.BLOCK


def test_unknown_context_blocks(policy):
    v = policy.check("read_document", context="nope")
    assert v.decision is Decision.BLOCK and v.rule_id == "POL-003"


def test_risk_escalates_to_confirm(policy):
    v = policy.check("write_ats_score", context="scoring", risk=0.7)
    assert v.decision is Decision.CONFIRM and v.rule_id == "POL-004"
    assert "70%" in v.rationale


def test_risk_exhausted_blocks_but_always_safe_survives(policy):
    assert policy.check("write_ats_score", context="scoring", risk=1.2).rule_id == "POL-002"
    assert policy.check("read_document", context="scoring", risk=1.2).decision is Decision.ALLOW


def test_risk_awareness_can_be_disabled():
    p = ToolPolicy({"c": ["t"]}, escalate_at=None, deny_at=None)
    assert p.check("t", risk=5.0).decision is Decision.ALLOW


def test_validation():
    with pytest.raises(ValueError):
        ToolPolicy({})
    with pytest.raises(ValueError):
        ToolPolicy({"a": []}, default_context="b")
