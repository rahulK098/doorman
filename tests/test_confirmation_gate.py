from doorman.layers.confirmation_gate import ConfirmationGate
from doorman.types import Decision, ToolCall, Verdict


def test_reversible_tool_allowed():
    v = ConfirmationGate(["send_email"]).check(ToolCall("read_document"))
    assert v.decision is Decision.ALLOW and v.rule_id == "GATE-000"


def test_irreversible_tool_needs_confirmation_without_approver():
    v = ConfirmationGate(["send_email"]).check(ToolCall("send_email"))
    assert v.decision is Decision.CONFIRM and v.rule_id == "GATE-001"
    assert "human approval required" in v.rationale


def test_approver_approves():
    seen: list[tuple[ToolCall, Verdict]] = []

    def approve(call: ToolCall, why: Verdict) -> bool:
        seen.append((call, why))
        return True

    v = ConfirmationGate(["send_email"], approver=approve).check(ToolCall("send_email"))
    assert v.decision is Decision.ALLOW and v.rule_id == "GATE-001-APPROVED"
    assert seen[0][1].decision is Decision.CONFIRM


def test_approver_declines():
    v = ConfirmationGate(["send_email"], approver=lambda c, w: False).check(ToolCall("send_email"))
    assert v.decision is Decision.BLOCK and v.rule_id == "GATE-001-DECLINED"


def test_elevated_risk_escalates_reversible_tools():
    gate = ConfirmationGate(["send_email"], escalate_at=0.5)
    low = gate.check(ToolCall("write_note"), risk=0.2)
    high = gate.check(ToolCall("write_note"), risk=0.6)
    assert low.decision is Decision.ALLOW
    assert high.decision is Decision.CONFIRM and high.rule_id == "GATE-002"
    assert "60%" in high.rationale


def test_exempt_tools_ignore_risk():
    gate = ConfirmationGate(["send_email"], exempt_tools=["read_document"])
    assert gate.check(ToolCall("read_document"), risk=9.0).decision is Decision.ALLOW


def test_escalation_can_be_disabled():
    gate = ConfirmationGate(["send_email"], escalate_at=None)
    assert gate.check(ToolCall("write_note"), risk=9.0).decision is Decision.ALLOW
