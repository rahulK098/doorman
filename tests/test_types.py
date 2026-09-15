from doorman.types import (
    Decision,
    Source,
    Tagged,
    ToolCall,
    Verdict,
    most_severe,
    source_of,
    truncate,
    untag,
)


def test_untag_is_recursive():
    args = {
        "to": Tagged("a@b.c", Source.TRUSTED),
        "body": [Tagged("x", Source.UNTRUSTED), "plain"],
        "meta": {"k": Tagged(Tagged(1, Source.TRUSTED), Source.UNTRUSTED)},
    }
    assert untag(args) == {"to": "a@b.c", "body": ["x", "plain"], "meta": {"k": 1}}


def test_tool_call_plain_args():
    call = ToolCall("send_email", {"to": Tagged("a@b.c", Source.TRUSTED)})
    assert call.plain_args == {"to": "a@b.c"}
    assert call.args["to"].source is Source.TRUSTED  # original untouched


def test_source_of():
    assert source_of("x") is Source.UNKNOWN
    assert source_of(Tagged("x", Source.UNTRUSTED)) is Source.UNTRUSTED


def test_tagged_str_gives_raw_value():
    assert f"{Tagged('hello', Source.UNTRUSTED)}" == "hello"


def test_decision_permits():
    assert Decision.ALLOW.permits and Decision.WARN.permits
    assert not Decision.CONFIRM.permits and not Decision.BLOCK.permits


def _v(d: Decision) -> Verdict:
    return Verdict(decision=d, layer="t", rule_id="T-0", rationale="r")


def test_most_severe_picks_block_over_others():
    assert most_severe([_v(Decision.ALLOW), _v(Decision.BLOCK), _v(Decision.CONFIRM)]).decision is (
        Decision.BLOCK
    )
    assert most_severe([_v(Decision.WARN), _v(Decision.CONFIRM)]).decision is Decision.CONFIRM
    assert most_severe([]) is None


def test_verdict_to_dict_serializes_enums():
    d = Verdict(Decision.BLOCK, "l", "R-1", "why", score=0.9, provenance=Source.UNTRUSTED).to_dict()
    assert d["decision"] == "block" and d["provenance"] == "untrusted" and d["score"] == 0.9


def test_truncate():
    assert truncate("a" * 200, 10).endswith("…") and len(truncate("a" * 200, 10)) == 10
    assert truncate("line1\nline2") == "line1 line2"
