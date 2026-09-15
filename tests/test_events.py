import json
import logging

from doorman.events import EventLog
from doorman.types import Decision, Verdict


def _v(d: Decision = Decision.BLOCK) -> Verdict:
    return Verdict(decision=d, layer="x", rule_id="X-1", rationale="because reasons")


def test_emit_and_query():
    log = EventLog(mirror_to_logging=False)
    log.emit(_v(Decision.ALLOW), "s1")
    log.emit(_v(Decision.BLOCK), "s2", tool="send_email")
    assert len(log) == 2
    assert [e.session_id for e in log.blocks()] == ["s2"]
    assert log.for_session("s2")[0].context == {"tool": "send_email"}


def test_jsonl_round_trip():
    log = EventLog(mirror_to_logging=False)
    log.emit(_v(), "s1")
    rows = [json.loads(line) for line in log.to_jsonl().splitlines()]
    assert rows[0]["rule_id"] == "X-1" and rows[0]["rationale"] == "because reasons"
    assert rows[0]["session_id"] == "s1" and "ts" in rows[0]


def test_mirrors_to_stdlib_logging(caplog):
    with caplog.at_level(logging.DEBUG, logger="doorman"):
        EventLog().emit(_v(Decision.BLOCK), "s1")
    rec = caplog.records[-1]
    assert rec.levelno == logging.ERROR
    assert "BLOCK x/X-1 session=s1: because reasons" in rec.getMessage()


def test_max_events_is_a_ring_buffer():
    log = EventLog(mirror_to_logging=False, max_events=2)
    for i in range(5):
        log.emit(_v(), f"s{i}")
    assert [e.session_id for e in log] == ["s3", "s4"]
