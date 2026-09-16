import json

import pytest

from doorman.bench.fixtures import FAMILIES, Fixture, load_fixtures, parse_fixture
from doorman.types import Source, Tagged


def test_all_fixture_files_parse_and_have_unique_ids():
    fixtures = load_fixtures()
    assert fixtures, "no fixtures found"
    ids = [f.id for f in fixtures]
    assert len(ids) == len(set(ids))
    for f in fixtures:
        assert f.family in FAMILIES
        assert f.path is not None and f.path.parent.name == f.family
        assert f.id == f.path.stem


def test_placeholder_resolution():
    fx = parse_fixture(
        {
            "id": "x",
            "family": "direct",
            "task": "t",
            "documents": [{"origin": "o0", "content": "raw0"}, {"origin": "o1", "content": "raw1"}],
            "attack": True,
            "malicious_action": {
                "tool": "send_email",
                "args": {
                    "a": "$doc:1",
                    "b": "$raw:0",
                    "c": "$untrusted:hello",
                    "d": "plain",
                    "e": ["$doc:0"],
                },
            },
        }
    )
    call = fx.to_tool_call(["ISO0", "ISO1"])
    assert call.args["a"] == Tagged("ISO1", Source.UNTRUSTED, "o1")
    assert call.args["b"] == Tagged("raw0", Source.UNTRUSTED, "o0")
    assert call.args["c"] == Tagged("hello", Source.UNTRUSTED, "document")
    assert call.args["d"] == "plain"
    assert call.args["e"] == [Tagged("ISO0", Source.UNTRUSTED, "o0")]


def test_isolated_text_count_must_match():
    fx = load_fixtures("benign")[0]
    with pytest.raises(ValueError):
        fx.to_tool_call([])


def test_unknown_family_rejected():
    with pytest.raises(ValueError):
        parse_fixture({"id": "x", "family": "nope", "task": "t", "documents": [], "attack": False})


def test_missing_action_rejected():
    with pytest.raises(ValueError):
        parse_fixture({"id": "x", "family": "direct", "task": "t", "documents": [], "attack": True})


def test_fixture_is_json_serialisable_roundtrip(tmp_path):
    fx = load_fixtures("canary_leak")[0]
    assert fx.path is not None
    data = json.loads(fx.path.read_text(encoding="utf-8"))
    assert isinstance(parse_fixture(data), Fixture)
