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


def _fixture_data(fixture_id: str) -> dict:
    return {
        "id": fixture_id,
        "family": "direct",
        "task": "t",
        "documents": [{"origin": "o", "content": "c"}],
        "attack": True,
        "malicious_action": {"tool": "x", "args": {}},
    }


@pytest.mark.parametrize(
    "bad_id",
    [
        "../../evil",
        "../evil",
        "/etc/cron.d/evil",
        "C:\\Windows\\Temp\\evil",
        "sub/dir/evil",
        "sub\\dir\\evil",
        ".hidden",
        "-leading-dash",
        "with space",
        "trailing/",
        "..",
        "",
        "x" * 200,
    ],
)
def test_unsafe_fixture_ids_are_rejected_at_parse_time(bad_id):
    """A fixture id becomes a filename, so it must be one safe path segment.

    Fixture corpora are meant to be shared, which makes every field in them
    untrusted input.
    """
    with pytest.raises(ValueError, match="unsafe fixture id"):
        parse_fixture(_fixture_data(bad_id))


@pytest.mark.parametrize("bad_type", [None, 42, ["a"], {"a": 1}])
def test_non_string_fixture_ids_are_rejected(bad_type):
    with pytest.raises(ValueError, match="unsafe fixture id"):
        parse_fixture(_fixture_data(bad_type))


@pytest.mark.parametrize(
    "good_id",
    ["gen-direct-001", "compounding-001--paraphrase-r1-0", "a", "A_b.c-d", "x" * 128],
)
def test_safe_fixture_ids_are_accepted(good_id):
    assert parse_fixture(_fixture_data(good_id)).id == good_id


def test_write_fixture_refuses_to_escape_its_directory(tmp_path):
    """Defense in depth: Fixtures built in code bypass parse_fixture entirely."""
    from dataclasses import replace

    from doorman.bench.fixtures import write_fixture

    fx = parse_fixture(_fixture_data("ok"))
    # Build the malicious object the way the evolve engine builds mutants,
    # sidestepping the parse-time check.
    escaped = replace(fx, id="../escaped")
    with pytest.raises(ValueError, match="unsafe fixture id"):
        write_fixture(escaped, tmp_path / "out")
    assert not (tmp_path / "escaped.json").exists()

    absolute = replace(fx, id=str(tmp_path / "absolute"))
    with pytest.raises(ValueError, match="unsafe fixture id"):
        write_fixture(absolute, tmp_path / "out")
    assert not (tmp_path / "absolute.json").exists()

    # The safe case still works.
    written = write_fixture(fx, tmp_path / "out")
    assert written == tmp_path / "out" / "ok.json"


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
