from __future__ import annotations

import json
from pathlib import Path

import pytest

from meercata.errors import QualificationError
from meercata.nfqueue_load_qualifier import (
    LISTENER_LOSS_SUCCESS_FLOOR,
    PAYLOAD_BYTES,
    _listener_loss_details,
    _mixed_details,
    _nested_counter,
    _normal_queue_details,
    _percentile,
    _read_cgroup_integer,
    _read_complete_json_lines,
    _require_mixed_correctness,
    _resource_summary,
)

ROOT = Path(__file__).parents[1]


def mixed_result() -> dict[str, object]:
    return {
        "accept_ok": 3,
        "accept_failed": 0,
        "accept_corrupt": 0,
        "bytes": 3 * PAYLOAD_BYTES,
        "drop_blocked": 2,
        "drop_unexpected": 0,
        "latencies_ms": [10.0, 20.0, 30.0],
    }


def test_mixed_load_requires_exact_accept_drop_oracles() -> None:
    _require_mixed_correctness(mixed_result())

    invalid = mixed_result()
    invalid["drop_unexpected"] = 1
    with pytest.raises(QualificationError, match="correctness"):
        _require_mixed_correctness(invalid)


def test_mixed_details_use_measured_duration_and_nearest_rank_p95() -> None:
    details = _mixed_details(mixed_result(), 2.5)

    assert details["duration_seconds"] == 2.5
    assert details["latency_median_ms"] == 20.0
    assert details["latency_p95_ms"] == 30.0
    assert details["goodput_mbps"] == round(3 * PAYLOAD_BYTES * 8 / 2.5 / 1_000_000, 3)


def test_percentile_rejects_empty_or_out_of_range_input() -> None:
    with pytest.raises(QualificationError, match="percentile"):
        _percentile([], 0.95)
    with pytest.raises(QualificationError, match="percentile"):
        _percentile([1.0], 1.1)


def test_resource_summary_computes_bounded_rss_cpu_and_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("meercata.nfqueue_load_qualifier.os.sysconf", lambda _name: 100)
    value = _resource_summary(
        [
            {"rss_bytes": 10, "cpu_ticks": 100, "threads": 4},
            {"rss_bytes": 20, "cpu_ticks": 250, "threads": 6},
        ],
        3.0,
    )

    assert value["rss_min_bytes"] == 10
    assert value["rss_max_bytes"] == 20
    assert value["threads_max"] == 6
    assert value["cpu_percent_one_core"] == 50.0


def test_normal_queue_integrity_rejects_any_transport_drop() -> None:
    initial = {
        "queue_total": 0,
        "queue_dropped": 0,
        "user_dropped": 0,
    }
    counters = {
        "in": {"packets": 1, "bytes": 2},
        "out": {"packets": 3, "bytes": 4},
    }

    details = _normal_queue_details(initial, [initial], counters, counters)
    assert details["queue_dropped_delta"] == 0

    dropped = dict(initial)
    dropped["queue_dropped"] = 1
    with pytest.raises(QualificationError, match="transport drop"):
        _normal_queue_details(initial, [dropped], counters, counters)


def test_listener_loss_requires_floor_and_zero_corruption() -> None:
    value = {
        "accept_ok": 9,
        "accept_failed": 1,
        "accept_corrupt": 0,
        "bytes": 9 * PAYLOAD_BYTES,
    }
    details = _listener_loss_details(value, {"bytes": PAYLOAD_BYTES})
    assert details["success_ratio"] == LISTENER_LOSS_SUCCESS_FLOOR

    value["accept_failed"] = 2
    with pytest.raises(QualificationError, match="disruption floor"):
        _listener_loss_details(value, {"bytes": PAYLOAD_BYTES})


def test_eve_reader_ignores_incomplete_trailer_but_rejects_complete_invalid_json(
    tmp_path: Path,
) -> None:
    path = tmp_path / "eve.json"
    event = {"event_type": "stats", "stats": {"ips": {"accepted": 3}}}
    path.write_text(json.dumps(event) + "\n{\"event_type\":")
    assert _read_complete_json_lines(path) == [event]

    path.write_text(json.dumps(event) + "\nnot-json\n")
    with pytest.raises(QualificationError, match="invalid JSON"):
        _read_complete_json_lines(path)


def test_nested_counter_defaults_missing_to_zero_and_rejects_wrong_type() -> None:
    assert _nested_counter({}, "ips", "accepted") == 0
    assert _nested_counter({"ips": {"accepted": 5}}, "ips", "accepted") == 5
    with pytest.raises(QualificationError, match="counter"):
        _nested_counter({"ips": {"accepted": True}}, "ips", "accepted")


def test_cgroup_integer_requires_positive_bounded_value(tmp_path: Path) -> None:
    path = tmp_path / "memory.max"
    path.write_text("1073741824\n")
    assert _read_cgroup_integer(path, "memory") == 1073741824

    path.write_text("max\n")
    with pytest.raises(QualificationError, match="memory"):
        _read_cgroup_integer(path, "memory")


def test_nfqueue_load_schema_and_recorded_evidence_are_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/nfqueue-load-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (ROOT / "qualification-evidence/nfqueue-load-dev20.json").read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(evidence, schema)
    assert evidence["project_version"] == "2.0.0.dev20"
    assert len({item["check_id"] for item in evidence["checks"]}) == 10
