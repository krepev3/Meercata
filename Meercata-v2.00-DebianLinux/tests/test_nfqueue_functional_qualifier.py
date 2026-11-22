from __future__ import annotations

import json
from pathlib import Path

import pytest

from meercata.errors import QualificationError
from meercata.nfqueue_functional_qualifier import (
    _effective_capabilities,
    _queue_counters,
    _read_listeners,
    _wait_for_drop_alert,
)

ROOT = Path(__file__).parents[1]


def test_effective_capabilities_requires_net_admin_and_sys_admin_bits(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text(f"Name:\tqualifier\nCapEff:\t{(1 << 12) | (1 << 21):016x}\n")

    assert _effective_capabilities(status) == ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"]


def test_effective_capabilities_rejects_malformed_status(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text("CapEff:\tnot-hex\n")

    with pytest.raises(QualificationError, match="effective Linux capabilities"):
        _effective_capabilities(status)


def test_nfqueue_listener_status_is_parsed_without_host_specific_sequence(
    tmp_path: Path,
) -> None:
    status = tmp_path / "nfnetlink_queue"
    status.write_text("   42  1234 2 2 65535 3 4 99 1\n")

    assert _read_listeners(status) == [
        {
            "queue": 42,
            "port_id": 1234,
            "queue_total": 2,
            "copy_mode": 2,
            "copy_range": 65535,
            "queue_dropped": 3,
            "user_dropped": 4,
        }
    ]


def test_missing_nfqueue_listener_status_means_no_listener(tmp_path: Path) -> None:
    assert _read_listeners(tmp_path / "missing") == []


def test_owned_queue_counters_are_extracted_by_direction() -> None:
    value = {
        "nftables": [
            {
                "rule": {
                    "comment": "meercata-managed:v1:in",
                    "expr": [{"counter": {"packets": 7, "bytes": 700}}],
                }
            },
            {
                "rule": {
                    "comment": "meercata-managed:v1:out",
                    "expr": [{"counter": {"packets": 5, "bytes": 500}}],
                }
            },
        ]
    }

    assert _queue_counters(value) == {
        "in": {"packets": 7, "bytes": 700},
        "out": {"packets": 5, "bytes": 500},
    }


def test_drop_alert_requires_blocking_action(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps(
            {
                "event_type": "alert",
                "alert": {
                    "signature_id": 9_900_019,
                    "signature": "qualification",
                    "action": "allowed",
                },
            }
        )
        + "\n"
    )

    with pytest.raises(QualificationError, match="blocking action"):
        _wait_for_drop_alert(eve, 9_900_019, 0.1)


def test_drop_alert_ignores_only_an_incomplete_trailing_record(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps({"event_type": "stats"})
        + "\n"
        + json.dumps(
            {
                "event_type": "alert",
                "alert": {
                    "signature_id": 9_900_019,
                    "signature": "qualification",
                    "action": "blocked",
                },
            }
        )
        + "\n{\"event_type\":"
    )

    assert _wait_for_drop_alert(eve, 9_900_019, 0.1) == {
        "action": "blocked",
        "signature": "qualification",
    }


def test_nfqueue_functional_schema_is_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/nfqueue-functional-qualification-v1.schema.json").read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)


def test_recorded_nfqueue_functional_evidence_is_schema_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/nfqueue-functional-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (ROOT / "qualification-evidence/nfqueue-functional-dev19.json").read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["project_version"] == "2.0.0.dev19"
    assert {item["check_id"] for item in evidence["checks"]} == {
        "platform.namespace",
        "topology.routed",
        "suricata.nfq-capability",
        "policy.transaction-commit",
        "nfqueue.listener",
        "verdict.accept",
        "verdict.drop",
        "performance.bounded-sample",
        "fail-open.listener-loss",
    }
