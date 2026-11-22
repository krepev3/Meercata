from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from meercata.monitor_delivery_qualifier import main, qualify


SOURCE_ROOT = Path(__file__).parents[1]


def test_monitor_delivery_qualification_passes_all_durable_delivery_checks() -> None:
    report = qualify()

    assert report["status"] == "monitor-delivery-qualified"
    assert report["project_version"] == "2.0.0.dev24"
    assert len(report["checks"]) == 8
    assert all(check["status"] == "passed" for check in report["checks"])
    assert report["checks"][2]["details"] == {
        "retried": 1,
        "before_due_attempted": 0,
    }
    assert report["checks"][5]["details"]["transport_calls"] == 0


def test_monitor_delivery_qualification_conforms_to_schema_and_evidence() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            SOURCE_ROOT
            / "schemas/monitor-delivery-qualification-v1.schema.json"
        ).read_text()
    )

    report = qualify()
    jsonschema.validate(report, schema)
    recorded = json.loads(
        (SOURCE_ROOT / "qualification-evidence/monitor-delivery-dev23.json").read_text()
    )
    jsonschema.validate(recorded, schema)
    assert recorded | {"project_version": report["project_version"]} == report


def test_monitor_delivery_qualification_cli_emits_one_report() -> None:
    stdout = io.StringIO()

    assert main([], stdout=stdout) == 0
    assert json.loads(stdout.getvalue())["status"] == "monitor-delivery-qualified"
