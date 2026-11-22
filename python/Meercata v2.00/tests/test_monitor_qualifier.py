from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from meercata.monitor_qualifier import main, qualify


SOURCE_ROOT = Path(__file__).parents[1]


def test_monitor_qualification_passes_all_transition_and_integrity_checks() -> None:
    report = qualify()

    assert report["status"] == "monitoring-qualified"
    assert report["project_version"] == "2.0.0.dev24"
    assert len(report["checks"]) == 7
    assert all(check["status"] == "passed" for check in report["checks"])
    assert report["checks"][1]["details"]["transition_emitted"] is False
    assert report["checks"][4]["details"] == {
        "sequence": 3,
        "transition_emitted": False,
        "events": 3,
    }


def test_monitor_qualification_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (SOURCE_ROOT / "schemas/monitor-qualification-v1.schema.json").read_text()
    )

    jsonschema.validate(qualify(), schema)
    recorded = json.loads(
        (SOURCE_ROOT / "qualification-evidence/monitoring-dev22.json").read_text()
    )
    jsonschema.validate(recorded, schema)
    assert recorded | {"project_version": "2.0.0.dev24"} == qualify()


def test_monitor_qualification_cli_emits_one_report() -> None:
    stdout = io.StringIO()

    assert main([], stdout=stdout) == 0
    assert json.loads(stdout.getvalue())["status"] == "monitoring-qualified"
