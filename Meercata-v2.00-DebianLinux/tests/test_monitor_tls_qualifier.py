from __future__ import annotations

import copy
import io
import json
import threading
from pathlib import Path

import pytest

from meercata.errors import MonitorDeliveryError
from meercata import monitor_tls_qualifier as qualifier

ROOT = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def tls_report() -> dict:
    # This is a real loopback TLS test, with fresh disposable keys and state.
    return qualifier.qualify()


def test_real_tls_delivery_and_health_gate_matches_recorded_evidence(tls_report) -> None:
    import jsonschema

    schema = json.loads((ROOT / "schemas/monitor-tls-qualification-v1.schema.json").read_text())
    recorded = json.loads((ROOT / "qualification-evidence/monitor-tls-dev24.json").read_text())
    jsonschema.validate(tls_report, schema)
    jsonschema.validate(recorded, schema)
    assert tls_report == recorded
    serialized = json.dumps(tls_report)
    assert qualifier.TOKEN_CURRENT not in serialized
    assert qualifier.TOKEN_RETIRED not in serialized
    assert not any(t.name == "meercata-dev24-tls-collector" for t in threading.enumerate())


@pytest.mark.parametrize("mutation", ["duplicate", "failed_oracle", "omitted"])
def test_tls_evidence_schema_rejects_incomplete_or_unproven_gates(tls_report, mutation) -> None:
    import jsonschema

    schema = json.loads((ROOT / "schemas/monitor-tls-qualification-v1.schema.json").read_text())
    damaged = copy.deepcopy(tls_report)
    if mutation == "duplicate":
        damaged["checks"][1] = damaged["checks"][0]
    elif mutation == "failed_oracle":
        damaged["checks"][7]["details"]["old_ca_blocked_before_http"] = False
    else:
        damaged["checks"].pop()
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(damaged, schema)


def test_tls_collector_is_closed_when_delivery_raises(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise MonitorDeliveryError("injected local delivery failure")

    monkeypatch.setattr(qualifier.HttpsDeliveryTransport, "send", fail)
    stdout, stderr = io.StringIO(), io.StringIO()
    assert qualifier.main([], stdout=stdout, stderr=stderr) == 3
    assert stdout.getvalue() == ""
    assert "injected local delivery failure" in stderr.getvalue()
    assert not any(t.name == "meercata-dev24-tls-collector" for t in threading.enumerate())
