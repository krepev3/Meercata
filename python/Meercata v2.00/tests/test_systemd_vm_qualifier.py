import io
import json
from pathlib import Path

import pytest

from meercata.errors import QualificationError
from meercata.systemd_vm_qualifier import (
    CLOUD_IMAGE_SHA512,
    _health_observed,
    _health_report,
    _parse_os_release,
    main,
)


ROOT = Path(__file__).parents[1]


def test_os_release_parser_handles_debian_quoted_values() -> None:
    assert _parse_os_release('ID=debian\nVERSION_ID="13"\n') == {
        "ID": "debian",
        "VERSION_ID": "13",
    }


def test_health_report_requires_every_check_to_be_healthy() -> None:
    report = {
        "schema_version": 1,
        "status": "healthy",
        "exit_code": 0,
        "mode": "ids",
        "checks": [{"id": "capture_mode", "status": "critical"}],
    }

    with pytest.raises(QualificationError, match="fully healthy"):
        _health_report(json.dumps(report))


def test_health_observation_requires_one_named_check() -> None:
    checks = [
        {
            "id": "suricata_socket",
            "status": "healthy",
            "observed": {"version": "8.0.6 RELEASE"},
        }
    ]

    assert _health_observed(checks, "suricata_socket", "version") == "8.0.6 RELEASE"
    with pytest.raises(QualificationError, match="inventory"):
        _health_observed(checks, "missing")


def test_cli_rejects_wrong_confirmation_before_host_mutation() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = main(
        ["--confirmation", "wrong", "--image-sha512", CLOUD_IMAGE_SHA512],
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 3
    assert stdout.getvalue() == ""
    assert "confirmation phrase" in stderr.getvalue()


def test_recorded_systemd_vm_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    evidence_path = ROOT / "qualification-evidence/systemd-vm-readiness-dev12.json"
    if not evidence_path.exists():
        pytest.skip("live VM evidence is generated after the installed qualification run")
    schema = json.loads(
        (ROOT / "schemas/systemd-vm-readiness-v1.schema.json").read_text()
    )
    evidence = json.loads(evidence_path.read_text())

    jsonschema.validate(evidence, schema)
    assert evidence["project_version"] == "2.0.0.dev12"
