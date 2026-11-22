from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from meercata.errors import QualificationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.paths import MeercataPaths
from meercata.rule_parser import summarize_ruleset
from meercata.rule_store import RuleCandidateStore
from meercata.ruleops_vm_qualifier import (
    CLOUD_IMAGE_SHA512,
    _ForcedPostReloadFailure,
    _approved_candidates,
    _build_fixture_rulesets,
    main,
)


class _Health:
    def __init__(self, status: HealthStatus) -> None:
        self.report = HealthReport(
            "ids", (HealthCheck("runtime", status, status.value),)
        )

    def collect(self) -> HealthReport:
        return self.report


def _candidate(paths: MeercataPaths, rule: bytes, candidate_id: str) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.controller_config_file.write_text(
        "schema_version = 1\n\n"
        "[rules]\n"
        f'active_rules_path = "{paths.suricata_rules_dir / "suricata.rules"}"\n'
        f'suricata_config_path = "{paths.suricata_config_file}"\n'
    )
    store = RuleCandidateStore(paths)
    directory = store.prepare(candidate_id)
    (directory / "rules" / "suricata.rules").write_bytes(rule)
    summary = summarize_ruleset(rule)
    pack_dir = paths.regression_packs_dir / "approved-pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    pcap = b"redistribution-safe synthetic pcap"
    (pack_dir / "case.pcap").write_bytes(pcap)
    pack = {
        "schema_version": 1,
        "pack_id": "approved-pack",
        "description": "synthetic qualification pack",
        "cases": [
            {
                "case_id": "case",
                "pcap_file": "case.pcap",
                "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
                "expected_alerts": [],
                "forbidden_alerts": [{"gid": 1, "sid": 999999}],
            }
        ],
    }
    pack_bytes = json.dumps(pack, separators=(",", ":")).encode()
    (pack_dir / "manifest.json").write_bytes(pack_bytes)
    store.save_manifest(
        candidate_id,
        {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": "et/open",
            "created_utc": "2026-08-14T00:00:00Z",
            "status": "regression_passed",
            "summary": summary.to_dict(),
            "validation": {"status": "passed"},
            "regression": {
                "status": "passed",
                "pack_id": "approved-pack",
                "candidate_sha256": summary.sha256,
                "pack_manifest_sha256": hashlib.sha256(pack_bytes).hexdigest(),
            },
        },
    )


def test_wrong_confirmation_is_rejected_before_vm_checks() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = main(
        [
            "--confirmation",
            "wrong",
            "--image-sha512",
            CLOUD_IMAGE_SHA512,
            "--success-candidate",
            "00000000-0000-0000-0000-000000000001",
            "--rollback-candidate",
            "00000000-0000-0000-0000-000000000002",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 3
    assert stdout.getvalue() == ""
    assert "confirmation phrase" in stderr.getvalue()


def test_candidate_gate_requires_distinct_hash_bound_approvals(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    success = "00000000-0000-0000-0000-000000000001"
    rollback = "00000000-0000-0000-0000-000000000002"
    _candidate(paths, b"alert ip any any -> any any (sid:1; rev:1;)\n", success)
    _candidate(paths, b"alert ip any any -> any any (sid:1; rev:2;)\n", rollback)

    details = _approved_candidates(paths, success, rollback)

    assert details["success_sha256"] != details["rollback_sha256"]
    assert details["success_pack_id"] == "approved-pack"
    with pytest.raises(QualificationError, match="must differ"):
        _approved_candidates(paths, success, success)


def test_forced_failure_requires_real_healthy_report_first() -> None:
    injected = _ForcedPostReloadFailure(_Health(HealthStatus.HEALTHY))
    failed = injected.collect()

    assert failed.status == HealthStatus.CRITICAL
    assert failed.checks[0].check_id == "qualification_injected_failure"

    existing = _ForcedPostReloadFailure(_Health(HealthStatus.DEGRADED)).collect()
    assert existing.status == HealthStatus.DEGRADED


def test_fixture_rulesets_are_hash_distinct_and_preserve_active_rules() -> None:
    active = b"alert ip any any -> any any (sid:1; rev:1;)\n"
    candidates = _build_fixture_rulesets(
        active,
        {
            "success": (
                b'alert udp any any -> any 65013 (msg:"fixture"; sid:9900013; rev:1;)\n'
            ),
            "rollback": (
                b'alert udp any any -> any 65013 (msg:"fixture"; sid:9900013; rev:2;)\n'
            ),
        },
    )

    success = summarize_ruleset(candidates["success"])
    rollback = summarize_ruleset(candidates["rollback"])
    assert success.active_rules == rollback.active_rules == 2
    assert success.sha256 != rollback.sha256
    assert success.signatures[0].key == (1, 1)
    assert success.signatures[1].key == (1, 9900013)


def test_fixture_rulesets_reject_active_sid_collision() -> None:
    active = b"alert ip any any -> any any (sid:9900013; rev:1;)\n"

    with pytest.raises(QualificationError, match="already uses"):
        _build_fixture_rulesets(
            active,
            {"success": b"", "rollback": b"different"},
        )


def test_ruleops_vm_schema_is_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "schemas/ruleops-vm-qualification-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)


def test_recorded_dev13_ruleops_vm_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "schemas/ruleops-vm-qualification-v1.schema.json").read_text()
    )
    report = json.loads(
        (root / "qualification-evidence/ruleops-vm-dev13.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev13"
