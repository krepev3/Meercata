from __future__ import annotations

import io
import json
from pathlib import Path
import pytest

from meercata.errors import QualificationError
from meercata.ips_systemd_vm_qualifier import (
    CLOUD_IMAGE_SHA512,
    EXPECTED_PACKAGES,
    QUALIFIED_PROJECT_VERSION,
    _exercise_failure,
    _validate_state,
    main,
)


def _prepared_state() -> dict:
    return {
        "schema_version": 1,
        "status": "reboot-prepared",
        "project_version": QUALIFIED_PROJECT_VERSION,
        "image_sha512": CLOUD_IMAGE_SHA512,
        "boot_id": "10000000-0000-4000-8000-000000000021",
        "packages": EXPECTED_PACKAGES,
        "protected_files": {"/etc/meercata/meercata.toml": "a" * 64},
        "initial": {"target_active": True},
        "guard_failure": {"fail_open": True},
        "rearmed": {"target_active": True},
        "engine_failure": {"fail_open": True},
        "stopped": {"policy_active": False},
        "final": {"target_active": True},
    }


def test_prepared_state_is_exact_and_image_bound() -> None:
    _validate_state(_prepared_state(), CLOUD_IMAGE_SHA512)

    altered = _prepared_state()
    altered["unexpected"] = True
    with pytest.raises(QualificationError, match="prepared state"):
        _validate_state(altered, CLOUD_IMAGE_SHA512)

    with pytest.raises(QualificationError, match="prepared state"):
        _validate_state(_prepared_state(), "0" * 128)


def test_guard_or_engine_failure_requires_observed_policy_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        "meercata.ips_systemd_vm_qualifier._runtime_status",
        lambda: {"policy": {"transaction_id": "21000000-0000-0000-0000-000000000021"}},
    )
    monkeypatch.setattr(
        "meercata.ips_systemd_vm_qualifier._run",
        lambda command_id, argv, **_kwargs: calls.append((command_id, argv)),
    )
    monkeypatch.setattr(
        "meercata.ips_systemd_vm_qualifier._wait_policy",
        lambda **_kwargs: {"listener_present": False},
    )

    result = _exercise_failure("meercata-ips-guard.service", "guard")

    assert calls[0][1][-2:] == ("--signal=SIGKILL", "meercata-ips-guard.service")
    assert result["policy_active_after"] is False
    assert result["fail_open"] is True


def test_cli_refuses_without_disposable_vm_confirmation() -> None:
    stderr = io.StringIO()

    assert main(["prepare", "--confirm", "wrong"], stderr=stderr) == 3
    assert "confirmation" in stderr.getvalue()


def test_final_report_shape_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    source = Path(__file__).parents[1]
    schema = json.loads(
        (source / "schemas/ips-systemd-vm-qualification-v1.schema.json").read_text()
    )
    platform = {
        "os_id": "debian",
        "version_id": "13",
        "architecture": "x86_64",
        "pid1": "systemd",
        "virtualization": "kvm",
        "cloud_image_sha512": CLOUD_IMAGE_SHA512,
        "effective_uid": 0,
        "effective_gid": 0,
    }
    identifiers = [
        "platform.vm",
        "packages.installed",
        "lifecycle.initial",
        "failure.guard",
        "lifecycle.rearmed",
        "failure.engine",
        "lifecycle.stop",
        "reboot.recovered",
        "health.ips",
        "protected.integrity",
        "cleanup.fail-open",
    ]
    report = {
        "schema_version": 1,
        "status": "ips-systemd-vm-qualified",
        "project_version": QUALIFIED_PROJECT_VERSION,
        "platform": platform,
        "checks": [
            {"check_id": check_id, "status": "passed", "details": {"ok": True}}
            for check_id in identifiers
        ],
        "limitations": ["one", "two", "three", "four"],
    }

    jsonschema.validate(report, schema)


def test_recorded_dev21_report_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    source = Path(__file__).parents[1]
    schema = json.loads(
        (source / "schemas/ips-systemd-vm-qualification-v1.schema.json").read_text()
    )
    report = json.loads(
        (source / "qualification-evidence/ips-systemd-vm-dev21.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["status"] == "ips-systemd-vm-qualified"
    assert len(report["checks"]) == 11
