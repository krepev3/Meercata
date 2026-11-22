from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from meercata.errors import QualificationError
from meercata.recovery_vm_qualifier import (
    CONFIRMATION,
    _boot_id,
    _enable_health_timer,
    _load_prepared_state,
    _protected_inventory,
    _timer_state,
    _validate_prepared_state,
    _verify_supervision_policy,
    _write_prepared_state,
    main,
)
from meercata.systemd_vm_qualifier import CLOUD_IMAGE_SHA512


ROOT = Path(__file__).parents[1]


def _prepared_state() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "reboot-prepared",
        "project_version": "2.0.0.dev16",
        "image_sha512": CLOUD_IMAGE_SHA512,
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "packages": {"meercata": "2.0.0~dev16-1"},
        "policy": {"restart": "on-failure"},
        "automatic_restart": {"signal": "SIGKILL"},
        "start_limit": {"result": "start-limit-enforced"},
        "manual_recovery": {"reset_failed": True},
        "timer": {"timer_enabled": True},
        "protected_files": {"configuration": {"sha256": "a" * 64}},
    }


def test_cli_rejects_wrong_confirmation_before_host_mutation() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = main(
        [
            "prepare",
            "--confirmation",
            "wrong",
            "--image-sha512",
            CLOUD_IMAGE_SHA512,
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 3
    assert stdout.getvalue() == ""
    assert "confirmation phrase" in stderr.getvalue()


def test_prepared_state_round_trip_is_root_private(tmp_path: Path) -> None:
    path = tmp_path / "qualification" / "state.json"
    path.parent.mkdir(mode=0o700)
    state = _prepared_state()

    _write_prepared_state(path, state, required_uid=None)

    assert path.stat().st_mode & 0o777 == 0o600
    assert _load_prepared_state(path, required_uid=None) == state
    with pytest.raises(FileExistsError):
        _write_prepared_state(path, state, required_uid=None)


def test_prepared_state_identity_is_exact() -> None:
    state = _prepared_state()
    _validate_prepared_state(state, CLOUD_IMAGE_SHA512)

    changed = dict(state)
    changed["image_sha512"] = "0" * 128
    with pytest.raises(QualificationError, match="identity"):
        _validate_prepared_state(changed, CLOUD_IMAGE_SHA512)

    changed = dict(state)
    changed["unexpected"] = True
    with pytest.raises(QualificationError, match="identity"):
        _validate_prepared_state(changed, CLOUD_IMAGE_SHA512)


def test_boot_id_requires_canonical_kernel_uuid(tmp_path: Path) -> None:
    path = tmp_path / "boot_id"
    path.write_text("11111111-2222-3333-4444-555555555555\n", encoding="ascii")
    assert _boot_id(path) == "11111111-2222-3333-4444-555555555555"

    path.write_text("not-a-boot-id\n", encoding="ascii")
    with pytest.raises(QualificationError, match="invalid"):
        _boot_id(path)


def test_protected_inventory_is_hash_bound_and_rejects_symlink(tmp_path: Path) -> None:
    config = tmp_path / "meercata.toml"
    config.write_bytes(b"[runtime]\nmode = \"ids\"\n")
    paths = {"configuration": (config, 1024)}

    inventory = _protected_inventory(paths, required_uid=None)

    assert inventory["configuration"]["path"] == str(config)
    assert len(inventory["configuration"]["sha256"]) == 64
    link = tmp_path / "link"
    link.symlink_to(config)
    with pytest.raises(QualificationError, match="unsafe"):
        _protected_inventory({"configuration": (link, 1024)}, required_uid=None)


def test_supervision_policy_requires_exact_installed_values(monkeypatch) -> None:
    values = {
        "Type": "notify",
        "Restart": "on-failure",
        "RestartUSec": "10s",
        "StartLimitBurst": "3",
        "StartLimitIntervalUSec": "5min",
        "TimeoutStartUSec": "1min 30s",
        "TimeoutStopUSec": "1min",
        "OOMPolicy": "stop",
    }
    monkeypatch.setattr(
        "meercata.recovery_vm_qualifier._systemctl_show",
        lambda unit, names: values,
    )

    assert _verify_supervision_policy()["start_limit_burst"] == 3

    values["Restart"] = "always"
    with pytest.raises(QualificationError, match="policy"):
        _verify_supervision_policy()


def test_timer_requires_nonzero_trigger_in_current_boot(monkeypatch) -> None:
    values = {
        "ActiveState": "active",
        "SubState": "waiting",
        "Unit": "meercata-health.service",
        "TimersMonotonic": "OnBootUSec=2min OnUnitActiveUSec=1min",
        "LastTriggerUSecMonotonic": "0",
    }
    monkeypatch.setattr(
        "meercata.recovery_vm_qualifier._run",
        lambda *args, **kwargs: SimpleNamespace(stdout="enabled\n"),
    )
    monkeypatch.setattr(
        "meercata.recovery_vm_qualifier._systemctl_show",
        lambda unit, names: values,
    )

    with pytest.raises(QualificationError, match="timer"):
        _timer_state(require_trigger=True)

    values["LastTriggerUSecMonotonic"] = "2min 5s"
    assert _timer_state(require_trigger=True)["triggered_this_boot"] is True


def test_timer_enable_explicitly_restarts_elapsed_unit(monkeypatch) -> None:
    calls = []
    values = {
        "ActiveState": "active",
        "SubState": "waiting",
        "Unit": "meercata-health.service",
        "TimersMonotonic": "OnBootUSec=2min OnUnitActiveUSec=1min",
        "LastTriggerUSecMonotonic": "0",
    }

    def fake_run(command_id, argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="enabled\n")

    monkeypatch.setattr("meercata.recovery_vm_qualifier._run", fake_run)
    monkeypatch.setattr(
        "meercata.recovery_vm_qualifier._systemctl_show",
        lambda unit, names: values,
    )

    assert _enable_health_timer()["timer_sub_state"] == "waiting"
    assert calls[:2] == [
        ("/usr/bin/systemctl", "enable", "--now", "meercata-health.timer"),
        ("/usr/bin/systemctl", "restart", "meercata-health.timer"),
    ]


def test_recovery_vm_schema_is_valid_and_strict() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/recovery-vm-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (ROOT / "qualification-evidence/recovery-vm-dev16.json").read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["project_version"]["const"] == "2.0.0.dev16"
    assert schema["properties"]["checks"]["minItems"] == 10
    jsonschema.validate(evidence, schema)
    checks = {item["check_id"]: item["details"] for item in evidence["checks"]}
    assert len(checks) == len(evidence["checks"]) == 10
    assert checks["crash.auto-restart"]["before_pid"] != checks["crash.auto-restart"]["after_pid"]
    assert checks["crash.start-limit"]["start_attempt_exit_code"] == 1
    assert checks["reboot.boot-changed"]["before"] != checks["reboot.boot-changed"]["after"]
    assert checks["reboot.services"]["triggered_this_boot"] is True
    assert checks["health.after-reboot"]["healthy_checks"] == 15
