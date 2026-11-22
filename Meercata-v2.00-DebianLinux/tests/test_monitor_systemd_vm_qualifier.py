from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from meercata import monitor_systemd_vm_qualifier as qualifier
from meercata.errors import QualificationError

ROOT = Path(__file__).parents[1]


def _prepared() -> dict:
    return {
        "schema_version": 1,
        "status": "reboot-prepared",
        "project_version": qualifier.QUALIFIED_PROJECT_VERSION,
        "image_sha512": qualifier.CLOUD_IMAGE_SHA512,
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "packages": {"meercata": "2.0.0~dev25-1"},
        "protected_files": {"configuration": {"sha256": "a" * 64}},
        "active_files": {"configuration": {"sha256": "b" * 64}},
        "checks": [qualifier._passed(name, {"observed": True}) for name in qualifier.CHECK_IDS[:12]],
        "pending": 2,
        "pending_event_ids": ["a" * 64, "b" * 64],
        "sequence": 9,
    }


@pytest.mark.parametrize("phase", ["prepare", "verify"])
@pytest.mark.parametrize("bad", ["confirmation", "image"])
def test_cli_guard_precedes_every_command_and_write(monkeypatch, phase, bad) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("a command or workspace mutation preceded the disposable VM guard")

    monkeypatch.setattr(qualifier, "_command", forbidden)
    monkeypatch.setattr(qualifier, "_preflight", forbidden)
    monkeypatch.setattr(qualifier, "_load_prepared_state", forbidden)
    stdout, stderr = io.StringIO(), io.StringIO()
    rc = qualifier.main([
        phase, "--confirmation", "wrong" if bad == "confirmation" else qualifier.CONFIRMATION,
        "--image-sha512", "0" * 128 if bad == "image" else qualifier.CLOUD_IMAGE_SHA512,
    ], stdout=stdout, stderr=stderr)
    assert rc == 3
    assert stdout.getvalue() == ""
    assert ("confirmation phrase" if bad == "confirmation" else "not approved") in stderr.getvalue()


@pytest.mark.parametrize("key,value", [
    ("schema_version", True), ("project_version", "2.0.0.dev24"),
    ("image_sha512", "0" * 128), ("boot_id", "x" * 36),
    ("pending", 0), ("sequence", True), ("packages", {}),
])
def test_reboot_state_rejects_wrong_identity_and_counters(key, value) -> None:
    state = _prepared()
    qualifier._validate_state(state, qualifier.CLOUD_IMAGE_SHA512)
    state[key] = value
    with pytest.raises(QualificationError):
        qualifier._validate_state(state, qualifier.CLOUD_IMAGE_SHA512)


@pytest.mark.parametrize("damage", ["duplicate", "omitted", "failed", "extra"])
def test_reboot_state_requires_exact_pre_reboot_checks(damage) -> None:
    state = _prepared()
    if damage == "duplicate":
        state["checks"][1] = state["checks"][0]
    elif damage == "omitted":
        state["checks"].pop()
    elif damage == "failed":
        state["checks"][0]["status"] = "failed"
    else:
        state["unexpected"] = True
    with pytest.raises(QualificationError):
        qualifier._validate_state(state, qualifier.CLOUD_IMAGE_SHA512)


def test_verify_requires_real_reboot_before_mutation(monkeypatch) -> None:
    state = _prepared()
    gate = qualifier.MonitorSystemdVmQualifier(
        confirmation=qualifier.CONFIRMATION, image_sha512=qualifier.CLOUD_IMAGE_SHA512,
    )
    monkeypatch.setattr(gate, "_guard", lambda: {})
    monkeypatch.setattr(qualifier, "_load_prepared_state", lambda path: state)
    monkeypatch.setattr(qualifier, "_boot_id", lambda: state["boot_id"])
    monkeypatch.setattr(qualifier, "_command", lambda *a, **k: pytest.fail("host mutation"))
    with pytest.raises(QualificationError, match="reboot is unproven"):
        gate.verify()


@pytest.mark.parametrize("ids", [[], ["a" * 64, "a" * 64], ["a" * 64, "bad"]])
def test_reboot_state_binds_every_pending_event_identity(ids) -> None:
    state = _prepared()
    state["pending_event_ids"] = ids
    with pytest.raises(QualificationError, match="event identities"):
        qualifier._validate_state(state, qualifier.CLOUD_IMAGE_SHA512)


def test_credential_destination_is_fixed_before_identity_or_file_access(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(qualifier.pwd, "getpwnam", lambda *a: pytest.fail("identity lookup"))
    with pytest.raises(QualificationError, match="not allowlisted"):
        qualifier._install_credential(tmp_path / "token", b"sensitive")
    assert not list(tmp_path.iterdir())


def test_command_runner_contract_handles_expected_nonzero_and_timeout() -> None:
    argv = ("/usr/bin/python3", "-I", "-c", "print('expected failure'); raise SystemExit(2)")
    result = qualifier._command(argv, allowed=(2,))
    assert result.return_code == 2
    assert result.stdout.strip() == "expected failure"
    with pytest.raises(QualificationError, match="command failed"):
        qualifier._command(argv)
    with pytest.raises(QualificationError, match="command failed"):
        qualifier._command(("/usr/bin/python3", "-I", "-c", "import time; time.sleep(5)"), timeout=0.01)


def test_atomic_credential_replacement_preserves_mode_and_removes_temporary_file(tmp_path, monkeypatch) -> None:
    target = tmp_path / "token"
    target.write_bytes(b"retired")
    qualifier._replace_file(target, b"current", os.getuid(), os.getgid(), 0o640)
    assert target.read_bytes() == b"current"
    assert target.stat().st_mode & 0o777 == 0o640

    def failed(*args):
        raise OSError("injected rename failure")

    monkeypatch.setattr(qualifier.os, "replace", failed)
    with pytest.raises(OSError, match="rename failure"):
        qualifier._replace_file(target, b"never installed", os.getuid(), os.getgid(), 0o640)
    assert target.read_bytes() == b"current"
    assert list(tmp_path.iterdir()) == [target]


def test_cleanup_restores_configuration_and_removes_keys_even_if_service_cleanup_fails(tmp_path, monkeypatch) -> None:
    config, token, ca = (tmp_path / name for name in ("config", "token", "ca"))
    for path in (config, token, ca):
        path.write_bytes(b"temporary qualification data")
    key = tmp_path / "pki1" / "server.key"
    key.parent.mkdir()
    key.write_bytes(b"temporary private key")
    monkeypatch.setattr(qualifier, "CONFIG", config)
    monkeypatch.setattr(qualifier, "TOKEN", token)
    monkeypatch.setattr(qualifier, "CA", ca)
    monkeypatch.setattr(qualifier, "WORK", tmp_path)
    calls = []

    def failed(*args, **kwargs):
        calls.append("service cleanup attempted")
        raise QualificationError("injected service-manager failure")

    monkeypatch.setattr(qualifier, "_pause", failed)
    monkeypatch.setattr(qualifier, "_command", failed)
    monkeypatch.setattr(qualifier, "_recover_suricata", lambda: calls.append("suricata recovery attempted"))
    with pytest.raises(QualificationError, match="cleanup failed"):
        qualifier._cleanup(b"original operator configuration")
    assert config.read_bytes() == b"original operator configuration"
    assert not token.exists() and not ca.exists() and not key.exists()
    assert calls[-1] == "suricata recovery attempted"


def test_journal_read_is_bound_to_current_service_invocation_and_boot(monkeypatch) -> None:
    calls = []
    invocation = "a" * 32

    def command(argv, **kwargs):
        calls.append(argv)
        assert "--all" in argv  # Otherwise journalctl replaces large MESSAGE fields with null.
        return SimpleNamespace(stdout=json.dumps({
            "__MONOTONIC_TIMESTAMP": "2000", "_SYSTEMD_INVOCATION_ID": invocation,
            "MESSAGE": json.dumps({"schema_version": 1, "exit_code": 0, "health": "x" * 6000}),
        }) + "\n")

    monkeypatch.setattr(qualifier, "_command", command)
    observed = qualifier._journal_report(qualifier.SERVICES[0], since_monotonic=1000)
    assert observed["exit_code"] == 0 and len(observed["health"]) == 6000
    assert "--boot" in calls[0]
    assert "--output=json" in calls[0]
    with pytest.raises(QualificationError, match="no JSON"):
        qualifier._journal_report(qualifier.SERVICES[0], since_monotonic=3000)
    with pytest.raises(QualificationError, match="not allowlisted"):
        qualifier._journal_report("unrelated.service")


def test_manual_probe_tolerates_collected_oneshot_with_no_failure_state(monkeypatch) -> None:
    def command(argv, **kwargs):
        if "reset-failed" in argv:
            assert 1 in kwargs["allowed"]
            return SimpleNamespace(return_code=1)
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(qualifier, "_command", command)
    monkeypatch.setattr(qualifier, "_systemctl_show", lambda *a: {"Result": "success", "ExecMainStatus": "0"})
    assert qualifier._start(qualifier.SERVICES[0], 0)["Result"] == "success"
    assert qualifier._PROBE_STARTS[qualifier.SERVICES[0]] > 0


def test_timers_cannot_pass_using_only_enabled_state_or_stale_journal(monkeypatch) -> None:
    trigger = 0

    def command(argv):
        if argv[0] == "/usr/bin/busctl":
            assert argv[3].startswith("/org/freedesktop/systemd1/unit/meercata_2dmonitor")
            assert argv[-1] == "LastTriggerUSecMonotonic"
            return SimpleNamespace(stdout=f"t {trigger}\n")
        return SimpleNamespace(stdout="enabled\n")

    monkeypatch.setattr(qualifier, "_command", command)

    def show(unit, names):
        if unit.endswith(".timer"):
            return {"ActiveState": "active", "Unit": unit.replace(".timer", ".service")}
        return {"Result": "success", "ExecMainStatus": "0"}

    monkeypatch.setattr(qualifier, "_systemctl_show", show)
    monkeypatch.setattr(qualifier, "_journal_report", lambda *a: pytest.fail("untriggered timer accepted"))
    monkeypatch.setattr(qualifier.time, "sleep", lambda *a: None)
    with pytest.raises(QualificationError, match="has not triggered"):
        qualifier._wait_timers(timeout=0.01)
    trigger = 907381508
    with pytest.raises(QualificationError, match="has not triggered"):
        qualifier._wait_timers(timeout=0.01, since_monotonic=trigger + 1)
    journal = {}

    def report(service, *, since_monotonic):
        journal[service] = since_monotonic
        return {"exit_code": 0}

    monkeypatch.setattr(qualifier, "_journal_report", report)
    monkeypatch.setattr(qualifier, "_service_json", lambda *a: {"pending": 0})
    assert set(qualifier._wait_timers(timeout=1)) == set(qualifier.TIMERS)
    assert journal == dict.fromkeys(qualifier.SERVICES, trigger)


def test_vm_evidence_schema_has_fifteen_ordered_strict_gates() -> None:
    import jsonschema

    schema = json.loads((ROOT / "schemas/monitor-systemd-vm-qualification-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    entries = schema["properties"]["checks"]["prefixItems"]
    assert [e["properties"]["check_id"]["const"] for e in entries] == list(qualifier.CHECK_IDS)
    assert schema["properties"]["checks"]["items"] is False
    assert all(e["additionalProperties"] is False for e in entries)
    evidence = ROOT / "qualification-evidence/monitor-systemd-vm-dev25.json"
    report = json.loads(evidence.read_text())
    jsonschema.validate(report, schema)
    details = {entry["check_id"]: entry["details"] for entry in report["checks"]}
    reboot = details["reboot.monitoring"]
    assert reboot["before_boot_id"] != reboot["after_boot_id"]
    assert reboot["sequence_after"] >= reboot["sequence_before"]
    assert len(reboot["recovered_event_ids"]) == reboot["recovered_events"]
    assert reboot["recovered_events"] == details["tls.ca-rotation"]["pending_before_reboot"]
    damaged = copy.deepcopy(report)
    damaged["checks"][12]["details"]["pending"] = 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(damaged, schema)
