from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from meercata.errors import RuleOperationError
from meercata.models import CommandResult
from meercata.paths import MeercataPaths
from meercata.rule_config import RuleConfig
from meercata.rule_parser import summarize_ruleset
from meercata.rule_store import RuleCandidateStore
from meercata.ruleops import RuleOpsService, build_stage_commands


def _config(paths: MeercataPaths, *, minimum: int = 1) -> RuleConfig:
    return RuleConfig(
        source="et/open",
        minimum_rule_count=minimum,
        maximum_reduction_percent=5,
        update_timeout_seconds=60,
        validation_timeout_seconds=30,
        reload_timeout_seconds=30,
        reload_poll_seconds=1,
        active_rules_path=paths.suricata_rules_dir / "suricata.rules",
        suricata_config_path=paths.suricata_config_file,
    )


def _result(command_id: str, argv: tuple[str, ...], return_code: int = 0) -> CommandResult:
    stdout = "suricata-update version 1.3.8\n" if command_id.endswith("version") else ""
    return CommandResult(
        command_id,
        argv,
        return_code,
        stdout,
        "",
        False,
        False,
        False,
        "2026-08-10T00:00:00Z",
        0.25,
    )


class FakeRunner:
    def __init__(self, commands, calls, *, fail_command=None, candidate_rules=None):
        self.commands = commands
        self.calls = calls
        self.fail_command = fail_command
        self.candidate_rules = candidate_rules

    def run(self, command_id: str) -> CommandResult:
        definition = self.commands[command_id]
        self.calls.append((command_id, definition))
        if command_id == "rules.update.build" and self.candidate_rules is not None:
            output = Path(definition.argv[definition.argv.index("-o") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / "suricata.rules").write_bytes(self.candidate_rules)
        return _result(
            command_id,
            definition.argv,
            1 if command_id == self.fail_command else 0,
        )


def _factory(calls, *, fail_command=None, candidate_rules=None):
    return lambda commands: FakeRunner(
        commands,
        calls,
        fail_command=fail_command,
        candidate_rules=candidate_rules,
    )


def test_stage_uses_fixed_safe_update_argv_and_persists_manifest(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    rules = b'alert ip any any -> any any (sid:1; rev:1;)\n'
    service = RuleOpsService(
        paths,
        _config(paths),
        RuleCandidateStore(paths),
        runner_factory=_factory(calls, candidate_rules=rules),
    )

    manifest = service.stage()

    assert manifest["status"] == "policy_passed"
    assert manifest["summary"]["active_rules"] == 1
    assert [call[0] for call in calls] == ["rules.update.version", "rules.update.build"]
    update = calls[1][1]
    assert update.argv[0] == "/usr/bin/suricata-update"
    assert "--no-reload" in update.argv
    assert "--no-test" in update.argv
    assert "--fail" in update.argv
    assert update.working_directory.is_absolute()
    assert service.store.load_manifest(manifest["candidate_id"])["status"] == "policy_passed"
    events = [json.loads(line) for line in paths.audit_file.read_text().splitlines()]
    assert [event["event"] for event in events] == [
        "rules.stage_requested",
        "rules.stage_completed",
    ]
    assert events[-1]["data"]["sha256"] == manifest["summary"]["sha256"]


def test_stage_rejects_update_failure(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = RuleOpsService(
        paths,
        _config(paths),
        RuleCandidateStore(paths),
        runner_factory=_factory([], fail_command="rules.update.build"),
    )

    with pytest.raises(RuleOperationError, match="exited 1"):
        service.stage()


def test_stage_marks_policy_rejected_candidate(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = RuleOpsService(
        paths,
        _config(paths, minimum=2),
        RuleCandidateStore(paths),
        runner_factory=_factory(
            [], candidate_rules=b'alert ip any any -> any any (sid:1; rev:1;)\n'
        ),
    )

    manifest = service.stage()

    assert manifest["status"] == "policy_rejected"
    with pytest.raises(RuleOperationError, match="rule-count policy"):
        service.validate(manifest["candidate_id"])


def test_validate_runs_suricata_test_and_updates_manifest(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    service = RuleOpsService(
        paths,
        _config(paths),
        RuleCandidateStore(paths),
        runner_factory=_factory(
            calls, candidate_rules=b'alert ip any any -> any any (sid:1; rev:1;)\n'
        ),
    )
    manifest = service.stage()

    validated = service.validate(manifest["candidate_id"])

    assert validated["status"] == "validated"
    command = calls[-1][1]
    assert command.argv[:2] == ("/usr/bin/suricata", "-T")
    assert "-S" in command.argv
    assert "--init-errors-fatal" in command.argv
    assert command.argv[command.argv.index("--set") + 1] == "unix-command.enabled=no"


def test_validate_records_suricata_failure(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    service = RuleOpsService(
        paths,
        _config(paths),
        RuleCandidateStore(paths),
        runner_factory=_factory(
            calls, candidate_rules=b'alert ip any any -> any any (sid:1; rev:1;)\n'
        ),
    )
    manifest = service.stage()
    service._runner_factory = _factory(calls, fail_command="rules.validate")

    with pytest.raises(RuleOperationError, match="rejected"):
        service.validate(manifest["candidate_id"])

    stored = service.store.load_manifest(manifest["candidate_id"])
    assert stored["status"] == "validation_failed"
    assert stored["validation"]["return_code"] == 1


def test_status_and_promotion_gate(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = RuleOpsService(paths, _config(paths), RuleCandidateStore(paths))

    status = service.status()

    assert status["active"]["exists"] is False
    assert status["promotion_available"] is False
    with pytest.raises(RuleOperationError, match="privileged helper"):
        service.promote("unused")


def test_build_stage_commands_rejects_non_allowlisted_source(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)
    unsafe = replace(config, source="custom")

    with pytest.raises(RuleOperationError, match="not allowlisted"):
        build_stage_commands(tmp_path / "data", tmp_path / "rules", unsafe)


def _validated_service_for_regression(tmp_path: Path, *, observed_sid: int):
    paths = MeercataPaths.isolated(tmp_path)
    store = RuleCandidateStore(paths)
    candidate_id = store.new_id()
    directory = store.prepare(candidate_id)
    rules = b'alert ip any any -> any any (sid:1001; rev:1;)\n'
    (directory / "rules" / "suricata.rules").write_bytes(rules)
    summary = summarize_ruleset(rules)
    store.save_manifest(
        candidate_id,
        {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": "et/open",
            "created_utc": "2026-08-12T00:00:00Z",
            "status": "validated",
            "summary": summary.to_dict(),
            "validation": {"status": "passed"},
            "regression": {"status": "pending"},
        },
    )
    pcap = b"fixed pcap"
    pack_dir = paths.regression_packs_dir / "smoke-v1"
    pack_dir.mkdir(parents=True)
    (pack_dir / "smoke.pcap").write_bytes(pcap)
    (pack_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pack_id": "smoke-v1",
                "description": "RuleOps integration pack",
                "cases": [
                    {
                        "case_id": "smoke",
                        "pcap_file": "smoke.pcap",
                        "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
                        "expected_alerts": [{"gid": 1, "sid": 1001}],
                        "forbidden_alerts": [],
                    }
                ],
            }
        )
    )

    class RegressionRunner:
        def __init__(self, commands):
            self.commands = commands

        def run(self, command_id):
            definition = self.commands[command_id]
            output = Path(definition.argv[definition.argv.index("-l") + 1])
            (output / "eve.json").write_text(
                json.dumps(
                    {
                        "event_type": "alert",
                        "alert": {"gid": 1, "signature_id": observed_sid},
                    }
                )
                + "\n"
            )
            return _result(command_id, definition.argv)

    service = RuleOpsService(
        paths,
        _config(paths),
        store,
        runner_factory=lambda commands: RegressionRunner(commands),
    )
    return paths, service, candidate_id


def test_regress_updates_candidate_manifest_and_audit(tmp_path: Path) -> None:
    paths, service, candidate_id = _validated_service_for_regression(
        tmp_path, observed_sid=1001
    )

    manifest = service.regress(candidate_id, "smoke-v1")

    assert manifest["status"] == "regression_passed"
    assert manifest["regression"]["status"] == "passed"
    assert manifest["regression"]["candidate_sha256"] == manifest["summary"]["sha256"]
    events = [json.loads(line) for line in paths.audit_file.read_text().splitlines()]
    assert [event["event"] for event in events] == [
        "rules.regression_requested",
        "rules.regression_completed",
    ]
    assert events[-1]["outcome"] == "success"


def test_regress_persists_failed_oracle_and_returns_error(tmp_path: Path) -> None:
    paths, service, candidate_id = _validated_service_for_regression(
        tmp_path, observed_sid=9999
    )

    with pytest.raises(RuleOperationError, match="failed the PCAP"):
        service.regress(candidate_id, "smoke-v1")

    manifest = service.store.load_manifest(candidate_id)
    assert manifest["status"] == "regression_failed"
    assert manifest["regression"]["failed_cases"] == 1
    events = [json.loads(line) for line in paths.audit_file.read_text().splitlines()]
    assert events[-1]["outcome"] == "failure"


def test_regress_requires_validated_unchanged_candidate(tmp_path: Path) -> None:
    _paths, service, candidate_id = _validated_service_for_regression(
        tmp_path, observed_sid=1001
    )
    manifest = service.store.load_manifest(candidate_id)
    manifest["validation"] = {"status": "failed"}
    service.store.save_manifest(candidate_id, manifest)

    with pytest.raises(RuleOperationError, match="must pass Suricata validation"):
        service.regress(candidate_id, "smoke-v1")

    manifest["validation"] = {"status": "passed"}
    service.store.save_manifest(candidate_id, manifest)
    service.store.rules_file(candidate_id).write_bytes(
        b'alert ip any any -> any any (sid:2002; rev:1;)\n'
    )
    with pytest.raises(RuleOperationError, match="hash changed"):
        service.regress(candidate_id, "smoke-v1")
