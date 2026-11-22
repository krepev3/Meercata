from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from meercata.audit import AuditLogger
from meercata.errors import AuditError, PrivilegedOperationError
from meercata.locking import ControllerLock
from meercata.models import Actor, CommandResult, TransactionRecord, TransactionState
from meercata.paths import MeercataPaths
from meercata.privileged_rules import PrivilegedRuleService
from meercata.rule_config import RuleConfig
from meercata.rule_parser import summarize_ruleset
from meercata.rule_store import RuleCandidateStore
from meercata.state_store import StateStore

OLD_RULE = b'alert ip any any -> any any (sid:10; rev:1;)\n'
NEW_RULE = b'alert ip any any -> any any (sid:20; rev:1;)\n'


def _config(paths: MeercataPaths) -> RuleConfig:
    return RuleConfig(
        "et/open",
        1,
        5,
        60,
        30,
        30,
        1,
        paths.suricata_rules_dir / "suricata.rules",
        paths.suricata_config_file,
    )


def _result(command_id: str, argv: tuple[str, ...], code: int = 0) -> CommandResult:
    return CommandResult(
        command_id,
        argv,
        code,
        "",
        "",
        False,
        False,
        False,
        "2026-08-12T00:00:00Z",
        0.25,
    )


class ValidationRunner:
    def __init__(self, commands, calls, *, code=0, regression_sid=20):
        self.commands = commands
        self.calls = calls
        self.code = code
        self.regression_sid = regression_sid

    def run(self, command_id):
        command = self.commands[command_id]
        self.calls.append((command_id, command))
        if command_id.startswith("rules.regression.") and self.code == 0:
            output = Path(command.argv[command.argv.index("-l") + 1])
            (output / "eve.json").write_text(
                json.dumps(
                    {
                        "event_type": "alert",
                        "alert": {"gid": 1, "signature_id": self.regression_sid},
                    }
                )
                + "\n"
            )
        return _result(command_id, command.argv, self.code)


def _factory(calls, *, code=0, regression_sid=20):
    return lambda commands: ValidationRunner(
        commands, calls, code=code, regression_sid=regression_sid
    )


def _advance(record: TransactionRecord, state: TransactionState) -> TransactionRecord:
    return record.transitioned(state, {})


def _fixture(
    tmp_path: Path,
    *,
    active: bytes | None = OLD_RULE,
    validation_code: int = 0,
    reload_action=None,
):
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)
    paths.suricata_config_dir.mkdir(parents=True)
    paths.suricata_config_file.write_text("%YAML 1.1\n---\n")
    if active is not None:
        paths.suricata_rules_dir.mkdir(parents=True)
        config.active_rules_path.write_bytes(active)

    candidates = RuleCandidateStore(paths)
    candidate_id = candidates.new_id()
    candidate_dir = candidates.prepare(candidate_id)
    (candidate_dir / "rules" / "suricata.rules").write_bytes(NEW_RULE)
    summary = summarize_ruleset(NEW_RULE)

    pack_dir = paths.regression_packs_dir / "approved-pack"
    pack_dir.mkdir(parents=True)
    pcap = b"approved pcap"
    (pack_dir / "test.pcap").write_bytes(pcap)
    pack_manifest = {
        "schema_version": 1,
        "pack_id": "approved-pack",
        "description": "privileged helper approval pack",
        "cases": [
            {
                "case_id": "test",
                "pcap_file": "test.pcap",
                "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
                "expected_alerts": [{"gid": 1, "sid": 20}],
                "forbidden_alerts": [],
            }
        ],
    }
    pack_bytes = json.dumps(pack_manifest).encode()
    (pack_dir / "manifest.json").write_bytes(pack_bytes)
    candidates.save_manifest(
        candidate_id,
        {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": "et/open",
            "created_utc": "2026-08-12T00:00:00Z",
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
    record = TransactionRecord.create_locked(
        "rules.promote",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
        {"candidate_id": candidate_id},
    )
    store = StateStore(paths)
    store.save(record)
    lock = ControllerLock(paths.controller_lock_file)
    lock.acquire(record.transaction_id)
    calls = []
    service = PrivilegedRuleService(
        paths,
        config,
        runner_factory=_factory(calls, code=validation_code),
        reload_action=reload_action
        or (lambda: {"failed_rules": 0, "ruleset_stats": {"rules_loaded": 1}}),
    )
    return paths, candidates, store, lock, calls, service, record


def _to_validated(store: StateStore, record: TransactionRecord) -> TransactionRecord:
    for state in (
        TransactionState.SNAPSHOTTED,
        TransactionState.STAGED,
        TransactionState.VALIDATED,
    ):
        record = _advance(record, state)
    store.save(record)
    return record


def _to_rolling_back(store: StateStore, record: TransactionRecord) -> TransactionRecord:
    record = _advance(record, TransactionState.APPLIED)
    record = _advance(record, TransactionState.ROLLING_BACK)
    store.save(record)
    return record


def test_helper_seals_activates_and_restores_rules(tmp_path: Path) -> None:
    paths, candidates, store, lock, calls, service, record = _fixture(tmp_path)
    try:
        snapshot = service.snapshot(record.transaction_id)
        assert snapshot["active_sha256"] == hashlib.sha256(OLD_RULE).hexdigest()
        assert snapshot["candidate_sha256"] == hashlib.sha256(NEW_RULE).hexdigest()

        # The helper must activate its sealed copy, not mutable candidate state.
        candidates.rules_file(snapshot["candidate_id"]).write_bytes(
            b'alert ip any any -> any any (sid:999; rev:1;)\n'
        )
        record = _to_validated(store, record)
        activated = service.activate(record.transaction_id)

        assert activated["state"] == "applied"
        assert paths.suricata_rules_dir.joinpath("suricata.rules").read_bytes() == NEW_RULE
        assert calls[0][0] == "privileged.rules.validate"
        command = calls[0][1]
        assert command.argv[:2] == ("/usr/bin/suricata", "-T")
        assert command.argv[command.argv.index("--set") + 1] == "unix-command.enabled=no"
        assert str(paths.privileged_state_dir) in command.argv[command.argv.index("-S") + 1]

        record = _to_rolling_back(store, record)
        restored = service.rollback(record.transaction_id)
        assert restored["applied"] is True
        assert restored["restored_sha256"] == hashlib.sha256(OLD_RULE).hexdigest()
        assert paths.suricata_rules_dir.joinpath("suricata.rules").read_bytes() == OLD_RULE
    finally:
        lock.release()

    events = [json.loads(line) for line in paths.privileged_audit_file.read_text().splitlines()]
    assert events[0]["event"] == "privileged.rules_snapshot_requested"
    assert events[0]["operation"] == "rules.snapshot"
    assert events[-1]["event"] == "privileged.rules_rollback_completed"
    assert events[-1]["operation"] == "rules.rollback"


def test_first_install_rollback_removes_only_activated_file(tmp_path: Path) -> None:
    paths, _candidates, store, lock, _calls, service, record = _fixture(
        tmp_path, active=None
    )
    try:
        snapshot = service.snapshot(record.transaction_id)
        assert snapshot["active_existed"] is False
        record = _to_validated(store, record)
        service.activate(record.transaction_id)
        record = _to_rolling_back(store, record)

        result = service.rollback(record.transaction_id)

        assert result == {"applied": True, "restored_sha256": None}
        assert not paths.suricata_rules_dir.joinpath("suricata.rules").exists()
    finally:
        lock.release()


def test_activation_rejects_active_change_after_snapshot(tmp_path: Path) -> None:
    paths, _candidates, store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        service.snapshot(record.transaction_id)
        external = b'alert ip any any -> any any (sid:777; rev:1;)\n'
        service.config.active_rules_path.write_bytes(external)
        record = _to_validated(store, record)

        with pytest.raises(PrivilegedOperationError, match="changed after snapshot"):
            service.activate(record.transaction_id)

        assert service.config.active_rules_path.read_bytes() == external
        record = _advance(record, TransactionState.ROLLING_BACK)
        store.save(record)
        result = service.rollback(record.transaction_id)
        assert result["reason"] == "activation_not_started"
    finally:
        lock.release()


def test_privileged_validation_failure_leaves_active_rules_unchanged(tmp_path: Path) -> None:
    paths, _candidates, store, lock, calls, service, record = _fixture(tmp_path)
    try:
        service.snapshot(record.transaction_id)
        service._runner_factory = _factory(calls, code=1)
        record = _to_validated(store, record)

        with pytest.raises(PrivilegedOperationError, match="failed privileged validation"):
            service.activate(record.transaction_id)

        assert service.config.active_rules_path.read_bytes() == OLD_RULE
        assert not (
            paths.privileged_transactions_dir
            / record.transaction_id
            / "rules"
            / "activation.json"
        ).exists()
    finally:
        lock.release()


def test_privileged_regression_failure_blocks_snapshot_and_activation(tmp_path: Path) -> None:
    paths, _candidates, _store, lock, calls, service, record = _fixture(tmp_path)
    service._runner_factory = _factory(calls, regression_sid=9999)
    try:
        with pytest.raises(PrivilegedOperationError, match="failed privileged PCAP"):
            service.snapshot(record.transaction_id)

        artefacts = (
            paths.privileged_transactions_dir / record.transaction_id / "rules"
        )
        assert not (artefacts / "snapshot.json").exists()
        assert service.config.active_rules_path.read_bytes() == OLD_RULE
    finally:
        lock.release()


def test_rollback_refuses_to_overwrite_unrelated_change(tmp_path: Path) -> None:
    _paths, _candidates, store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        service.snapshot(record.transaction_id)
        record = _to_validated(store, record)
        service.activate(record.transaction_id)
        service.config.active_rules_path.write_bytes(
            b'alert ip any any -> any any (sid:888; rev:1;)\n'
        )
        record = _to_rolling_back(store, record)

        with pytest.raises(PrivilegedOperationError, match="outside this transaction"):
            service.rollback(record.transaction_id)
    finally:
        lock.release()


def test_helper_rejects_missing_lock_wrong_state_and_wrong_operation(tmp_path: Path) -> None:
    _paths, _candidates, store, lock, _calls, service, record = _fixture(tmp_path)
    lock.release()
    with pytest.raises(PrivilegedOperationError, match="not held"):
        service.snapshot(record.transaction_id)

    lock.acquire(record.transaction_id)
    try:
        record = _advance(record, TransactionState.SNAPSHOTTED)
        store.save(record)
        with pytest.raises(PrivilegedOperationError, match="not authorized"):
            service.snapshot(record.transaction_id)

        wrong = TransactionRecord.create_locked(
            "config.deploy",
            record.actor,
            {"candidate_id": record.redacted_arguments["candidate_id"]},
            record.transaction_id,
        )
        store.save(wrong)
        with pytest.raises(PrivilegedOperationError, match="not authorized"):
            service.snapshot(record.transaction_id)
    finally:
        lock.release()


def test_snapshot_rejects_candidate_or_pack_tampering(tmp_path: Path) -> None:
    paths, candidates, _store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        candidates.rules_file(record.redacted_arguments["candidate_id"]).write_bytes(b"changed")
        with pytest.raises(PrivilegedOperationError, match="does not match approval"):
            service.snapshot(record.transaction_id)
    finally:
        lock.release()

    paths, _candidates, _store, lock, _calls, service, record = _fixture(
        tmp_path / "pack-case"
    )
    try:
        pack_manifest = paths.regression_packs_dir / "approved-pack" / "manifest.json"
        pack_manifest.write_text(pack_manifest.read_text() + "\n")
        with pytest.raises(PrivilegedOperationError, match="pack changed"):
            service.snapshot(record.transaction_id)
    finally:
        lock.release()


def test_pack_change_after_snapshot_blocks_activation_but_not_recovery(tmp_path: Path) -> None:
    paths, _candidates, store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        service.snapshot(record.transaction_id)
        pack_manifest = paths.regression_packs_dir / "approved-pack" / "manifest.json"
        pack_manifest.write_text(pack_manifest.read_text() + "\n")
        record = _to_validated(store, record)

        with pytest.raises(PrivilegedOperationError, match="changed after privileged"):
            service.activate(record.transaction_id)

        record = _advance(record, TransactionState.ROLLING_BACK)
        store.save(record)
        result = service.rollback(record.transaction_id)
        assert result["reason"] == "activation_not_started"
        assert service.config.active_rules_path.read_bytes() == OLD_RULE
    finally:
        lock.release()

class FailingAudit:
    def record(self, *_args, **_kwargs):
        raise AuditError("audit unavailable")


def test_required_privileged_audit_failure_blocks_snapshot(tmp_path: Path) -> None:
    paths, _candidates, _store, lock, _calls, _service, record = _fixture(tmp_path)
    service = PrivilegedRuleService(
        paths,
        _config(paths),
        audit=FailingAudit(),
    )
    try:
        with pytest.raises(AuditError, match="unavailable"):
            service.snapshot(record.transaction_id)
        assert not paths.privileged_state_dir.exists()
    finally:
        lock.release()


def test_helper_rejects_symlinked_candidate_and_active_target(tmp_path: Path) -> None:
    paths, candidates, _store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        candidate = candidates.rules_file(record.redacted_arguments["candidate_id"])
        candidate.unlink()
        outside_candidate = tmp_path / "outside-candidate.rules"
        outside_candidate.write_bytes(NEW_RULE)
        candidate.symlink_to(outside_candidate)
        with pytest.raises(PrivilegedOperationError):
            service.snapshot(record.transaction_id)
    finally:
        lock.release()

    paths, _candidates, store, lock, _calls, service, record = _fixture(
        tmp_path / "active-case"
    )
    try:
        service.snapshot(record.transaction_id)
        active = service.config.active_rules_path
        active.unlink()
        outside_active = tmp_path / "outside-active.rules"
        outside_active.write_bytes(OLD_RULE)
        active.symlink_to(outside_active)
        record = _to_validated(store, record)
        with pytest.raises(PrivilegedOperationError):
            service.activate(record.transaction_id)
        assert outside_active.read_bytes() == OLD_RULE
    finally:
        lock.release()


def test_production_helper_requires_effective_root(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = MeercataPaths.production()
    monkeypatch.setattr("meercata.privileged_rules.os.geteuid", lambda: 1000)

    with pytest.raises(PrivilegedOperationError, match="effective UID 0"):
        PrivilegedRuleService(paths, _config(paths), require_root=True)


def test_helper_reload_verifies_applied_and_rollback_hashes_idempotently(
    tmp_path: Path,
) -> None:
    reload_calls = []

    def reload_action():
        reload_calls.append("reload")
        return {"failed_rules": 0, "ruleset_stats": {"rules_loaded": 1}}

    paths, _candidates, store, lock, _calls, service, record = _fixture(
        tmp_path, reload_action=reload_action
    )
    try:
        service.snapshot(record.transaction_id)
        record = _to_validated(store, record)
        service.activate(record.transaction_id)
        record = _advance(record, TransactionState.APPLIED)
        store.save(record)

        applied = service.reload(record.transaction_id)
        repeated = service.reload(record.transaction_id)

        assert applied["phase"] == "applied"
        assert applied["active_sha256"] == hashlib.sha256(NEW_RULE).hexdigest()
        assert repeated["idempotent"] is True
        assert reload_calls == ["reload"]

        record = _advance(record, TransactionState.ROLLING_BACK)
        store.save(record)
        service.rollback(record.transaction_id)
        rolled_back = service.reload(record.transaction_id)
        rollback_repeat = service.reload(record.transaction_id)

        assert rolled_back["phase"] == "rollback"
        assert rolled_back["active_sha256"] == hashlib.sha256(OLD_RULE).hexdigest()
        assert rollback_repeat["idempotent"] is True
        assert reload_calls == ["reload", "reload"]
    finally:
        lock.release()


def test_helper_reload_rejects_wrong_state_or_active_hash(tmp_path: Path) -> None:
    _paths, _candidates, store, lock, _calls, service, record = _fixture(tmp_path)
    try:
        with pytest.raises(PrivilegedOperationError, match="not authorized"):
            service.reload(record.transaction_id)

        service.snapshot(record.transaction_id)
        record = _to_validated(store, record)
        service.activate(record.transaction_id)
        record = _advance(record, TransactionState.APPLIED)
        store.save(record)
        service.config.active_rules_path.write_bytes(
            b'alert ip any any -> any any (sid:333; rev:1;)\n'
        )

        with pytest.raises(PrivilegedOperationError, match="active rules hash"):
            service.reload(record.transaction_id)
    finally:
        lock.release()


def test_applied_reload_failure_is_audited_and_has_no_success_receipt(
    tmp_path: Path,
) -> None:
    def fail_reload():
        raise PrivilegedOperationError("socket reload failed")

    paths, _candidates, store, lock, _calls, service, record = _fixture(
        tmp_path, reload_action=fail_reload
    )
    try:
        service.snapshot(record.transaction_id)
        record = _to_validated(store, record)
        service.activate(record.transaction_id)
        record = _advance(record, TransactionState.APPLIED)
        store.save(record)

        with pytest.raises(PrivilegedOperationError, match="socket reload failed"):
            service.reload(record.transaction_id)

        receipt = (
            paths.privileged_transactions_dir
            / record.transaction_id
            / "rules"
            / "reload-applied.json"
        )
        assert not receipt.exists()
    finally:
        lock.release()

    events = [json.loads(line) for line in paths.privileged_audit_file.read_text().splitlines()]
    assert events[-1]["event"] == "privileged.rules_reload_failed"
    assert events[-1]["operation"] == "rules.reload"
