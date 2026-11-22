from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from meercata.audit import AuditLogger
from meercata.errors import RuleOperationError, TransactionFailed
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.paths import MeercataPaths
from meercata.rule_config import RuleConfig
from meercata.rule_parser import summarize_ruleset
from meercata.rule_promotion import RulePromotionWorkflow
from meercata.rule_store import RuleCandidateStore
from meercata.ruleops import RuleOpsService
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine


RULE = b'alert ip any any -> any any (sid:1; rev:1;)\n'


class Activator:
    def __init__(self, *, fail_rollback=False, rollback_result=None):
        self.calls = []
        self.fail_rollback = fail_rollback
        self.rollback_result = rollback_result

    def snapshot(self, _record):
        self.calls.append("snapshot")
        return {"active_sha256": "old"}

    def activate(self, _record, candidate_id):
        self.calls.append(f"activate:{candidate_id}")
        return {"active_sha256": "new"}

    def rollback(self, _record):
        self.calls.append("rollback")
        if self.fail_rollback:
            raise OSError("restore failed")
        return self.rollback_result or {"applied": True, "restored_sha256": "old"}


class Reload:
    def __init__(self, *, fail_first=False):
        self.calls = 0
        self.fail_first = fail_first

    def reload_and_verify(self, _record):
        self.calls += 1
        if self.fail_first and self.calls == 1:
            raise RuleOperationError("reload failed")
        return {"failed_rules": 0, "generation": self.calls}


class Health:
    def __init__(self, status):
        self.report = HealthReport("ids", (HealthCheck("runtime", status, status.value),))

    def collect(self):
        return self.report


def _workflow(tmp_path: Path, activator, reload, health):
    paths = MeercataPaths.isolated(tmp_path)
    config = RuleConfig(
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
    store = RuleCandidateStore(paths)
    candidate_id = store.new_id()
    candidate = store.prepare(candidate_id)
    (candidate / "rules" / "suricata.rules").write_bytes(RULE)
    summary = summarize_ruleset(RULE)
    pack_dir = paths.regression_packs_dir / "test-pack"
    pack_dir.mkdir(parents=True)
    pcap = b"fixed test pcap"
    (pack_dir / "test.pcap").write_bytes(pcap)
    pack_manifest = {
        "schema_version": 1,
        "pack_id": "test-pack",
        "description": "promotion workflow evidence pack",
        "cases": [
            {
                "case_id": "test",
                "pcap_file": "test.pcap",
                "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
                "expected_alerts": [{"gid": 1, "sid": 1}],
                "forbidden_alerts": [],
            }
        ],
    }
    pack_bytes = json.dumps(pack_manifest).encode()
    (pack_dir / "manifest.json").write_bytes(pack_bytes)
    store.save_manifest(
        candidate_id,
        {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": "et/open",
            "created_utc": "2026-08-10T00:00:00Z",
            "status": "regression_passed",
            "summary": summary.to_dict(),
            "validation": {"status": "passed"},
            "regression": {
                "status": "passed",
                "pack_id": "test-pack",
                "candidate_sha256": summary.sha256,
                "pack_manifest_sha256": hashlib.sha256(pack_bytes).hexdigest(),
            },
        },
    )
    state = StateStore(paths)
    engine = TransactionEngine(
        store=state,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    service = RuleOpsService(paths, config, store)
    return candidate_id, state, RulePromotionWorkflow(service, engine, activator, reload, health)


def test_promotion_workflow_commits_after_reload_and_health(tmp_path: Path) -> None:
    activator = Activator()
    reload = Reload()
    candidate_id, state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.HEALTHY)
    )

    record = workflow.promote(candidate_id)

    assert record.state == TransactionState.COMMITTED
    assert activator.calls == ["snapshot", f"activate:{candidate_id}"]
    assert reload.calls == 1
    assert state.get_last_known_good()["transaction_id"] == record.transaction_id


def test_unhealthy_promotion_rolls_back_and_reloads_previous_rules(tmp_path: Path) -> None:
    activator = Activator()
    reload = Reload()
    candidate_id, state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.CRITICAL)
    )

    with pytest.raises(TransactionFailed) as failure:
        workflow.promote(candidate_id)

    assert state.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert activator.calls[-1] == "rollback"
    assert reload.calls == 2


def test_reload_failure_and_rollback_failure_requires_recovery(tmp_path: Path) -> None:
    activator = Activator(fail_rollback=True)
    reload = Reload(fail_first=True)
    candidate_id, state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.HEALTHY)
    )

    with pytest.raises(TransactionFailed) as failure:
        workflow.promote(candidate_id)

    assert failure.value.rollback_error is not None
    assert state.load(failure.value.transaction_id).state == TransactionState.RECOVERY_FAILED


def test_rollback_retry_reloads_already_restored_rules(tmp_path: Path) -> None:
    activator = Activator(
        rollback_result={
            "applied": False,
            "reason": "already_restored",
            "restored_sha256": "old",
        }
    )
    reload = Reload()
    candidate_id, state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.CRITICAL)
    )

    with pytest.raises(TransactionFailed) as failure:
        workflow.promote(candidate_id)

    assert state.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert reload.calls == 2


def test_promotion_rejects_changed_candidate_before_apply(tmp_path: Path) -> None:
    activator = Activator()
    reload = Reload()
    candidate_id, state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.HEALTHY)
    )
    workflow.ruleops.store.rules_file(candidate_id).write_bytes(
        b'alert ip any any -> any any (sid:2; rev:1;)\n'
    )

    with pytest.raises(TransactionFailed) as failure:
        workflow.promote(candidate_id)

    assert state.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert not any(call.startswith("activate:") for call in activator.calls)


def test_promotion_rejects_missing_or_stale_regression_evidence(tmp_path: Path) -> None:
    activator = Activator()
    reload = Reload()
    candidate_id, _state, workflow = _workflow(
        tmp_path, activator, reload, Health(HealthStatus.HEALTHY)
    )
    manifest = workflow.ruleops.store.load_manifest(candidate_id)
    evidence = dict(manifest["regression"])
    manifest["status"] = "validated"
    manifest["regression"] = {"status": "pending"}
    workflow.ruleops.store.save_manifest(candidate_id, manifest)
    with pytest.raises(RuleOperationError, match="must pass a PCAP"):
        workflow.promote(candidate_id)

    manifest["status"] = "regression_passed"
    manifest["regression"] = evidence
    manifest["regression"]["candidate_sha256"] = "0" * 64
    workflow.ruleops.store.save_manifest(candidate_id, manifest)

    with pytest.raises(RuleOperationError, match="does not match"):
        workflow.promote(candidate_id)

    manifest["regression"]["candidate_sha256"] = manifest["summary"]["sha256"]
    manifest["regression"]["pack_manifest_sha256"] = "0" * 64
    workflow.ruleops.store.save_manifest(candidate_id, manifest)
    with pytest.raises(RuleOperationError, match="pack changed"):
        workflow.promote(candidate_id)
