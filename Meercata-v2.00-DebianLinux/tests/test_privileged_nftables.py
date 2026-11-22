from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Mapping

import pytest

from meercata.audit import AuditLogger
from meercata.errors import PrivilegedOperationError, TransactionFailed
from meercata.ips_config import IpsConfig
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.nftables_policy import NftablesPolicy, inspect_owned_table
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine


def table_json(policy: NftablesPolicy, *, extra_rule: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {
                "table": {
                    "family": "inet",
                    "name": "meercata",
                    "handle": 1,
                    "comment": policy.owner_comment,
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "meercata",
                    "name": "forward",
                    "handle": 2,
                    "comment": "meercata-managed:v1",
                    "type": "filter",
                    "hook": "forward",
                    "prio": 10,
                    "policy": "accept",
                }
            },
        ]
    }
    for handle, direction, key in ((3, "in", "iifname"), (4, "out", "oifname")):
        value["nftables"].append(
            {
                "rule": {
                    "family": "inet",
                    "table": "meercata",
                    "chain": "forward",
                    "handle": handle,
                    "comment": f"meercata-managed:v1:{direction}",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": key}},
                                "right": policy.interface,
                            }
                        },
                        {"counter": {"packets": 0, "bytes": 0}},
                        {"queue": {"num": policy.queue, "flags": "bypass"}},
                    ],
                }
            }
        )
    if extra_rule:
        value["nftables"].append(
            {
                "rule": {
                    "family": "inet",
                    "table": "meercata",
                    "chain": "forward",
                    "handle": 5,
                    "comment": "foreign",
                    "expr": [
                        {"counter": {"packets": 0, "bytes": 0}},
                        {"accept": None},
                    ],
                }
            }
        )
    return value


class FakeBackend:
    def __init__(self, current: Mapping[str, Any] | None = None) -> None:
        self.current = copy.deepcopy(current)
        self.calls: list[tuple[str, str]] = []
        self.fail_apply = False

    def read_table(self):
        return copy.deepcopy(self.current)

    def check(self, script: Path):
        text = script.read_text()
        self.calls.append(("check", text))
        return {"return_code": 0}

    def apply(self, script: Path):
        text = script.read_text()
        self.calls.append(("apply", text))
        if self.fail_apply:
            raise PrivilegedOperationError("injected apply failure")
        owner = re.search(r"meercata-managed:v1:([0-9a-f-]{36})", text)
        if owner is None:
            if text == "delete table inet meercata\n":
                self.current = None
            else:
                raise AssertionError("unexpected nftables script")
        else:
            interface = re.search(r'iifname "([A-Za-z0-9_.:-]+)"', text)
            queue = re.search(r"queue flags bypass to ([0-9]+)", text)
            assert interface is not None and queue is not None
            policy = NftablesPolicy(owner.group(1), interface.group(1), int(queue.group(1)))
            self.current = table_json(policy)
        return {"return_code": 0}


class DirectActivator:
    def __init__(self, service: PrivilegedNftablesService) -> None:
        self.service = service

    def snapshot(self, record):
        return self.service.snapshot(record.transaction_id)

    def apply(self, record):
        return self.service.apply(record.transaction_id)

    def verify(self, record):
        return self.service.verify(record.transaction_id)

    def rollback(self, record):
        return self.service.rollback(record.transaction_id)


def components(tmp_path: Path, backend: FakeBackend):
    paths = MeercataPaths.isolated(tmp_path)
    config = IpsConfig("eth0", 42)
    service = PrivilegedNftablesService(
        paths,
        config,
        backend=backend,
        require_root=False,
    )
    store = StateStore(paths)
    engine = TransactionEngine(
        store=store,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    workflow = IpsNftablesWorkflow(config, engine, DirectActivator(service))
    return paths, service, store, workflow


def test_privileged_nftables_transaction_seals_applies_and_verifies(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, _service, store, workflow = components(tmp_path, backend)

    record = workflow.activate_policy()

    assert record.state == TransactionState.COMMITTED
    observed = inspect_owned_table(backend.current)
    assert observed.transaction_id == record.transaction_id
    directory = paths.privileged_transactions_dir / record.transaction_id / "nftables"
    assert (directory / "snapshot.json").stat().st_mode & 0o777 == 0o600
    assert (directory / "policy.nft").stat().st_mode & 0o777 == 0o600
    receipt = json.loads((directory / "activation.json").read_text())
    assert receipt["state"] == "applied"
    assert receipt["semantic_sha256"] == observed.semantic_sha256
    assert store.get_last_known_good()["transaction_id"] == record.transaction_id


def test_second_transaction_failure_restores_receipted_previous_policy(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, service, store, first_workflow = components(tmp_path, backend)
    first = first_workflow.activate_policy()

    class FailAfterApply:
        direct = DirectActivator(service)
        snapshot = direct.snapshot
        apply = direct.apply
        rollback = direct.rollback

        def verify(self, record):
            self.direct.verify(record)
            raise PrivilegedOperationError("injected post-apply failure")

    second_engine = TransactionEngine(
        store=store,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    second_workflow = IpsNftablesWorkflow(IpsConfig("eth0", 42), second_engine, FailAfterApply())

    with pytest.raises(TransactionFailed) as failure:
        second_workflow.activate_policy()

    assert store.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert inspect_owned_table(backend.current).transaction_id == first.transaction_id
    rollback = json.loads(
        (
            paths.privileged_transactions_dir
            / failure.value.transaction_id
            / "nftables"
            / "rollback.json"
        ).read_text()
    )
    assert rollback["applied"] is True


def test_apply_failure_before_mutation_preserves_absent_snapshot(tmp_path: Path) -> None:
    backend = FakeBackend()
    _paths, _service, store, workflow = components(tmp_path, backend)
    backend.fail_apply = True

    with pytest.raises(TransactionFailed) as failure:
        workflow.activate_policy()

    assert store.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert backend.current is None


def test_snapshot_refuses_owned_comment_without_root_activation_receipt(tmp_path: Path) -> None:
    foreign = NftablesPolicy("f0000000-0000-0000-0000-000000000018", "eth0", 42)
    backend = FakeBackend(table_json(foreign))
    _paths, _service, store, workflow = components(tmp_path, backend)

    with pytest.raises(TransactionFailed) as failure:
        workflow.activate_policy()

    assert store.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert inspect_owned_table(backend.current).transaction_id == foreign.transaction_id


def test_unknown_drift_after_apply_refuses_rollback_and_requires_recovery(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, service, store, _workflow = components(tmp_path, backend)

    class DriftAfterApply:
        direct = DirectActivator(service)
        snapshot = direct.snapshot
        apply = direct.apply
        rollback = direct.rollback

        def verify(self, _record):
            policy = inspect_owned_table(backend.current)
            backend.current = table_json(
                NftablesPolicy(policy.transaction_id, policy.interface, policy.queue),
                extra_rule=True,
            )
            self.direct.verify(_record)

    engine = TransactionEngine(
        store=store,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    workflow = IpsNftablesWorkflow(IpsConfig("eth0", 42), engine, DriftAfterApply())

    with pytest.raises(TransactionFailed) as failure:
        workflow.activate_policy()

    assert failure.value.rollback_error is not None
    assert store.load(failure.value.transaction_id).state == TransactionState.RECOVERY_FAILED


def test_emergency_bypass_removes_only_exact_owned_table_and_is_idempotent(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, service, _store, workflow = components(tmp_path, backend)
    workflow.activate_policy()

    result = service.emergency_bypass("listener-loss", "INC-NFQ-001")
    repeated = service.emergency_bypass("listener-loss", "INC-NFQ-001")

    assert result["removed"] is True
    assert backend.current is None
    assert repeated["idempotent"] is True
    receipt = paths.privileged_state_dir / "emergency" / "INC-NFQ-001.json"
    assert receipt.stat().st_mode & 0o777 == 0o600


def test_emergency_bypass_recovers_durable_prepared_intent(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, service, _store, workflow = components(tmp_path, backend)
    workflow.activate_policy()
    observed = inspect_owned_table(backend.current)
    directory = paths.privileged_state_dir / "emergency"
    directory.mkdir(parents=True, mode=0o700)
    receipt = directory / "INC-NFQ-INTERRUPTED.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "prepared",
                "incident_id": "INC-NFQ-INTERRUPTED",
                "reason": "listener-loss",
                "previous": {
                    "transaction_id": observed.transaction_id,
                    "interface": observed.interface,
                    "queue": observed.queue,
                    "fail_open": observed.fail_open,
                    "semantic_sha256": observed.semantic_sha256,
                },
                "prepared_utc": "2026-08-22T00:00:00Z",
            }
        )
    )
    receipt.chmod(0o600)

    result = service.emergency_bypass("listener-loss", "INC-NFQ-INTERRUPTED")

    assert result["removed"] is True
    assert result["state"] == "removed"
    assert backend.current is None


@pytest.mark.parametrize(
    ("reason", "incident"),
    [("operator-choice", "INC-NFQ-001"), ("listener-loss", "../../escape")],
)
def test_emergency_bypass_rejects_unapproved_reason_or_incident(
    tmp_path: Path, reason: str, incident: str
) -> None:
    _paths, service, _store, _workflow = components(tmp_path, FakeBackend())

    with pytest.raises(PrivilegedOperationError, match="reason or incident"):
        service.emergency_bypass(reason, incident)


def test_active_policy_verification_and_lifecycle_deactivation_are_receipted(
    tmp_path: Path,
) -> None:
    backend = FakeBackend()
    paths, service, _store, workflow = components(tmp_path, backend)
    transaction = workflow.activate_policy()

    active = service.verify_active()
    assert active["active"] is True
    assert active["transaction_id"] == transaction.transaction_id

    lifecycle_id = "21000000-0000-0000-0000-000000000001"
    removed = service.deactivate(lifecycle_id)
    repeated = service.deactivate(lifecycle_id)

    assert removed["removed"] is True
    assert backend.current is None
    assert repeated["idempotent"] is True
    receipt = paths.privileged_state_dir / "lifecycle" / f"{lifecycle_id}.json"
    assert receipt.stat().st_mode & 0o777 == 0o600
    assert json.loads(receipt.read_text())["state"] == "removed"


def test_lifecycle_deactivation_resumes_prepared_removal(tmp_path: Path) -> None:
    backend = FakeBackend()
    paths, service, _store, workflow = components(tmp_path, backend)
    workflow.activate_policy()
    observed = inspect_owned_table(backend.current)
    lifecycle_id = "21000000-0000-0000-0000-000000000002"
    directory = paths.privileged_state_dir / "lifecycle"
    directory.mkdir(parents=True, mode=0o700)
    receipt = directory / f"{lifecycle_id}.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "lifecycle_id": lifecycle_id,
                "state": "prepared",
                "removed": False,
                "previous": {
                    "transaction_id": observed.transaction_id,
                    "interface": observed.interface,
                    "queue": observed.queue,
                    "fail_open": observed.fail_open,
                    "semantic_sha256": observed.semantic_sha256,
                },
                "prepared_utc": "2026-08-25T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    receipt.chmod(0o600)

    result = service.deactivate(lifecycle_id)

    assert result["removed"] is True
    assert backend.current is None


def test_active_verification_refuses_unreceipted_owned_table(tmp_path: Path) -> None:
    policy = NftablesPolicy("21000000-0000-0000-0000-000000000003", "eth0", 42)
    _paths, service, _store, _workflow = components(
        tmp_path, FakeBackend(table_json(policy))
    )

    with pytest.raises(PrivilegedOperationError, match="receipt"):
        service.verify_active()
