from pathlib import Path

import pytest

from meercata.audit import AuditLogger
from meercata.errors import PrivilegedOperationError, TransactionFailed
from meercata.ips_config import IpsConfig
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.paths import MeercataPaths
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine


class Activator:
    def __init__(self, *, fail_verify: bool = False, fail_rollback: bool = False):
        self.calls: list[str] = []
        self.fail_verify = fail_verify
        self.fail_rollback = fail_rollback

    def snapshot(self, record):
        self.calls.append("snapshot")
        return {"transaction_id": record.transaction_id}

    def apply(self, record):
        self.calls.append("apply")
        return {"transaction_id": record.transaction_id, "state": "applied"}

    def verify(self, record):
        self.calls.append("verify")
        if self.fail_verify:
            raise PrivilegedOperationError("verification failed")
        return {"transaction_id": record.transaction_id, "status": "verified"}

    def rollback(self, record):
        self.calls.append("rollback")
        if self.fail_rollback:
            raise PrivilegedOperationError("rollback failed")
        return {"transaction_id": record.transaction_id, "applied": True}


def workflow(tmp_path: Path, activator: Activator) -> tuple[IpsNftablesWorkflow, StateStore]:
    paths = MeercataPaths.isolated(tmp_path)
    store = StateStore(paths)
    engine = TransactionEngine(
        store=store,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    return IpsNftablesWorkflow(IpsConfig("eth0", 42), engine, activator), store


def test_ips_policy_workflow_commits_with_exact_redacted_intent(tmp_path: Path) -> None:
    activator = Activator()
    instance, store = workflow(tmp_path, activator)

    record = instance.activate_policy()

    assert record.state == TransactionState.COMMITTED
    assert record.operation == "ips.activate"
    assert record.redacted_arguments == {
        "interface": "eth0",
        "queue": 42,
        "fail_policy": "open",
        "traffic_scope": "gateway-forward",
    }
    assert activator.calls == ["snapshot", "apply", "verify"]
    assert store.get_last_known_good()["transaction_id"] == record.transaction_id


def test_ips_policy_workflow_rolls_back_failed_verification(tmp_path: Path) -> None:
    activator = Activator(fail_verify=True)
    instance, store = workflow(tmp_path, activator)

    with pytest.raises(TransactionFailed) as failure:
        instance.activate_policy()

    assert store.load(failure.value.transaction_id).state == TransactionState.ROLLED_BACK
    assert activator.calls == ["snapshot", "apply", "verify", "rollback"]


def test_ips_policy_workflow_records_recovery_failure(tmp_path: Path) -> None:
    activator = Activator(fail_verify=True, fail_rollback=True)
    instance, store = workflow(tmp_path, activator)

    with pytest.raises(TransactionFailed) as failure:
        instance.activate_policy()

    assert failure.value.rollback_error is not None
    assert store.load(failure.value.transaction_id).state == TransactionState.RECOVERY_FAILED
