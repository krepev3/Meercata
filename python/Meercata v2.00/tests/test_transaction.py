import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from meercata.audit import AuditLogger
from meercata.errors import AuditError, LockHeldError, TransactionFailed
from meercata.locking import ControllerLock
from meercata.models import Actor, TransactionRecord, TransactionState
from meercata.paths import MeercataPaths
from meercata.state_store import StateStore
from meercata.transaction import TransactionActions, TransactionEngine


class SimulatedCrash(BaseException):
    pass


def actor() -> Actor:
    return Actor(uid=1000, gid=1000, invocation_source="test", pid=123)


def action(name: str, calls: list[str]):
    def run(_record: TransactionRecord) -> Mapping[str, Any]:
        calls.append(name)
        return {"step": name}

    return run


def actions(calls: list[str]) -> TransactionActions:
    return TransactionActions(
        snapshot=action("snapshot", calls),
        stage=action("stage", calls),
        validate=action("validate", calls),
        apply=action("apply", calls),
        verify=action("verify", calls),
        rollback=action("rollback", calls),
    )


def components(tmp_path: Path, hook=None):
    paths = MeercataPaths.isolated(tmp_path)
    store = StateStore(paths)
    audit = AuditLogger(paths.audit_file)
    engine = TransactionEngine(
        store=store,
        audit=audit,
        lock=ControllerLock(paths.controller_lock_file),
        transition_hook=hook,
    )
    return paths, store, engine


def test_successful_transaction_commits_in_order(tmp_path: Path) -> None:
    paths, store, engine = components(tmp_path)
    calls: list[str] = []

    result = engine.execute(
        "config.deploy",
        actions(calls),
        actor=actor(),
        redacted_arguments={"config": "candidate.toml", "token": "[redacted]"},
    )

    assert result.state == TransactionState.COMMITTED
    assert calls == ["snapshot", "stage", "validate", "apply", "verify"]
    assert [entry.state for entry in result.history] == [
        TransactionState.REQUESTED,
        TransactionState.LOCKED,
        TransactionState.SNAPSHOTTED,
        TransactionState.STAGED,
        TransactionState.VALIDATED,
        TransactionState.APPLIED,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ]
    assert store.get_last_known_good()["transaction_id"] == result.transaction_id
    events = [json.loads(line) for line in paths.audit_file.read_text().splitlines()]
    assert events[0]["event"] == "transaction.requested"
    assert events[-1]["data"]["state"] == "COMMITTED"
    assert "token-value" not in paths.audit_file.read_text()


def test_failed_validation_rolls_back_and_classifies_error(tmp_path: Path) -> None:
    _paths, store, engine = components(tmp_path)
    calls: list[str] = []

    def fail_validation(_record: TransactionRecord) -> Mapping[str, Any]:
        calls.append("validate")
        raise ValueError("sensitive candidate text")

    transaction_actions = actions(calls)
    transaction_actions = TransactionActions(
        snapshot=transaction_actions.snapshot,
        stage=transaction_actions.stage,
        validate=fail_validation,
        apply=transaction_actions.apply,
        verify=transaction_actions.verify,
        rollback=transaction_actions.rollback,
    )

    with pytest.raises(TransactionFailed) as failure:
        engine.execute("config.deploy", transaction_actions, actor=actor())

    result = store.load(failure.value.transaction_id)
    assert result.state == TransactionState.ROLLED_BACK
    assert calls == ["snapshot", "stage", "validate", "rollback"]
    assert result.errors[-1] == {"phase": "staged", "error_type": "ValueError"}
    assert "sensitive candidate text" not in json.dumps(result.to_dict())


def test_failed_rollback_marks_recovery_failed(tmp_path: Path) -> None:
    _paths, store, engine = components(tmp_path)
    calls: list[str] = []

    def fail_apply(_record: TransactionRecord) -> Mapping[str, Any]:
        raise RuntimeError("apply failed")

    def fail_rollback(_record: TransactionRecord) -> Mapping[str, Any]:
        raise OSError("rollback failed")

    base = actions(calls)
    failing = TransactionActions(
        snapshot=base.snapshot,
        stage=base.stage,
        validate=base.validate,
        apply=fail_apply,
        verify=base.verify,
        rollback=fail_rollback,
    )

    with pytest.raises(TransactionFailed) as failure:
        engine.execute("config.deploy", failing, actor=actor())

    assert failure.value.rollback_error is not None
    assert store.load(failure.value.transaction_id).state == TransactionState.RECOVERY_FAILED


def test_concurrent_transaction_is_rejected_before_actions(tmp_path: Path) -> None:
    paths, _store, engine = components(tmp_path)
    owner = ControllerLock(paths.controller_lock_file)
    owner.acquire("11111111-1111-1111-1111-111111111111")
    calls: list[str] = []
    try:
        with pytest.raises(LockHeldError):
            engine.execute("config.deploy", actions(calls), actor=actor())
    finally:
        owner.release()

    assert calls == []
    audit_text = paths.audit_file.read_text()
    assert "transaction.lock_rejected" in audit_text


def test_initial_audit_failure_blocks_all_actions(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.log_dir.mkdir(parents=True)
    target = tmp_path / "do-not-touch"
    target.write_text("preserve", encoding="utf-8")
    paths.audit_file.symlink_to(target)
    calls: list[str] = []
    engine = TransactionEngine(
        store=StateStore(paths),
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )

    with pytest.raises(AuditError):
        engine.execute("config.deploy", actions(calls), actor=actor())

    assert calls == []
    assert target.read_text(encoding="utf-8") == "preserve"


def test_mid_transaction_audit_failure_triggers_rollback(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    store = StateStore(paths)
    delegate = AuditLogger(paths.audit_file)
    calls: list[str] = []

    class FailingAudit:
        def record(self, event: str, **kwargs: Any) -> None:
            data = kwargs.get("data", {})
            if event == "transaction.state_changed" and data.get("state") == "STAGED":
                raise AuditError("simulated audit sink failure")
            delegate.record(event, **kwargs)

    engine = TransactionEngine(
        store=store,
        audit=FailingAudit(),  # type: ignore[arg-type]
        lock=ControllerLock(paths.controller_lock_file),
    )

    with pytest.raises(TransactionFailed) as failure:
        engine.execute("config.deploy", actions(calls), actor=actor())

    recovered = store.load(failure.value.transaction_id)
    assert recovered.state == TransactionState.ROLLED_BACK
    assert calls == ["snapshot", "stage", "rollback"]
    assert recovered.errors[-1]["error_type"] == "AuditError"


@pytest.mark.parametrize(
    "crash_state",
    [
        TransactionState.LOCKED,
        TransactionState.SNAPSHOTTED,
        TransactionState.STAGED,
        TransactionState.VALIDATED,
        TransactionState.APPLIED,
        TransactionState.VERIFIED,
    ],
)
def test_crash_after_forward_transition_is_recoverable(
    tmp_path: Path,
    crash_state: TransactionState,
) -> None:
    crashed = False

    def crash_hook(record: TransactionRecord) -> None:
        nonlocal crashed
        if record.state == crash_state and not crashed:
            crashed = True
            raise SimulatedCrash(record.state.value)

    _paths, store, engine = components(tmp_path, crash_hook)
    with pytest.raises(SimulatedCrash):
        engine.execute("config.deploy", actions([]), actor=actor())

    [incomplete] = store.list_incomplete()
    recovered = engine.recover(
        incomplete.transaction_id,
        lambda _record: {"restored": True},
        actor=actor(),
    )

    assert recovered.state == TransactionState.ROLLED_BACK
    assert store.list_incomplete() == []


def test_crash_during_rollback_is_recoverable(tmp_path: Path) -> None:
    crashed = False

    def crash_hook(record: TransactionRecord) -> None:
        nonlocal crashed
        if record.state == TransactionState.ROLLING_BACK and not crashed:
            crashed = True
            raise SimulatedCrash("during rollback")

    _paths, store, engine = components(tmp_path, crash_hook)
    base = actions([])

    def fail(_record: TransactionRecord) -> Mapping[str, Any]:
        raise ValueError("force rollback")

    failing = TransactionActions(
        snapshot=base.snapshot,
        stage=fail,
        validate=base.validate,
        apply=base.apply,
        verify=base.verify,
        rollback=base.rollback,
    )
    with pytest.raises(SimulatedCrash):
        engine.execute("config.deploy", failing, actor=actor())

    [incomplete] = store.list_incomplete()
    assert incomplete.state == TransactionState.ROLLING_BACK
    recovered = engine.recover(
        incomplete.transaction_id,
        lambda _record: {"restored": True},
        actor=actor(),
    )
    assert recovered.state == TransactionState.ROLLED_BACK


def test_crash_after_commit_repairs_last_known_good_pointer(tmp_path: Path) -> None:
    crashed = False

    def crash_hook(record: TransactionRecord) -> None:
        nonlocal crashed
        if record.state == TransactionState.COMMITTED and not crashed:
            crashed = True
            raise SimulatedCrash("after commit state")

    _paths, store, engine = components(tmp_path, crash_hook)
    with pytest.raises(SimulatedCrash):
        engine.execute("config.deploy", actions([]), actor=actor())

    [recovery_required] = store.list_recovery_required()
    assert recovery_required.state == TransactionState.COMMITTED
    recovered = engine.recover(
        recovery_required.transaction_id,
        lambda _record: pytest.fail("committed state must not roll back"),
        actor=actor(),
    )

    assert recovered.state == TransactionState.COMMITTED
    assert store.get_last_known_good()["transaction_id"] == recovered.transaction_id
    assert store.list_recovery_required() == []
