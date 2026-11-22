"""Durable stage/validate/apply/verify/rollback transaction engine."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from meercata.audit import AuditLogger
from meercata.errors import AuditError, LockHeldError, TransactionFailed
from meercata.locking import ControllerLock
from meercata.models import Actor, TransactionRecord, TransactionState
from meercata.state_store import StateStore

StepAction = Callable[[TransactionRecord], Mapping[str, Any] | None]
TransitionHook = Callable[[TransactionRecord], None]

MAX_STEP_DETAILS_BYTES = 256 * 1024

_FORWARD_TRANSITIONS = {
    TransactionState.LOCKED: TransactionState.SNAPSHOTTED,
    TransactionState.SNAPSHOTTED: TransactionState.STAGED,
    TransactionState.STAGED: TransactionState.VALIDATED,
    TransactionState.VALIDATED: TransactionState.APPLIED,
    TransactionState.APPLIED: TransactionState.VERIFIED,
    TransactionState.VERIFIED: TransactionState.COMMITTED,
}


@dataclass(frozen=True, slots=True)
class TransactionActions:
    snapshot: StepAction
    stage: StepAction
    validate: StepAction
    apply: StepAction
    verify: StepAction
    rollback: StepAction


class TransactionEngine:
    def __init__(
        self,
        *,
        store: StateStore,
        audit: AuditLogger,
        lock: ControllerLock,
        transition_hook: TransitionHook | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.lock = lock
        self._transition_hook = transition_hook

    def execute(
        self,
        operation: str,
        actions: TransactionActions,
        *,
        actor: Actor | None = None,
        redacted_arguments: Mapping[str, Any] | None = None,
    ) -> TransactionRecord:
        actor = actor or Actor.current()
        transaction_id = str(uuid.uuid4())
        self.audit.record(
            "transaction.requested",
            actor=actor,
            outcome="requested",
            transaction_id=transaction_id,
            operation=operation,
            data={"arguments": dict(redacted_arguments or {})},
        )
        try:
            self.lock.acquire(transaction_id)
        except LockHeldError:
            self.audit.record(
                "transaction.lock_rejected",
                actor=actor,
                outcome="rejected",
                transaction_id=transaction_id,
                operation=operation,
                data={"reason": "controller_lock_held"},
            )
            raise

        with self.lock:
            record = TransactionRecord.create_locked(
                operation,
                actor,
                redacted_arguments,
                transaction_id,
            )
            self.store.save(record)
            try:
                self._audit_state(record)
                self._call_hook(record)
                record = self._advance(record, TransactionState.SNAPSHOTTED, actions.snapshot)
                record = self._advance(record, TransactionState.STAGED, actions.stage)
                record = self._advance(record, TransactionState.VALIDATED, actions.validate)
                record = self._advance(record, TransactionState.APPLIED, actions.apply)
                record = self._advance(record, TransactionState.VERIFIED, actions.verify)
                record = self._transition(record, TransactionState.COMMITTED, {})
                self.store.set_last_known_good(record)
                return record
            except Exception as exc:
                latest = self.store.load(transaction_id)
                if latest.state == TransactionState.COMMITTED:
                    raise TransactionFailed(transaction_id, exc) from exc
                self._rollback_after_failure(latest, actions.rollback, exc)
                raise AssertionError("rollback helper must raise")

    def recover(
        self,
        transaction_id: str,
        rollback: StepAction,
        *,
        actor: Actor | None = None,
    ) -> TransactionRecord:
        actor = actor or Actor.current("recovery-cli")
        self.audit.record(
            "transaction.recovery_requested",
            actor=actor,
            outcome="requested",
            transaction_id=transaction_id,
            operation="state.recover",
        )
        self.lock.acquire(transaction_id)
        with self.lock:
            record = self.store.load(transaction_id)
            if record.state.terminal:
                if record.state == TransactionState.COMMITTED:
                    pointer = self.store.get_last_known_good()
                    if pointer is None or pointer.get("transaction_id") != record.transaction_id:
                        self.store.set_last_known_good(record)
                        self.audit.record(
                            "transaction.recovery_repaired",
                            actor=actor,
                            outcome="success",
                            transaction_id=transaction_id,
                            operation=record.operation,
                            data={"repair": "last_known_good_pointer"},
                        )
                        return record
                self.audit.record(
                    "transaction.recovery_skipped",
                    actor=actor,
                    outcome="unchanged",
                    transaction_id=transaction_id,
                    operation=record.operation,
                    data={"state": record.state.value},
                )
                return record
            try:
                if record.state != TransactionState.ROLLING_BACK:
                    record = self._transition(
                        record,
                        TransactionState.ROLLING_BACK,
                        {"recovery": True},
                        audit_required=False,
                    )
                details = _safe_step_details(rollback(record))
                record = self._transition(
                    record,
                    TransactionState.ROLLED_BACK,
                    details,
                    artefact_name="rollback",
                    audit_required=False,
                )
                return record
            except Exception as exc:
                latest = self.store.load(transaction_id)
                failure = _error_record(exc, phase="recovery")
                failed = latest.transitioned(
                    TransactionState.RECOVERY_FAILED,
                    failure,
                    error=failure,
                )
                self.store.save(failed)
                self._best_effort_audit_state(failed)
                raise TransactionFailed(transaction_id, exc, exc) from exc

    def _advance(
        self,
        record: TransactionRecord,
        target: TransactionState,
        action: StepAction,
    ) -> TransactionRecord:
        expected = _FORWARD_TRANSITIONS.get(record.state)
        if expected != target:
            raise ValueError(f"invalid forward transition {record.state.value} -> {target.value}")
        details = _safe_step_details(action(record))
        return self._transition(
            record,
            target,
            details,
            artefact_name=target.value.lower(),
        )

    def _transition(
        self,
        record: TransactionRecord,
        target: TransactionState,
        details: Mapping[str, Any],
        *,
        artefact_name: str | None = None,
        error: Mapping[str, Any] | None = None,
        audit_required: bool = True,
    ) -> TransactionRecord:
        if target == TransactionState.ROLLING_BACK:
            if record.state.terminal:
                raise ValueError("terminal transactions cannot enter rollback")
        elif target in {TransactionState.ROLLED_BACK, TransactionState.RECOVERY_FAILED}:
            if record.state != TransactionState.ROLLING_BACK:
                raise ValueError("rollback terminal state requires ROLLING_BACK")
        elif _FORWARD_TRANSITIONS.get(record.state) != target:
            raise ValueError(f"invalid transition {record.state.value} -> {target.value}")
        updated = record.transitioned(
            target,
            details,
            artefact_name=artefact_name,
            error=error,
        )
        self.store.save(updated)
        if audit_required:
            self._audit_state(updated)
        else:
            self._best_effort_audit_state(updated)
        self._call_hook(updated)
        return updated

    def _rollback_after_failure(
        self,
        record: TransactionRecord,
        rollback: StepAction,
        cause: Exception,
    ) -> None:
        failure = _error_record(cause, phase=record.state.value.lower())
        try:
            rolling_back = self._transition(
                record,
                TransactionState.ROLLING_BACK,
                failure,
                error=failure,
                audit_required=False,
            )
            details = _safe_step_details(rollback(rolling_back))
            self._transition(
                rolling_back,
                TransactionState.ROLLED_BACK,
                details,
                artefact_name="rollback",
                audit_required=False,
            )
        except Exception as rollback_error:
            latest = self.store.load(record.transaction_id)
            failure = _error_record(rollback_error, phase="rollback")
            if latest.state == TransactionState.ROLLING_BACK:
                failed = latest.transitioned(
                    TransactionState.RECOVERY_FAILED,
                    failure,
                    error=failure,
                )
                self.store.save(failed)
                self._best_effort_audit_state(failed)
            raise TransactionFailed(record.transaction_id, cause, rollback_error) from cause
        raise TransactionFailed(record.transaction_id, cause) from cause

    def _audit_state(self, record: TransactionRecord) -> None:
        self.audit.record(
            "transaction.state_changed",
            actor=record.actor,
            outcome="success",
            transaction_id=record.transaction_id,
            operation=record.operation,
            data={"state": record.state.value},
        )

    def _best_effort_audit_state(self, record: TransactionRecord) -> None:
        try:
            self._audit_state(record)
        except AuditError:
            # Rollback and recovery must continue even when the normal audit sink
            # is unavailable. Durable state retains the recovery outcome.
            return

    def _call_hook(self, record: TransactionRecord) -> None:
        if self._transition_hook is not None:
            self._transition_hook(record)


def _safe_step_details(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("transaction step must return a mapping or None")
    details = dict(value)
    payload = json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_STEP_DETAILS_BYTES:
        raise ValueError("transaction step details exceed the size limit")
    return details


def _error_record(error: BaseException, *, phase: str) -> Mapping[str, str]:
    # Exception messages may contain secrets or attacker-controlled input. Keep
    # durable and audit classification useful without persisting the message.
    return {
        "phase": phase,
        "error_type": type(error).__name__,
    }
