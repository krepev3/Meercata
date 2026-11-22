"""Typed transaction, actor, and command result models."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

from meercata.errors import InvalidModelError

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def local_now() -> str:
    return datetime.now().astimezone().isoformat()


class TransactionState(StrEnum):
    REQUESTED = "REQUESTED"
    LOCKED = "LOCKED"
    SNAPSHOTTED = "SNAPSHOTTED"
    STAGED = "STAGED"
    VALIDATED = "VALIDATED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    COMMITTED = "COMMITTED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    RECOVERY_FAILED = "RECOVERY_FAILED"

    @property
    def terminal(self) -> bool:
        return self in {
            TransactionState.COMMITTED,
            TransactionState.ROLLED_BACK,
            TransactionState.RECOVERY_FAILED,
        }


@dataclass(frozen=True, slots=True)
class Actor:
    uid: int
    gid: int
    invocation_source: str
    pid: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in (self.uid, self.gid, self.pid)):
            raise InvalidModelError("actor uid, gid, and pid must be non-negative integers")
        if not isinstance(self.invocation_source, str) or not self.invocation_source:
            raise InvalidModelError("actor invocation_source cannot be empty")
        if len(self.invocation_source) > 64:
            raise InvalidModelError("actor invocation_source exceeds 64 characters")

    @classmethod
    def current(cls, invocation_source: str = "cli") -> Actor:
        if not invocation_source or len(invocation_source) > 64:
            raise InvalidModelError("invocation_source must contain 1 to 64 characters")
        return cls(
            uid=os.getuid(),
            gid=os.getgid(),
            invocation_source=invocation_source,
            pid=os.getpid(),
        )

    def to_dict(self) -> dict[str, int | str]:
        return {
            "uid": self.uid,
            "gid": self.gid,
            "invocation_source": self.invocation_source,
            "pid": self.pid,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Actor:
        try:
            return cls(
                uid=int(value["uid"]),
                gid=int(value["gid"]),
                invocation_source=str(value["invocation_source"]),
                pid=int(value["pid"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidModelError("invalid actor record") from exc


@dataclass(frozen=True, slots=True)
class StateHistoryEntry:
    state: TransactionState
    utc_timestamp: str
    local_timestamp: str
    details: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        state: TransactionState,
        details: Mapping[str, Any] | None = None,
    ) -> StateHistoryEntry:
        return cls(state, utc_now(), local_now(), dict(details or {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "utc_timestamp": self.utc_timestamp,
            "local_timestamp": self.local_timestamp,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StateHistoryEntry:
        try:
            details = value.get("details", {})
            if not isinstance(details, dict):
                raise TypeError("details must be an object")
            return cls(
                state=TransactionState(str(value["state"])),
                utc_timestamp=str(value["utc_timestamp"]),
                local_timestamp=str(value["local_timestamp"]),
                details=details,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidModelError("invalid state history entry") from exc


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    transaction_id: str
    operation: str
    actor: Actor
    redacted_arguments: Mapping[str, Any]
    state: TransactionState
    created_utc: str
    created_local: str
    updated_utc: str
    history: tuple[StateHistoryEntry, ...]
    artefacts: Mapping[str, Any] = field(default_factory=dict)
    errors: tuple[Mapping[str, Any], ...] = ()
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def create_locked(
        cls,
        operation: str,
        actor: Actor,
        redacted_arguments: Mapping[str, Any] | None = None,
        transaction_id: str | None = None,
    ) -> TransactionRecord:
        transaction_id = transaction_id or str(uuid.uuid4())
        _validate_transaction_id(transaction_id)
        _validate_operation(operation)
        created_utc = utc_now()
        created_local = local_now()
        history = (
            StateHistoryEntry(
                TransactionState.REQUESTED,
                created_utc,
                created_local,
                {},
            ),
            StateHistoryEntry.create(TransactionState.LOCKED),
        )
        return cls(
            transaction_id=transaction_id,
            operation=operation,
            actor=actor,
            redacted_arguments=dict(redacted_arguments or {}),
            state=TransactionState.LOCKED,
            created_utc=created_utc,
            created_local=created_local,
            updated_utc=history[-1].utc_timestamp,
            history=history,
        )

    def transitioned(
        self,
        state: TransactionState,
        details: Mapping[str, Any] | None = None,
        *,
        artefact_name: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> TransactionRecord:
        entry = StateHistoryEntry.create(state, details)
        artefacts = dict(self.artefacts)
        if artefact_name is not None:
            artefacts[artefact_name] = dict(details or {})
        errors = self.errors
        if error is not None:
            errors = (*errors, dict(error))
        return replace(
            self,
            state=state,
            updated_utc=entry.utc_timestamp,
            history=(*self.history, entry),
            artefacts=artefacts,
            errors=errors,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "transaction_id": self.transaction_id,
            "operation": self.operation,
            "actor": self.actor.to_dict(),
            "redacted_arguments": dict(self.redacted_arguments),
            "state": self.state.value,
            "created_utc": self.created_utc,
            "created_local": self.created_local,
            "updated_utc": self.updated_utc,
            "history": [entry.to_dict() for entry in self.history],
            "artefacts": dict(self.artefacts),
            "errors": [dict(error) for error in self.errors],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> TransactionRecord:
        try:
            if int(value["schema_version"]) != SCHEMA_VERSION:
                raise InvalidModelError("unsupported transaction schema version")
            transaction_id = str(value["transaction_id"])
            operation = str(value["operation"])
            _validate_transaction_id(transaction_id)
            _validate_operation(operation)
            redacted_arguments = value.get("redacted_arguments", {})
            artefacts = value.get("artefacts", {})
            errors = value.get("errors", [])
            history = value["history"]
            if not isinstance(redacted_arguments, dict):
                raise TypeError("redacted_arguments must be an object")
            if not isinstance(artefacts, dict):
                raise TypeError("artefacts must be an object")
            if not isinstance(errors, list) or not all(isinstance(item, dict) for item in errors):
                raise TypeError("errors must be an array of objects")
            if not isinstance(history, list) or not history:
                raise TypeError("history must be a non-empty array")
            record = cls(
                transaction_id=transaction_id,
                operation=operation,
                actor=Actor.from_dict(value["actor"]),
                redacted_arguments=redacted_arguments,
                state=TransactionState(str(value["state"])),
                created_utc=str(value["created_utc"]),
                created_local=str(value["created_local"]),
                updated_utc=str(value["updated_utc"]),
                history=tuple(StateHistoryEntry.from_dict(item) for item in history),
                artefacts=artefacts,
                errors=tuple(errors),
                schema_version=SCHEMA_VERSION,
            )
            if record.history[-1].state != record.state:
                raise InvalidModelError("current state does not match state history")
            return record
        except InvalidModelError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidModelError("invalid transaction record") from exc


@dataclass(frozen=True, slots=True)
class CommandResult:
    command_id: str
    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    started_utc: str
    duration_seconds: float

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "started_utc": self.started_utc,
            "duration_seconds": self.duration_seconds,
            "succeeded": self.succeeded,
        }


def _validate_transaction_id(value: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise InvalidModelError("transaction_id must be a UUID") from exc
    if str(parsed) != value:
        raise InvalidModelError("transaction_id must use canonical UUID form")


def _validate_operation(value: str) -> None:
    if not value or len(value) > 128:
        raise InvalidModelError("operation must contain 1 to 128 characters")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    if any(character not in allowed for character in value):
        raise InvalidModelError("operation contains unsupported characters")
