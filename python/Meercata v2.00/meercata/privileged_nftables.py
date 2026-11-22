"""Fixed privileged nftables operations for transactional fail-open IPS."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from meercata.audit import AuditLogger
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import AuditError, NftablesPolicyError, PrivilegedOperationError
from meercata.ips_config import IpsConfig, load_ips_config
from meercata.models import Actor, TransactionRecord, TransactionState, utc_now
from meercata.nftables_policy import NftablesInspection, NftablesPolicy, inspect_owned_table
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within
from meercata.privileged_rules import (
    _atomic_json_write,
    _read_json,
    _require_controller_lock,
    _require_production_configuration_trust,
    _require_production_private_directory,
    _validate_uuid,
)
from meercata.state_store import StateStore

NFT = Path("/usr/sbin/nft")
MAX_POLICY_BYTES = 64 * 1024
_INCIDENT_PATTERN = re.compile(r"INC-[A-Z0-9][A-Z0-9._-]{2,63}\Z")
EMERGENCY_REASONS = frozenset({"listener-loss", "queue-overload", "recovery-failed"})
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]


class NftablesBackend(Protocol):
    def read_table(self) -> Mapping[str, Any] | None: ...
    def check(self, script: Path) -> Mapping[str, Any]: ...
    def apply(self, script: Path) -> Mapping[str, Any]: ...


class NftablesCommandBackend:
    def __init__(self, *, runner_factory: RunnerFactory = CommandRunner) -> None:
        self._runner_factory = runner_factory

    def read_table(self) -> Mapping[str, Any] | None:
        tables = self._run(
            "privileged.nftables.list-tables",
            (str(NFT), "-j", "list", "tables"),
        )
        value = _parse_nft_json(tables.stdout)
        found = []
        for item in value.get("nftables", []):
            if not isinstance(item, dict) or "metainfo" in item:
                continue
            table = item.get("table")
            if not isinstance(table, dict):
                raise PrivilegedOperationError("nftables table inventory is invalid")
            if table.get("family") == "inet" and table.get("name") == "meercata":
                found.append(table)
        if not found:
            return None
        if len(found) != 1:
            raise PrivilegedOperationError("nftables returned duplicate Meercata tables")
        result = self._run(
            "privileged.nftables.list-owned",
            (str(NFT), "-j", "list", "table", "inet", "meercata"),
        )
        return _parse_nft_json(result.stdout)

    def check(self, script: Path) -> Mapping[str, Any]:
        return self._details(
            self._run(
                "privileged.nftables.check",
                (str(NFT), "-c", "-f", str(script)),
            )
        )

    def apply(self, script: Path) -> Mapping[str, Any]:
        return self._details(
            self._run(
                "privileged.nftables.apply",
                (str(NFT), "-f", str(script)),
            )
        )

    def _run(self, command_id: str, argv: tuple[str, ...]):
        result = self._runner_factory(
            {command_id: CommandDefinition.fixed(argv, timeout_seconds=30)}
        ).run(command_id)
        if (
            not result.succeeded
            or result.stdout_truncated
            or result.stderr_truncated
        ):
            raise PrivilegedOperationError(f"{command_id} failed safely")
        return result

    @staticmethod
    def _details(result: Any) -> Mapping[str, Any]:
        return {
            "return_code": result.return_code,
            "duration_seconds": result.duration_seconds,
            "timed_out": result.timed_out,
        }


class PrivilegedNftablesService:
    def __init__(
        self,
        paths: MeercataPaths,
        config: IpsConfig,
        *,
        backend: NftablesBackend | None = None,
        audit: AuditLogger | None = None,
        require_root: bool | None = None,
    ) -> None:
        config.validate()
        self.paths = paths
        self.config = config
        self.store = StateStore(paths)
        self.backend = backend or NftablesCommandBackend()
        self.audit = audit or AuditLogger(paths.privileged_audit_file)
        should_require_root = paths == MeercataPaths.production() if require_root is None else require_root
        if should_require_root and os.geteuid() != 0:
            raise PrivilegedOperationError("production nftables helper requires effective UID 0")

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> "PrivilegedNftablesService":
        _require_production_configuration_trust(paths)
        return cls(paths, load_ips_config(paths))

    @classmethod
    def for_emergency(cls, paths: MeercataPaths) -> "PrivilegedNftablesService":
        """Construct bypass recovery without depending on readable active config."""
        return cls(paths, IpsConfig("lo", 0))

    def snapshot(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.LOCKED)
        actor = Actor.current("privileged-helper")
        self._audit_required("snapshot", "requested", actor, record, {})
        try:
            directory = self._prepare_transaction_dir(transaction_id)
            snapshot_path = directory / "snapshot.json"
            policy_path = directory / "policy.nft"
            if snapshot_path.exists():
                snapshot = self._validated_snapshot(record)
                _require_file_hash(policy_path, snapshot["policy_sha256"])
                self._audit_required(
                    "snapshot", "success", actor, record, {"idempotent": True}
                )
                return {**snapshot, "idempotent": True}

            current = self._inspect_current()
            previous: dict[str, Any] | None = None
            if current is not None:
                self._require_prior_receipt(current)
                previous = _inspection_details(current)
            policy = self._policy(record)
            policy_text = policy.render_apply(replace_owned_table=current is not None)
            policy_hash = _write_private_text(policy_path, policy_text, directory)
            snapshot = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "created_utc": utc_now(),
                "intent": self._intent(),
                "active_existed": current is not None,
                "previous": previous,
                "policy_sha256": policy_hash,
                "candidate": _policy_details(policy),
            }
            _atomic_json_write(snapshot_path, snapshot, directory, mode=0o600)
            self._audit_required(
                "snapshot",
                "success",
                actor,
                record,
                {"active_existed": current is not None, "policy_sha256": policy_hash},
            )
            return snapshot
        except Exception as exc:
            self._audit_required(
                "snapshot", "failure", actor, record, {"error_type": type(exc).__name__}
            )
            raise

    def apply(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.VALIDATED)
        actor = Actor.current("privileged-helper")
        self._audit_required("apply", "requested", actor, record, {})
        try:
            directory = self._transaction_dir(transaction_id)
            snapshot = self._validated_snapshot(record)
            policy_path = directory / "policy.nft"
            _require_file_hash(policy_path, snapshot["policy_sha256"])
            candidate = self._policy(record)
            if _policy_details(candidate) != snapshot["candidate"]:
                raise PrivilegedOperationError("sealed nftables intent changed after snapshot")
            current = self._inspect_current()
            receipt_path = directory / "activation.json"
            receipt = _read_json(receipt_path, "nftables activation receipt") if receipt_path.exists() else None
            if receipt is not None:
                self._validate_activation_receipt(receipt, record, snapshot)
                if current is not None and _matches_policy(current, candidate):
                    if receipt.get("state") == "prepared":
                        receipt = self._finalize_activation(
                            receipt_path, receipt, current, directory
                        )
                    elif receipt.get("semantic_sha256") != current.semantic_sha256:
                        raise PrivilegedOperationError(
                            "applied nftables receipt semantic hash is inconsistent"
                        )
                    result = {**dict(receipt), "idempotent": True}
                    self._audit_required(
                        "apply",
                        "success",
                        actor,
                        record,
                        {"idempotent": True, "semantic_sha256": current.semantic_sha256},
                    )
                    return result
                if receipt.get("state") == "applied":
                    raise PrivilegedOperationError("applied nftables state changed outside the transaction")
            self._require_snapshot_state(current, snapshot)
            prepared = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "state": "prepared",
                "prepared_utc": utc_now(),
                "policy_sha256": snapshot["policy_sha256"],
                "candidate": snapshot["candidate"],
            }
            _atomic_json_write(receipt_path, prepared, directory, mode=0o600)
            validation = dict(self.backend.check(policy_path))
            applied = dict(self.backend.apply(policy_path))
            observed = self._inspect_current()
            if observed is None or not _matches_policy(observed, candidate):
                raise PrivilegedOperationError("applied nftables policy failed exact verification")
            completed = self._finalize_activation(
                receipt_path,
                {**prepared, "validation": validation, "apply": applied},
                observed,
                directory,
            )
            self._audit_required(
                "apply",
                "success",
                actor,
                record,
                {"semantic_sha256": observed.semantic_sha256},
            )
            return completed
        except Exception as exc:
            self._audit_required(
                "apply", "failure", actor, record, {"error_type": type(exc).__name__}
            )
            raise

    def verify(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.APPLIED)
        actor = Actor.current("privileged-helper")
        self._audit_required("verify", "requested", actor, record, {})
        try:
            snapshot = self._validated_snapshot(record)
            receipt = _read_json(
                self._transaction_dir(transaction_id) / "activation.json",
                "nftables activation receipt",
            )
            self._validate_activation_receipt(receipt, record, snapshot, require_applied=True)
            current = self._inspect_current()
            candidate = self._policy(record)
            if current is None or not _matches_policy(current, candidate):
                raise PrivilegedOperationError("nftables verification no longer matches candidate")
            if receipt.get("semantic_sha256") != current.semantic_sha256:
                raise PrivilegedOperationError("nftables activation receipt no longer matches state")
            result = {
                "status": "verified",
                "transaction_id": transaction_id,
                "semantic_sha256": current.semantic_sha256,
                "fail_open": current.fail_open,
            }
            self._audit_required("verify", "success", actor, record, result)
            return result
        except Exception as exc:
            self._audit_required(
                "verify", "failure", actor, record, {"error_type": type(exc).__name__}
            )
            raise

    def rollback(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.ROLLING_BACK)
        actor = Actor.current("privileged-helper")
        self._audit_best_effort("rollback", "requested", actor, record, {})
        try:
            directory = self._transaction_dir(transaction_id)
            snapshot_path = directory / "snapshot.json"
            if not snapshot_path.exists():
                result = {"applied": False, "reason": "snapshot_not_started"}
                self._audit_best_effort("rollback", "success", actor, record, result)
                return result
            snapshot = self._validated_snapshot(record)
            current = self._inspect_current()
            candidate = self._policy(record)
            if self._matches_snapshot(current, snapshot):
                result = {"applied": False, "reason": "already_restored"}
            elif current is not None and _matches_policy(current, candidate):
                rollback_path = directory / "rollback.nft"
                previous = snapshot.get("previous")
                if snapshot["active_existed"]:
                    if not isinstance(previous, dict):
                        raise PrivilegedOperationError("previous nftables snapshot is missing")
                    restored_policy = NftablesPolicy(
                        previous["transaction_id"], previous["interface"], previous["queue"]
                    ).validated()
                    script = restored_policy.render_apply(replace_owned_table=True)
                else:
                    restored_policy = None
                    script = candidate.render_remove()
                script_hash = _write_private_text(rollback_path, script, directory)
                validation = dict(self.backend.check(rollback_path))
                applied = dict(self.backend.apply(rollback_path))
                restored = self._inspect_current()
                if not self._matches_snapshot(restored, snapshot):
                    raise PrivilegedOperationError("nftables rollback failed exact verification")
                result = {
                    "applied": True,
                    "script_sha256": script_hash,
                    "validation": validation,
                    "apply": applied,
                    "restored": None if restored is None else _inspection_details(restored),
                }
            else:
                raise PrivilegedOperationError(
                    "nftables state changed outside this transaction; refusing rollback"
                )
            _atomic_json_write(
                directory / "rollback.json",
                {
                    "schema_version": 1,
                    "transaction_id": transaction_id,
                    "completed_utc": utc_now(),
                    **result,
                },
                directory,
                mode=0o600,
            )
            self._audit_best_effort("rollback", "success", actor, record, result)
            return result
        except Exception as exc:
            self._audit_best_effort(
                "rollback", "failure", actor, record, {"error_type": type(exc).__name__}
            )
            raise

    def emergency_bypass(self, reason: str, incident_id: str) -> dict[str, Any]:
        if reason not in EMERGENCY_REASONS or _INCIDENT_PATTERN.fullmatch(incident_id) is None:
            raise PrivilegedOperationError("emergency bypass reason or incident reference is invalid")
        actor = Actor.current("privileged-helper")
        directory = require_within(
            self.paths.privileged_state_dir / "emergency", self.paths.privileged_state_dir
        )
        ensure_secure_directory(directory, mode=0o700)
        _require_production_private_directory(self.paths, directory)
        receipt_path = directory / f"{incident_id}.json"
        current = self._inspect_current()
        if receipt_path.exists():
            receipt = _read_json(receipt_path, "emergency bypass receipt")
            if (
                receipt.get("schema_version") != 1
                or
                receipt.get("incident_id") != incident_id
                or receipt.get("reason") != reason
                or receipt.get("state") not in {"prepared", "removed"}
            ):
                raise PrivilegedOperationError("emergency bypass receipt cannot be reused")
            if receipt["state"] == "removed":
                if current is not None:
                    raise PrivilegedOperationError("emergency bypass receipt cannot be reused")
                return {**dict(receipt), "idempotent": True}
            previous = receipt.get("previous")
            if previous is not None:
                saved = _inspection_from_details(previous)
                if current is not None and _inspection_details(current) != _inspection_details(saved):
                    raise PrivilegedOperationError("nftables state changed after bypass intent")
            elif current is not None:
                raise PrivilegedOperationError("nftables state appeared after bypass intent")
        else:
            previous = None if current is None else _inspection_details(current)
            prepared = {
                "schema_version": 1,
                "state": "prepared",
                "incident_id": incident_id,
                "reason": reason,
                "previous": previous,
                "prepared_utc": utc_now(),
            }
            _atomic_json_write(receipt_path, prepared, directory, mode=0o600)

        if current is not None:
            policy = NftablesPolicy(
                current.transaction_id, current.interface, current.queue
            ).validated()
            script_path = directory / f"{incident_id}.nft"
            _write_private_text(script_path, policy.render_remove(), directory)
            self.backend.check(script_path)
            self.backend.apply(script_path)
            if self._inspect_current() is not None:
                raise PrivilegedOperationError("emergency bypass did not remove Meercata table")
        result = {
            "schema_version": 1,
            "state": "removed",
            "incident_id": incident_id,
            "reason": reason,
            "removed": previous is not None,
            "previous": previous,
            "completed_utc": utc_now(),
        }
        _atomic_json_write(receipt_path, result, directory, mode=0o600)
        try:
            self.audit.record(
                "privileged.emergency_bypass",
                actor=actor,
                outcome="success",
                transaction_id=None,
                operation="emergency.bypass",
                data={"incident_id": incident_id, "reason": reason, "removed": result["removed"]},
            )
        except AuditError:
            pass
        return result

    def verify_active(self) -> dict[str, Any]:
        """Verify an installed lifecycle policy against its root activation receipt."""
        current = self._inspect_current()
        if current is None:
            return {"status": "inactive", "active": False}
        self._require_prior_receipt(current)
        if (
            current.interface != self.config.interface
            or current.queue != self.config.queue
            or current.fail_open is not True
        ):
            raise PrivilegedOperationError(
                "active nftables policy does not match installed IPS configuration"
            )
        return {
            "status": "active",
            "active": True,
            **_inspection_details(current),
        }

    def deactivate(self, lifecycle_id: str) -> dict[str, Any]:
        """Durably remove a receipted policy for ordered systemd shutdown."""
        _validate_uuid(lifecycle_id, "lifecycle ID")
        actor = Actor.current("ips-bootstrap")
        directory = require_within(
            self.paths.privileged_state_dir / "lifecycle",
            self.paths.privileged_state_dir,
        )
        ensure_secure_directory(directory, mode=0o700)
        _require_production_private_directory(self.paths, directory)
        receipt_path = directory / f"{lifecycle_id}.json"
        script_path = directory / f"{lifecycle_id}.nft"
        current = self._inspect_current()

        if receipt_path.exists():
            receipt = _read_json(receipt_path, "IPS lifecycle deactivation receipt")
            if (
                receipt.get("schema_version") != 1
                or receipt.get("lifecycle_id") != lifecycle_id
                or receipt.get("state") not in {"prepared", "removed"}
            ):
                raise PrivilegedOperationError(
                    "IPS lifecycle deactivation receipt is invalid"
                )
            if receipt["state"] == "removed":
                if current is not None:
                    raise PrivilegedOperationError(
                        "removed IPS lifecycle policy unexpectedly reappeared"
                    )
                return {**dict(receipt), "idempotent": True}
            previous = receipt.get("previous")
            if not isinstance(previous, dict):
                raise PrivilegedOperationError(
                    "prepared IPS lifecycle receipt has no previous policy"
                )
            saved = _inspection_from_details(previous)
            if current is not None and _inspection_details(current) != _inspection_details(saved):
                raise PrivilegedOperationError(
                    "IPS policy changed after lifecycle removal intent"
                )
        else:
            if current is None:
                result = {
                    "schema_version": 1,
                    "lifecycle_id": lifecycle_id,
                    "state": "removed",
                    "removed": False,
                    "previous": None,
                    "completed_utc": utc_now(),
                }
                _atomic_json_write(receipt_path, result, directory, mode=0o600)
                return result
            self._require_prior_receipt(current)
            if (
                current.interface != self.config.interface
                or current.queue != self.config.queue
                or current.fail_open is not True
            ):
                raise PrivilegedOperationError(
                    "active policy does not match lifecycle configuration"
                )
            previous = _inspection_details(current)
            prepared = {
                "schema_version": 1,
                "lifecycle_id": lifecycle_id,
                "state": "prepared",
                "removed": False,
                "previous": previous,
                "prepared_utc": utc_now(),
            }
            _atomic_json_write(receipt_path, prepared, directory, mode=0o600)

        if current is not None:
            policy = NftablesPolicy(
                current.transaction_id,
                current.interface,
                current.queue,
            ).validated()
            script_hash = _write_private_text(
                script_path,
                policy.render_remove(),
                directory,
            )
            validation = dict(self.backend.check(script_path))
            applied = dict(self.backend.apply(script_path))
            if self._inspect_current() is not None:
                raise PrivilegedOperationError(
                    "IPS lifecycle deactivation did not remove Meercata policy"
                )
        else:
            script_hash = None
            validation = None
            applied = None

        result = {
            "schema_version": 1,
            "lifecycle_id": lifecycle_id,
            "state": "removed",
            "removed": previous is not None,
            "previous": previous,
            "script_sha256": script_hash,
            "validation": validation,
            "apply": applied,
            "completed_utc": utc_now(),
        }
        _atomic_json_write(receipt_path, result, directory, mode=0o600)
        try:
            self.audit.record(
                "privileged.ips_deactivate",
                actor=actor,
                outcome="success",
                transaction_id=None,
                operation="ips.deactivate",
                data={"lifecycle_id": lifecycle_id, "removed": result["removed"]},
            )
        except AuditError:
            pass
        return result

    def _authorize(self, transaction_id: str, state: TransactionState) -> TransactionRecord:
        _validate_uuid(transaction_id, "transaction ID")
        _require_controller_lock(self.paths.controller_lock_file, transaction_id)
        record = self.store.load(transaction_id)
        if record.operation != "ips.activate" or record.state != state:
            raise PrivilegedOperationError(
                f"transaction is not authorized for nftables helper state {state.value}"
            )
        if record.redacted_arguments != self._intent():
            raise PrivilegedOperationError("IPS transaction intent does not match fixed configuration")
        return record

    def _policy(self, record: TransactionRecord) -> NftablesPolicy:
        return NftablesPolicy.from_config(record.transaction_id, self.config)

    def _intent(self) -> dict[str, Any]:
        return {
            "interface": self.config.interface,
            "queue": self.config.queue,
            "fail_policy": self.config.fail_policy,
            "traffic_scope": self.config.traffic_scope,
        }

    def _prepare_transaction_dir(self, transaction_id: str) -> Path:
        directory = self._transaction_dir(transaction_id)
        ensure_secure_directory(directory, mode=0o700)
        _require_production_private_directory(self.paths, self.paths.privileged_state_dir)
        _require_production_private_directory(self.paths, directory)
        return directory

    def _transaction_dir(self, transaction_id: str) -> Path:
        _validate_uuid(transaction_id, "transaction ID")
        return require_within(
            self.paths.privileged_transactions_dir / transaction_id / "nftables",
            self.paths.privileged_transactions_dir,
        )

    def _validated_snapshot(self, record: TransactionRecord) -> Mapping[str, Any]:
        snapshot = _read_json(
            self._transaction_dir(record.transaction_id) / "snapshot.json",
            "nftables snapshot",
        )
        if (
            snapshot.get("schema_version") != 1
            or snapshot.get("transaction_id") != record.transaction_id
            or snapshot.get("intent") != self._intent()
            or type(snapshot.get("active_existed")) is not bool
            or not isinstance(snapshot.get("policy_sha256"), str)
            or not isinstance(snapshot.get("candidate"), dict)
        ):
            raise PrivilegedOperationError("nftables snapshot metadata is invalid")
        previous = snapshot.get("previous")
        if snapshot["active_existed"] != isinstance(previous, dict):
            raise PrivilegedOperationError("nftables previous-state metadata is invalid")
        if isinstance(previous, dict):
            _inspection_from_details(previous)
        return snapshot

    def _inspect_current(self) -> NftablesInspection | None:
        value = self.backend.read_table()
        if value is None:
            return None
        try:
            return inspect_owned_table(value)
        except NftablesPolicyError as exc:
            raise PrivilegedOperationError("active Meercata nftables table is not exactly owned") from exc

    def _require_prior_receipt(self, current: NftablesInspection) -> None:
        _validate_uuid(current.transaction_id, "previous owner transaction")
        directory = self._transaction_dir(current.transaction_id)
        try:
            receipt = _read_json(
                directory / "activation.json",
                "previous nftables activation receipt",
            )
        except (OSError, PrivilegedOperationError) as exc:
            raise PrivilegedOperationError(
                "active nftables table lacks a matching root receipt"
            ) from exc
        if (
            receipt.get("schema_version") != 1
            or receipt.get("transaction_id") != current.transaction_id
            or receipt.get("state") != "applied"
            or receipt.get("semantic_sha256") != current.semantic_sha256
        ):
            raise PrivilegedOperationError("active nftables table lacks a matching root receipt")

    def _require_snapshot_state(
        self, current: NftablesInspection | None, snapshot: Mapping[str, Any]
    ) -> None:
        if not self._matches_snapshot(current, snapshot):
            raise PrivilegedOperationError("nftables state changed after snapshot; refusing apply")

    @staticmethod
    def _matches_snapshot(
        current: NftablesInspection | None, snapshot: Mapping[str, Any]
    ) -> bool:
        if not snapshot["active_existed"]:
            return current is None
        return current is not None and _inspection_details(current) == snapshot["previous"]

    def _validate_activation_receipt(
        self,
        receipt: Mapping[str, Any],
        record: TransactionRecord,
        snapshot: Mapping[str, Any],
        *,
        require_applied: bool = False,
    ) -> None:
        allowed_states = {"applied"} if require_applied else {"prepared", "applied"}
        if (
            receipt.get("schema_version") != 1
            or receipt.get("transaction_id") != record.transaction_id
            or receipt.get("state") not in allowed_states
            or receipt.get("policy_sha256") != snapshot["policy_sha256"]
            or receipt.get("candidate") != snapshot["candidate"]
            or (
                receipt.get("state") == "applied"
                and re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("semantic_sha256"))) is None
            )
        ):
            raise PrivilegedOperationError("nftables activation receipt is invalid")

    @staticmethod
    def _finalize_activation(
        path: Path,
        receipt: Mapping[str, Any],
        observed: NftablesInspection,
        directory: Path,
    ) -> dict[str, Any]:
        completed = {
            **dict(receipt),
            "state": "applied",
            "applied_utc": utc_now(),
            "semantic_sha256": observed.semantic_sha256,
        }
        _atomic_json_write(path, completed, directory, mode=0o600)
        return completed

    def _audit_required(
        self,
        action: str,
        outcome: str,
        actor: Actor,
        record: TransactionRecord,
        data: Mapping[str, Any],
    ) -> None:
        self.audit.record(
            f"privileged.nftables_{action}_{outcome}",
            actor=actor,
            outcome=outcome,
            transaction_id=record.transaction_id,
            operation=f"nftables.{action}",
            data=data,
        )

    def _audit_best_effort(
        self,
        action: str,
        outcome: str,
        actor: Actor,
        record: TransactionRecord,
        data: Mapping[str, Any],
    ) -> None:
        try:
            self._audit_required(action, outcome, actor, record, data)
        except AuditError:
            pass


def _parse_nft_json(value: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise PrivilegedOperationError("nftables returned invalid JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("nftables"), list):
        raise PrivilegedOperationError("nftables JSON schema is invalid")
    return parsed


def _policy_details(policy: NftablesPolicy) -> dict[str, Any]:
    policy.validated()
    return {
        "transaction_id": policy.transaction_id,
        "interface": policy.interface,
        "queue": policy.queue,
        "fail_open": True,
    }


def _inspection_details(value: NftablesInspection) -> dict[str, Any]:
    return {
        "transaction_id": value.transaction_id,
        "interface": value.interface,
        "queue": value.queue,
        "fail_open": value.fail_open,
        "semantic_sha256": value.semantic_sha256,
    }


def _inspection_from_details(value: Mapping[str, Any]) -> NftablesInspection:
    try:
        if not isinstance(value.get("semantic_sha256"), str):
            raise TypeError("semantic hash must be a string")
        inspection = NftablesInspection(
            transaction_id=value["transaction_id"],
            interface=value["interface"],
            queue=value["queue"],
            fail_open=value["fail_open"],
            semantic_sha256=value["semantic_sha256"],
        )
        NftablesPolicy(
            inspection.transaction_id,
            inspection.interface,
            inspection.queue,
            inspection.fail_open,
        ).validated()
    except (KeyError, TypeError, NftablesPolicyError) as exc:
        raise PrivilegedOperationError("saved nftables inspection is invalid") from exc
    if re.fullmatch(r"[0-9a-f]{64}", inspection.semantic_sha256) is None:
        raise PrivilegedOperationError("saved nftables semantic hash is invalid")
    return inspection


def _matches_policy(value: NftablesInspection, policy: NftablesPolicy) -> bool:
    return (
        value.transaction_id == policy.transaction_id
        and value.interface == policy.interface
        and value.queue == policy.queue
        and value.fail_open is True
    )


def _write_private_text(path: Path, value: str, root: Path) -> str:
    require_within(path, root)
    payload = value.encode("utf-8")
    if not payload or len(payload) > MAX_POLICY_BYTES:
        raise PrivilegedOperationError("nftables policy text is empty or oversized")
    ensure_secure_directory(root, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=root)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short nftables policy write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise PrivilegedOperationError("cannot persist sealed nftables policy") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def _require_file_hash(path: Path, expected: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise PrivilegedOperationError("sealed nftables policy hash is invalid")
    try:
        metadata = path.lstat()
        if not path.is_file() or path.is_symlink() or metadata.st_size > MAX_POLICY_BYTES:
            raise PrivilegedOperationError("sealed nftables policy file is unsafe")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise PrivilegedOperationError("cannot read sealed nftables policy") from exc
    if actual != expected:
        raise PrivilegedOperationError("sealed nftables policy hash changed")
