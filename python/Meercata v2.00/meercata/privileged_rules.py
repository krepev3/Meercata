"""Fixed privileged RuleOps filesystem operations.

The public methods accept only a transaction UUID. Candidate and destination
paths are derived from validated state and fixed configuration.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from meercata.audit import AuditLogger
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import AuditError, PrivilegedOperationError
from meercata.models import Actor, CommandResult, TransactionRecord, TransactionState, utc_now
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within
from meercata.pcap_regression import PcapRegressionRunner, RegressionPackStore
from meercata.rule_config import RuleConfig, load_rule_config
from meercata.rule_store import RuleCandidateStore
from meercata.rule_reload import RuleReloadController, RuleReloadSocketClient
from meercata.state_store import StateStore

MAX_RULE_BYTES = 128 * 1024 * 1024
MAX_HELPER_JSON_BYTES = 1024 * 1024
SURICATA = Path("/usr/bin/suricata")
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]


class PrivilegedRuleService:
    def __init__(
        self,
        paths: MeercataPaths,
        config: RuleConfig,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        audit: AuditLogger | None = None,
        require_root: bool | None = None,
        socket_path: Path | None = None,
        socket_timeout_seconds: float = 2.0,
        reload_action: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self.paths = paths
        self.config = config
        self.store = StateStore(paths)
        self.candidates = RuleCandidateStore(paths)
        self.packs = RegressionPackStore(paths)
        self._runner_factory = runner_factory
        self.audit = audit or AuditLogger(paths.privileged_audit_file)
        self.socket_path = socket_path or (
            paths.suricata_run_dir / "suricata-command.socket"
        )
        self.socket_timeout_seconds = socket_timeout_seconds
        self._reload_action = reload_action or self._live_reload
        should_require_root = paths == MeercataPaths.production() if require_root is None else require_root
        if should_require_root and os.geteuid() != 0:
            raise PrivilegedOperationError("production helper requires effective UID 0")

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> "PrivilegedRuleService":
        _require_production_configuration_trust(paths)
        from meercata.health_config import load_health_config

        health = load_health_config(paths)
        return cls(
            paths,
            load_rule_config(paths),
            socket_path=health.socket_path,
            socket_timeout_seconds=health.thresholds.socket_timeout_seconds,
        )

    def snapshot(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.LOCKED)
        candidate_id = self._candidate_id(record)
        actor = Actor.current("privileged-helper")
        self._audit_required(
            "privileged.rules_snapshot_requested",
            actor,
            record,
            {"candidate_id": candidate_id},
        )
        try:
            artefact_dir = self._prepare_artefact_dir(transaction_id)
            metadata_path = artefact_dir / "snapshot.json"
            if metadata_path.exists():
                metadata = _read_json(metadata_path, "rule snapshot metadata")
                self._validate_snapshot_metadata(metadata, record, candidate_id)
                if _hash_regular(artefact_dir / "candidate.rules") != metadata["candidate_sha256"]:
                    raise PrivilegedOperationError("sealed candidate changed after snapshot")
                if metadata["active_existed"] and (
                    _hash_regular(artefact_dir / "active.rules")
                    != metadata.get("active_sha256")
                ):
                    raise PrivilegedOperationError("saved active rule snapshot is corrupt")
                return dict(metadata)

            candidate_manifest = self.candidates.load_manifest(candidate_id)
            expected_candidate_hash = _validated_candidate_hash(candidate_manifest)
            _verify_regression_evidence(self.packs, candidate_manifest)
            sealed = _copy_regular_atomic(
                self.candidates.rules_file(candidate_id),
                artefact_dir / "candidate.rules",
                expected_sha256=expected_candidate_hash,
                mode=0o600,
            )
            validation = self._strict_validate(
                artefact_dir / "candidate.rules", artefact_dir
            )
            pack_id = candidate_manifest["regression"]["pack_id"]
            regression = PcapRegressionRunner(
                self.paths,
                self.config,
                self.candidates,
                runner_factory=self._runner_factory,
            ).run_rule_file(
                artefact_dir / "candidate.rules",
                artefact_dir / "regression",
                pack_id,
            )
            if regression["status"] != "passed":
                raise PrivilegedOperationError(
                    "sealed candidate failed privileged PCAP regression"
                )
            _atomic_json_write(
                artefact_dir / "qualification.json",
                regression,
                artefact_dir,
                mode=0o600,
            )

            active_path = self.config.active_rules_path
            _require_production_activation_trust(self.paths, active_path)
            try:
                active = _copy_regular_atomic(
                    active_path,
                    artefact_dir / "active.rules",
                    expected_sha256=None,
                    mode=0o600,
                )
                active_existed = True
            except FileNotFoundError:
                active = {"sha256": None, "size_bytes": 0}
                active_existed = False

            metadata = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "candidate_id": candidate_id,
                "created_utc": utc_now(),
                "candidate_sha256": sealed["sha256"],
                "candidate_size_bytes": sealed["size_bytes"],
                "active_existed": active_existed,
                "active_sha256": active["sha256"],
                "active_size_bytes": active["size_bytes"],
                "privileged_validation": validation,
                "privileged_regression": {
                    "status": regression["status"],
                    "pack_id": regression["pack_id"],
                    "pack_manifest_sha256": regression["pack_manifest_sha256"],
                    "candidate_sha256": regression["candidate_sha256"],
                    "passed_cases": regression["passed_cases"],
                    "failed_cases": regression["failed_cases"],
                },
            }
            _atomic_json_write(metadata_path, metadata, artefact_dir, mode=0o600)
            self._audit_required(
                "privileged.rules_snapshot_completed",
                actor,
                record,
                {
                    "candidate_id": candidate_id,
                    "candidate_sha256": sealed["sha256"],
                    "active_existed": active_existed,
                    "active_sha256": active["sha256"],
                },
            )
            return metadata
        except Exception as exc:
            self._audit_required(
                "privileged.rules_snapshot_failed",
                actor,
                record,
                {"error_type": type(exc).__name__},
            )
            raise

    def activate(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.VALIDATED)
        candidate_id = self._candidate_id(record)
        actor = Actor.current("privileged-helper")
        self._audit_required(
            "privileged.rules_activate_requested",
            actor,
            record,
            {"candidate_id": candidate_id},
        )
        try:
            artefact_dir = self._artefact_dir(transaction_id)
            snapshot = _read_json(artefact_dir / "snapshot.json", "rule snapshot metadata")
            self._validate_snapshot_metadata(snapshot, record, candidate_id)
            sealed_path = artefact_dir / "candidate.rules"
            sealed_hash = _hash_regular(sealed_path)
            if sealed_hash != snapshot["candidate_sha256"]:
                raise PrivilegedOperationError("sealed candidate hash does not match snapshot metadata")

            receipt_path = artefact_dir / "activation.json"
            if receipt_path.exists():
                receipt = _read_json(receipt_path, "rule activation receipt")
                if (
                    receipt.get("transaction_id") == transaction_id
                    and receipt.get("candidate_sha256") == sealed_hash
                    and receipt.get("state") == "applied"
                    and _current_hash(self.config.active_rules_path) == sealed_hash
                ):
                    return {**receipt, "idempotent": True}
                raise PrivilegedOperationError("existing activation receipt is inconsistent")

            validation = self._strict_validate(sealed_path, artefact_dir)
            _require_production_activation_trust(
                self.paths, self.config.active_rules_path
            )
            _require_active_matches_snapshot(self.config.active_rules_path, snapshot)
            intent = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "candidate_id": candidate_id,
                "candidate_sha256": sealed_hash,
                "state": "prepared",
                "prepared_utc": utc_now(),
                "validation": validation,
            }
            _atomic_json_write(receipt_path, intent, artefact_dir, mode=0o600)
            activated = _replace_from_regular(sealed_path, self.config.active_rules_path)
            if activated["sha256"] != sealed_hash:
                raise PrivilegedOperationError("activated rules hash does not match sealed candidate")
            receipt = {
                **intent,
                "state": "applied",
                "applied_utc": utc_now(),
                "active_sha256": activated["sha256"],
                "active_size_bytes": activated["size_bytes"],
            }
            _atomic_json_write(receipt_path, receipt, artefact_dir, mode=0o600)
            self._audit_required(
                "privileged.rules_activate_completed",
                actor,
                record,
                {"candidate_id": candidate_id, "active_sha256": sealed_hash},
            )
            return receipt
        except Exception as exc:
            self._audit_required(
                "privileged.rules_activate_failed",
                actor,
                record,
                {"error_type": type(exc).__name__},
            )
            raise

    def rollback(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize(transaction_id, TransactionState.ROLLING_BACK)
        actor = Actor.current("privileged-helper")
        self._audit_best_effort(
            "privileged.rules_rollback_requested", actor, record, {}
        )
        try:
            artefact_dir = self._artefact_dir(transaction_id)
            receipt_path = artefact_dir / "activation.json"
            if not receipt_path.exists():
                result = {"applied": False, "reason": "activation_not_started"}
                self._audit_best_effort(
                    "privileged.rules_rollback_completed", actor, record, result
                )
                return result
            receipt = _read_json(receipt_path, "rule activation receipt")
            snapshot = _read_json(artefact_dir / "snapshot.json", "rule snapshot metadata")
            self._validate_snapshot_metadata(
                snapshot,
                record,
                self._candidate_id(record),
                verify_regression=False,
            )
            if receipt.get("transaction_id") != transaction_id:
                raise PrivilegedOperationError("activation receipt transaction does not match")
            candidate_hash = snapshot["candidate_sha256"]
            _require_production_activation_trust(
                self.paths, self.config.active_rules_path
            )
            current_hash = _current_hash(self.config.active_rules_path)
            snapshot_hash = snapshot.get("active_sha256")

            if snapshot["active_existed"]:
                if current_hash == snapshot_hash:
                    result = {"applied": False, "reason": "already_restored", "restored_sha256": snapshot_hash}
                elif current_hash == candidate_hash:
                    source = artefact_dir / "active.rules"
                    if _hash_regular(source) != snapshot_hash:
                        raise PrivilegedOperationError("rule snapshot hash is corrupt")
                    restored = _replace_from_regular(source, self.config.active_rules_path)
                    result = {"applied": True, "restored_sha256": restored["sha256"]}
                else:
                    raise PrivilegedOperationError(
                        "active rules changed outside this transaction; refusing rollback overwrite"
                    )
            else:
                if current_hash is None:
                    result = {"applied": False, "reason": "already_absent", "restored_sha256": None}
                elif current_hash == candidate_hash:
                    _unlink_regular(self.config.active_rules_path)
                    result = {"applied": True, "restored_sha256": None}
                else:
                    raise PrivilegedOperationError(
                        "active rules changed outside this transaction; refusing rollback removal"
                    )
            rollback_receipt = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "completed_utc": utc_now(),
                **result,
            }
            _atomic_json_write(
                artefact_dir / "rollback.json", rollback_receipt, artefact_dir, mode=0o600
            )
            self._audit_best_effort(
                "privileged.rules_rollback_completed", actor, record, result
            )
            return result
        except Exception as exc:
            self._audit_best_effort(
                "privileged.rules_rollback_failed",
                actor,
                record,
                {"error_type": type(exc).__name__},
            )
            raise

    def reload(self, transaction_id: str) -> dict[str, Any]:
        record = self._authorize_any(
            transaction_id,
            {TransactionState.APPLIED, TransactionState.ROLLING_BACK},
        )
        actor = Actor.current("privileged-helper")
        rollback = record.state == TransactionState.ROLLING_BACK
        audit = self._audit_best_effort if rollback else self._audit_required
        audit("privileged.rules_reload_requested", actor, record, {})
        try:
            artefact_dir = self._artefact_dir(transaction_id)
            snapshot = _read_json(
                artefact_dir / "snapshot.json", "rule snapshot metadata"
            )
            self._validate_snapshot_metadata(
                snapshot,
                record,
                self._candidate_id(record),
                verify_regression=not rollback,
            )
            if rollback:
                rollback_receipt = _read_json(
                    artefact_dir / "rollback.json", "rule rollback receipt"
                )
                if rollback_receipt.get("transaction_id") != transaction_id:
                    raise PrivilegedOperationError(
                        "rollback receipt transaction does not match"
                    )
                expected_hash = rollback_receipt.get("restored_sha256")
                receipt_path = artefact_dir / "reload-rollback.json"
                phase = "rollback"
            else:
                activation = _read_json(
                    artefact_dir / "activation.json", "rule activation receipt"
                )
                if (
                    activation.get("transaction_id") != transaction_id
                    or activation.get("state") != "applied"
                ):
                    raise PrivilegedOperationError("activation receipt is invalid")
                expected_hash = activation.get("active_sha256")
                receipt_path = artefact_dir / "reload-applied.json"
                phase = "applied"
            if _current_hash(self.config.active_rules_path) != expected_hash:
                raise PrivilegedOperationError(
                    "active rules hash does not match the authorized reload state"
                )
            if receipt_path.exists():
                receipt = _read_json(receipt_path, "rule reload receipt")
                if (
                    receipt.get("transaction_id") == transaction_id
                    and receipt.get("active_sha256") == expected_hash
                    and receipt.get("phase") == phase
                    and receipt.get("status") == "verified"
                ):
                    return {**receipt, "idempotent": True}
                raise PrivilegedOperationError("existing reload receipt is inconsistent")
            details = dict(self._reload_action())
            receipt = {
                "schema_version": 1,
                "transaction_id": transaction_id,
                "phase": phase,
                "status": "verified",
                "active_sha256": expected_hash,
                "completed_utc": utc_now(),
                "details": details,
            }
            _atomic_json_write(receipt_path, receipt, artefact_dir, mode=0o600)
            audit(
                "privileged.rules_reload_completed",
                actor,
                record,
                {"phase": phase, "active_sha256": expected_hash},
            )
            return receipt
        except Exception as exc:
            audit(
                "privileged.rules_reload_failed",
                actor,
                record,
                {"error_type": type(exc).__name__},
            )
            raise

    def _authorize(
        self,
        transaction_id: str,
        expected_state: TransactionState,
    ) -> TransactionRecord:
        _validate_uuid(transaction_id, "transaction ID")
        _require_controller_lock(self.paths.controller_lock_file, transaction_id)
        record = self.store.load(transaction_id)
        if record.operation != "rules.promote" or record.state != expected_state:
            raise PrivilegedOperationError(
                f"transaction is not authorized for helper state {expected_state.value}"
            )
        return record

    def _authorize_any(
        self,
        transaction_id: str,
        expected_states: set[TransactionState],
    ) -> TransactionRecord:
        _validate_uuid(transaction_id, "transaction ID")
        _require_controller_lock(self.paths.controller_lock_file, transaction_id)
        record = self.store.load(transaction_id)
        if record.operation != "rules.promote" or record.state not in expected_states:
            expected = ", ".join(sorted(state.value for state in expected_states))
            raise PrivilegedOperationError(
                f"transaction is not authorized for helper states: {expected}"
            )
        return record

    def _live_reload(self) -> Mapping[str, Any]:
        _require_production_socket_trust(self.paths, self.socket_path)
        controller = RuleReloadController(
            lambda: RuleReloadSocketClient(
                self.socket_path, self.socket_timeout_seconds
            ),
            timeout_seconds=self.config.reload_timeout_seconds,
            poll_seconds=self.config.reload_poll_seconds,
        )
        return controller.reload_and_verify()

    def _candidate_id(self, record: TransactionRecord) -> str:
        candidate_id = record.redacted_arguments.get("candidate_id")
        _validate_uuid(candidate_id, "candidate ID")
        return str(candidate_id)

    def _prepare_artefact_dir(self, transaction_id: str) -> Path:
        directory = self._artefact_dir(transaction_id)
        ensure_secure_directory(directory, mode=0o700)
        _require_production_private_directory(self.paths, self.paths.privileged_state_dir)
        _require_production_private_directory(self.paths, directory)
        return directory

    def _artefact_dir(self, transaction_id: str) -> Path:
        return require_within(
            self.paths.privileged_transactions_dir / transaction_id / "rules",
            self.paths.privileged_transactions_dir,
        )

    def _validate_snapshot_metadata(
        self,
        metadata: Mapping[str, Any],
        record: TransactionRecord,
        candidate_id: str,
        *,
        verify_regression: bool = True,
    ) -> None:
        if (
            metadata.get("schema_version") != 1
            or metadata.get("transaction_id") != record.transaction_id
            or metadata.get("candidate_id") != candidate_id
            or not isinstance(metadata.get("candidate_sha256"), str)
            or type(metadata.get("active_existed")) is not bool
        ):
            raise PrivilegedOperationError("rule snapshot metadata is invalid")
        if verify_regression:
            regression = metadata.get("privileged_regression")
            if (
                not isinstance(regression, dict)
                or regression.get("status") != "passed"
                or regression.get("candidate_sha256") != metadata.get("candidate_sha256")
                or not isinstance(regression.get("pack_id"), str)
            ):
                raise PrivilegedOperationError(
                    "privileged regression qualification is invalid"
                )
            pack = self.packs.load(regression["pack_id"])
            if pack.manifest_sha256 != regression.get("pack_manifest_sha256"):
                raise PrivilegedOperationError(
                    "regression pack changed after privileged qualification"
                )

    def _strict_validate(self, sealed_path: Path, artefact_dir: Path) -> dict[str, Any]:
        command = CommandDefinition.fixed(
            (
                str(SURICATA),
                "-T",
                "-c",
                str(self.config.suricata_config_path),
                "-S",
                str(sealed_path),
                "--init-errors-fatal",
                "--set",
                "unix-command.enabled=no",
            ),
            timeout_seconds=self.config.validation_timeout_seconds,
            working_directory=artefact_dir,
        )
        result = self._runner_factory({"privileged.rules.validate": command}).run(
            "privileged.rules.validate"
        )
        if not result.succeeded:
            raise PrivilegedOperationError("sealed candidate failed privileged validation")
        return _bounded_command_details(result)

    def _audit_required(
        self,
        event: str,
        actor: Actor,
        record: TransactionRecord,
        data: Mapping[str, Any],
    ) -> None:
        outcome = "requested" if event.endswith("requested") else (
            "failure" if event.endswith("failed") else "success"
        )
        operation = next(
            (
                f"rules.{name}"
                for name in ("snapshot", "activate", "rollback", "reload")
                if f"rules_{name}_" in event
            ),
            "rules.unknown",
        )
        self.audit.record(
            event,
            actor=actor,
            outcome=outcome,
            transaction_id=record.transaction_id,
            operation=operation,
            data=data,
        )

    def _audit_best_effort(
        self,
        event: str,
        actor: Actor,
        record: TransactionRecord,
        data: Mapping[str, Any],
    ) -> None:
        try:
            self._audit_required(event, actor, record, data)
        except AuditError:
            return


def _validated_candidate_hash(manifest: Mapping[str, Any]) -> str:
    if (
        manifest.get("status") != "regression_passed"
        or not isinstance(manifest.get("validation"), dict)
        or manifest["validation"].get("status") != "passed"
        or not isinstance(manifest.get("regression"), dict)
        or manifest["regression"].get("status") != "passed"
    ):
        raise PrivilegedOperationError("candidate lacks validation and regression approval")
    value = manifest.get("summary", {}).get("sha256")
    if not isinstance(value, str) or len(value) != 64:
        raise PrivilegedOperationError("candidate manifest SHA-256 is invalid")
    if manifest["regression"].get("candidate_sha256") != value:
        raise PrivilegedOperationError("regression evidence does not match candidate SHA-256")
    return value


def _verify_regression_evidence(
    packs: RegressionPackStore,
    manifest: Mapping[str, Any],
) -> None:
    regression = manifest["regression"]
    pack_id = regression.get("pack_id")
    if not isinstance(pack_id, str):
        raise PrivilegedOperationError("regression evidence pack ID is invalid")
    pack = packs.load(pack_id)
    if pack.manifest_sha256 != regression.get("pack_manifest_sha256"):
        raise PrivilegedOperationError("regression pack changed after approval")


def _require_controller_lock(path: Path, transaction_id: str) -> None:
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot verify controller lock: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            raise PrivilegedOperationError("controller lock metadata is invalid")
        raw = os.read(descriptor, 4097)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrivilegedOperationError("controller lock metadata is invalid") from exc
        if not isinstance(value, dict) or value.get("transaction_id") != transaction_id:
            raise PrivilegedOperationError("controller lock belongs to another transaction")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return
            raise PrivilegedOperationError(f"cannot verify controller lock ownership: {exc}") from exc
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            raise PrivilegedOperationError("controller lock is not held")
    finally:
        os.close(descriptor)


def _copy_regular_atomic(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str | None,
    mode: int,
) -> dict[str, Any]:
    if destination.exists():
        digest = _hash_regular(destination)
        if expected_sha256 is not None and digest != expected_sha256:
            raise PrivilegedOperationError("existing sealed artefact hash does not match")
        return {"sha256": digest, "size_bytes": destination.stat().st_size}
    source_fd = _open_regular_read(source)
    temporary: Path | None = None
    try:
        source_meta = os.fstat(source_fd)
        if source_meta.st_size > MAX_RULE_BYTES:
            raise PrivilegedOperationError("rule artefact exceeds 128 MiB")
        ensure_secure_directory(destination.parent, mode=0o700)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(name)
        digest = hashlib.sha256()
        size = 0
        try:
            os.fchmod(descriptor, mode)
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RULE_BYTES:
                    raise PrivilegedOperationError("rule artefact exceeds 128 MiB")
                digest.update(chunk)
                _write_all(descriptor, chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        actual = digest.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise PrivilegedOperationError("rule artefact SHA-256 does not match approval")
        os.replace(temporary, destination)
        temporary = None
        _fsync_directory(destination.parent)
        return {"sha256": actual, "size_bytes": size}
    finally:
        os.close(source_fd)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _replace_from_regular(source: Path, destination: Path) -> dict[str, Any]:
    ensure_secure_directory(destination.parent, mode=0o750)
    source_fd = _open_regular_read(source)
    temporary: Path | None = None
    try:
        source_meta = os.fstat(source_fd)
        if source_meta.st_size > MAX_RULE_BYTES:
            raise PrivilegedOperationError("rule artefact exceeds 128 MiB")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(name)
        digest = hashlib.sha256()
        size = 0
        try:
            os.fchmod(descriptor, 0o640)
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                _write_all(descriptor, chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
        temporary = None
        _fsync_directory(destination.parent)
        return {"sha256": digest.hexdigest(), "size_bytes": size}
    finally:
        os.close(source_fd)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _require_active_matches_snapshot(path: Path, snapshot: Mapping[str, Any]) -> None:
    current = _current_hash(path)
    expected = snapshot.get("active_sha256") if snapshot.get("active_existed") else None
    if current != expected:
        raise PrivilegedOperationError(
            "active rules changed after snapshot; refusing activation overwrite"
        )


def _current_hash(path: Path) -> str | None:
    try:
        return _hash_regular(path)
    except FileNotFoundError:
        return None


def _hash_regular(path: Path) -> str:
    descriptor = _open_regular_read(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > MAX_RULE_BYTES:
            raise PrivilegedOperationError("rule artefact exceeds 128 MiB")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RULE_BYTES:
                raise PrivilegedOperationError("rule artefact exceeds 128 MiB")
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _open_regular_read(path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot open fixed rule artefact: {exc}") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise PrivilegedOperationError("fixed rule artefact is not a regular file")
    return descriptor


def _unlink_regular(path: Path) -> None:
    descriptor = _open_regular_read(path)
    os.close(descriptor)
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot remove activated rules: {exc}") from exc


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    descriptor = _open_regular_read(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > MAX_HELPER_JSON_BYTES:
            raise PrivilegedOperationError(f"{label} exceeds 1 MiB")
        raw = os.read(descriptor, MAX_HELPER_JSON_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrivilegedOperationError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise PrivilegedOperationError(f"{label} must be an object")
    return value


def _atomic_json_write(
    path: Path,
    value: Mapping[str, Any],
    allowed_root: Path,
    *,
    mode: int,
) -> None:
    require_within(path, allowed_root)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_HELPER_JSON_BYTES:
        raise PrivilegedOperationError("helper receipt exceeds 1 MiB")
    ensure_secure_directory(allowed_root, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=allowed_root)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(allowed_root)
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot persist helper receipt: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _bounded_command_details(result: CommandResult) -> dict[str, Any]:
    return {
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "duration_seconds": result.duration_seconds,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_uuid(value: Any, label: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise PrivilegedOperationError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise PrivilegedOperationError(f"{label} must be a canonical UUID")


def _require_production_configuration_trust(paths: MeercataPaths) -> None:
    if paths != MeercataPaths.production():
        return
    for path in (paths.controller_config_file, paths.suricata_config_file):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise PrivilegedOperationError(f"cannot inspect production configuration: {exc}") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise PrivilegedOperationError(
                "production configuration must be root-owned and not group/world writable"
            )


def _require_production_private_directory(paths: MeercataPaths, path: Path) -> None:
    if paths != MeercataPaths.production():
        return
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise PrivilegedOperationError("privileged state directory must be root-owned mode 0700")


def _require_production_activation_trust(paths: MeercataPaths, path: Path) -> None:
    if paths != MeercataPaths.production():
        return
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot inspect active rules directory: {exc}") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
    ):
        raise PrivilegedOperationError(
            "active rules directory must be root-owned and not group/world writable"
        )
    try:
        active = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot inspect active rules file: {exc}") from exc
    if (
        not stat.S_ISREG(active.st_mode)
        or active.st_uid != 0
        or active.st_mode & 0o022
    ):
        raise PrivilegedOperationError(
            "active rules file must be root-owned and not group/world writable"
        )


def _require_production_socket_trust(paths: MeercataPaths, path: Path) -> None:
    if paths != MeercataPaths.production():
        return
    try:
        parent = path.parent.lstat()
        target = path.lstat()
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot inspect Suricata socket: {exc}") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
        or not stat.S_ISSOCK(target.st_mode)
        or target.st_uid != 0
        or target.st_mode & 0o002
    ):
        raise PrivilegedOperationError(
            "Suricata socket must be root-owned and not world writable"
        )
