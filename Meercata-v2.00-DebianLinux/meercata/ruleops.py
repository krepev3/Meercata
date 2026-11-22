"""Safe RuleOps staging, validation, status, and policy evaluation."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable

from meercata.audit import AuditLogger
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import RuleOperationError, RuleStoreError
from meercata.models import Actor, CommandResult, utc_now
from meercata.pcap_regression import PcapRegressionRunner
from meercata.paths import MeercataPaths, require_within
from meercata.rule_config import RuleConfig, load_rule_config
from meercata.rule_models import RuleDiff, RuleSetSummary
from meercata.rule_parser import MAX_RULESET_BYTES, compare_rulesets, summarize_ruleset
from meercata.rule_store import RuleCandidateStore

SURICATA = Path("/usr/bin/suricata")
SURICATA_UPDATE = Path("/usr/bin/suricata-update")
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]


class RuleOpsService:
    def __init__(
        self,
        paths: MeercataPaths,
        config: RuleConfig,
        store: RuleCandidateStore,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        audit: AuditLogger | None = None,
    ) -> None:
        self.paths = paths
        self.config = config
        self.store = store
        self._runner_factory = runner_factory
        self.audit = audit or AuditLogger(paths.audit_file)

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> "RuleOpsService":
        return cls(paths, load_rule_config(paths), RuleCandidateStore(paths))

    def status(self) -> dict[str, Any]:
        active: dict[str, Any]
        try:
            summary = summarize_ruleset(_read_active(self.config.active_rules_path))
            active = {"exists": True, **summary.to_dict()}
        except FileNotFoundError:
            active = {"exists": False, "path": str(self.config.active_rules_path)}
        candidates = self.store.list_manifests()
        return {
            "schema_version": 1,
            "source": self.config.source,
            "active": active,
            "candidate_count": len(candidates),
            "latest_candidate": candidates[0] if candidates else None,
            "promotion_available": False,
            "promotion_blocker": "Phase 4 privileged helper is not installed",
        }

    def stage(self) -> dict[str, Any]:
        candidate_id = self.store.new_id()
        actor = Actor.current()
        self.audit.record(
            "rules.stage_requested",
            actor=actor,
            outcome="requested",
            operation="rules.stage",
            data={"candidate_id": candidate_id, "source": self.config.source},
        )
        initial: dict[str, Any] = {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": self.config.source,
            "created_utc": utc_now(),
            "status": "building",
            "summary": {},
            "validation": {"status": "pending"},
            "regression": {"status": "pending"},
        }
        try:
            candidate_dir = self.store.prepare(candidate_id)
            self.store.save_manifest(candidate_id, initial)
            data_dir = require_within(candidate_dir / "data", candidate_dir)
            output_dir = require_within(candidate_dir / "rules", candidate_dir)
            commands = build_stage_commands(data_dir, output_dir, self.config)
            runner = self._runner_factory(commands)
            version = runner.run("rules.update.version")
            _require_success(version, "suricata-update version discovery")
            result = runner.run("rules.update.build")
            _require_success(result, "suricata-update candidate build")
            data = self.store.read_rules(candidate_id)
            summary = summarize_ruleset(data)
            baseline = self._active_summary_or_empty()
            difference = compare_rulesets(
                baseline,
                summary,
                minimum_rule_count=self.config.minimum_rule_count,
                maximum_reduction_percent=self.config.maximum_reduction_percent,
            )
            manifest: dict[str, Any] = {
                **initial,
                "status": "policy_passed" if difference.policy_allowed else "policy_rejected",
                "summary": summary.to_dict(),
                "difference": difference.to_dict(),
                "tools": {
                    "suricata_update": _first_line(version.stdout),
                    "suricata": str(SURICATA),
                },
                "commands": {
                    "update_return_code": result.return_code,
                    "update_duration_seconds": result.duration_seconds,
                    "stdout_truncated": result.stdout_truncated,
                    "stderr_truncated": result.stderr_truncated,
                },
            }
            self.store.save_manifest(candidate_id, manifest)
            self.audit.record(
                "rules.stage_completed",
                actor=actor,
                outcome="success" if difference.policy_allowed else "rejected",
                operation="rules.stage",
                data={
                    "candidate_id": candidate_id,
                    "sha256": summary.sha256,
                    "active_rules": summary.active_rules,
                    "policy_allowed": difference.policy_allowed,
                },
            )
            return manifest
        except Exception as exc:
            try:
                failed = dict(initial)
                failed["status"] = "build_failed"
                failed["failure"] = {"error_type": type(exc).__name__}
                if self.store.candidate_dir(candidate_id).is_dir():
                    self.store.save_manifest(candidate_id, failed)
            finally:
                self.audit.record(
                    "rules.stage_failed",
                    actor=actor,
                    outcome="failure",
                    operation="rules.stage",
                    data={"candidate_id": candidate_id, "error_type": type(exc).__name__},
                )
            if isinstance(exc, RuleStoreError):
                raise RuleOperationError(
                    "suricata-update did not produce a readable candidate"
                ) from exc
            raise

    def diff(self, candidate_id: str) -> RuleDiff:
        candidate = summarize_ruleset(self.store.read_rules(candidate_id))
        return compare_rulesets(
            self._active_summary_or_empty(),
            candidate,
            minimum_rule_count=self.config.minimum_rule_count,
            maximum_reduction_percent=self.config.maximum_reduction_percent,
        )

    def validate(self, candidate_id: str) -> dict[str, Any]:
        actor = Actor.current()
        manifest = self.store.load_manifest(candidate_id)
        self.audit.record(
            "rules.validation_requested",
            actor=actor,
            outcome="requested",
            operation="rules.validate",
            data={"candidate_id": candidate_id, "sha256": manifest.get("summary", {}).get("sha256")},
        )
        try:
            difference = self.diff(candidate_id)
        except Exception as exc:
            self.audit.record(
                "rules.validation_failed",
                actor=actor,
                outcome="failure",
                operation="rules.validate",
                data={"candidate_id": candidate_id, "error_type": type(exc).__name__},
            )
            raise
        if not difference.policy_allowed:
            self.audit.record(
                "rules.validation_rejected",
                actor=actor,
                outcome="rejected",
                operation="rules.validate",
                data={"candidate_id": candidate_id, "reason": "rule_count_policy"},
            )
            raise RuleOperationError("candidate is rejected by rule-count policy")
        candidate_path = require_within(self.store.rules_file(candidate_id), self.store.candidate_dir(candidate_id))
        command = CommandDefinition.fixed(
            (
                str(SURICATA),
                "-T",
                "-c",
                str(self.config.suricata_config_path),
                "-S",
                str(candidate_path),
                "--init-errors-fatal",
                "--set",
                "unix-command.enabled=no",
            ),
            timeout_seconds=self.config.validation_timeout_seconds,
            working_directory=self.store.candidate_dir(candidate_id),
        )
        try:
            result = self._runner_factory({"rules.validate": command}).run("rules.validate")
        except Exception as exc:
            self.audit.record(
                "rules.validation_failed",
                actor=actor,
                outcome="failure",
                operation="rules.validate",
                data={"candidate_id": candidate_id, "error_type": type(exc).__name__},
            )
            raise
        validation = {
            "status": "passed" if result.return_code == 0 and not result.timed_out else "failed",
            "return_code": result.return_code,
            "duration_seconds": result.duration_seconds,
            "timed_out": result.timed_out,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "validated_utc": utc_now(),
        }
        manifest["validation"] = validation
        manifest["regression"] = {"status": "pending"}
        manifest["status"] = "validated" if validation["status"] == "passed" else "validation_failed"
        self.store.save_manifest(candidate_id, manifest)
        self.audit.record(
            "rules.validation_completed",
            actor=actor,
            outcome="success" if validation["status"] == "passed" else "failure",
            operation="rules.validate",
            data={
                "candidate_id": candidate_id,
                "return_code": result.return_code,
                "timed_out": result.timed_out,
            },
        )
        if validation["status"] != "passed":
            raise RuleOperationError("Suricata rejected the candidate ruleset")
        return manifest

    def regress(self, candidate_id: str, pack_id: str) -> dict[str, Any]:
        actor = Actor.current()
        manifest = self.store.load_manifest(candidate_id)
        audited_pack_id = pack_id[:64]
        self.audit.record(
            "rules.regression_requested",
            actor=actor,
            outcome="requested",
            operation="rules.regress",
            data={"candidate_id": candidate_id, "pack_id": audited_pack_id},
        )
        validation = manifest.get("validation")
        if not isinstance(validation, dict) or validation.get("status") != "passed":
            self.audit.record(
                "rules.regression_rejected",
                actor=actor,
                outcome="rejected",
                operation="rules.regress",
                data={"candidate_id": candidate_id, "reason": "validation_required"},
            )
            raise RuleOperationError("candidate must pass Suricata validation before regression")
        current = summarize_ruleset(self.store.read_rules(candidate_id))
        if current.sha256 != manifest.get("summary", {}).get("sha256"):
            self.audit.record(
                "rules.regression_rejected",
                actor=actor,
                outcome="rejected",
                operation="rules.regress",
                data={"candidate_id": candidate_id, "reason": "candidate_hash_changed"},
            )
            raise RuleOperationError("candidate hash changed after validation")
        try:
            regression = PcapRegressionRunner(
                self.paths,
                self.config,
                self.store,
                runner_factory=self._runner_factory,
            ).run(candidate_id, pack_id)
        except Exception as exc:
            manifest["regression"] = {
                "status": "failed",
                "pack_id": audited_pack_id,
                "completed_utc": utc_now(),
                "error_type": type(exc).__name__,
            }
            manifest["status"] = "regression_failed"
            self.store.save_manifest(candidate_id, manifest)
            self.audit.record(
                "rules.regression_failed",
                actor=actor,
                outcome="failure",
                operation="rules.regress",
                data={
                    "candidate_id": candidate_id,
                    "pack_id": audited_pack_id,
                    "error_type": type(exc).__name__,
                },
            )
            raise
        manifest["regression"] = regression
        manifest["status"] = (
            "regression_passed" if regression["status"] == "passed" else "regression_failed"
        )
        self.store.save_manifest(candidate_id, manifest)
        self.audit.record(
            "rules.regression_completed",
            actor=actor,
            outcome="success" if regression["status"] == "passed" else "failure",
            operation="rules.regress",
            data={
                "candidate_id": candidate_id,
                "pack_id": pack_id,
                "pack_manifest_sha256": regression["pack_manifest_sha256"],
                "passed_cases": regression["passed_cases"],
                "failed_cases": regression["failed_cases"],
            },
        )
        if regression["status"] != "passed":
            raise RuleOperationError("candidate failed the PCAP regression pack")
        return manifest

    def promote(self, _candidate_id: str) -> None:
        raise RuleOperationError(
            "rule promotion is disabled until the Phase 4 privileged helper is installed"
        )

    def _active_summary_or_empty(self) -> RuleSetSummary:
        try:
            return summarize_ruleset(_read_active(self.config.active_rules_path))
        except FileNotFoundError:
            return summarize_ruleset(b"")


def build_stage_commands(
    data_dir: Path,
    output_dir: Path,
    config: RuleConfig,
) -> dict[str, CommandDefinition]:
    if config.source != "et/open":
        raise RuleOperationError("rule source is not allowlisted")
    return {
        "rules.update.version": CommandDefinition.fixed(
            (str(SURICATA_UPDATE), "--version"), timeout_seconds=10
        ),
        "rules.update.build": CommandDefinition.fixed(
            (
                str(SURICATA_UPDATE),
                "update",
                "-D",
                str(data_dir),
                "-o",
                str(output_dir),
                "--suricata-conf",
                str(config.suricata_config_path),
                "--suricata",
                str(SURICATA),
                "--no-reload",
                "--no-test",
                "--fail",
            ),
            timeout_seconds=config.update_timeout_seconds,
            working_directory=data_dir.parent,
        ),
    }


def _read_active(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuleOperationError(f"cannot read active ruleset: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuleOperationError("active ruleset is not a regular file")
        if metadata.st_size > MAX_RULESET_BYTES:
            raise RuleOperationError("active ruleset exceeds 128 MiB")
        chunks: list[bytes] = []
        remaining = MAX_RULESET_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > MAX_RULESET_BYTES:
        raise RuleOperationError("active ruleset exceeds 128 MiB")
    return data


def _require_success(result: CommandResult, description: str) -> None:
    if result.return_code != 0 or result.timed_out:
        reason = "timed out" if result.timed_out else f"exited {result.return_code}"
        raise RuleOperationError(f"{description} {reason}")


def _first_line(value: str) -> str:
    line = value.strip().splitlines()
    return line[0][:256] if line else "unknown"
