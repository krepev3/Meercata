"""Transaction-backed RuleOps promotion orchestration for the future helper."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from meercata.errors import RuleOperationError
from meercata.health_models import HealthStatus
from meercata.models import TransactionRecord
from meercata.pcap_regression import RegressionPackStore
from meercata.rule_parser import compare_rulesets, summarize_ruleset
from meercata.rule_store import RuleCandidateStore
from meercata.ruleops import RuleOpsService
from meercata.transaction import TransactionActions, TransactionEngine


class RuleActivator(Protocol):
    """Phase 4 helper boundary; implementations must not accept arbitrary paths."""

    def snapshot(self, record: TransactionRecord) -> Mapping[str, Any]: ...
    def activate(self, record: TransactionRecord, candidate_id: str) -> Mapping[str, Any]: ...
    def rollback(self, record: TransactionRecord) -> Mapping[str, Any]: ...


class ReloadVerifier(Protocol):
    def reload_and_verify(self, record: TransactionRecord) -> dict[str, Any]: ...


class HealthVerifier(Protocol):
    def collect(self) -> Any: ...


class RulePromotionWorkflow:
    """Coordinates promotion without implementing privileged file mutation."""

    def __init__(
        self,
        ruleops: RuleOpsService,
        engine: TransactionEngine,
        activator: RuleActivator,
        reload_verifier: ReloadVerifier,
        health_verifier: HealthVerifier,
    ) -> None:
        self.ruleops = ruleops
        self.engine = engine
        self.activator = activator
        self.reload_verifier = reload_verifier
        self.health_verifier = health_verifier

    def promote(self, candidate_id: str) -> TransactionRecord:
        manifest = self.ruleops.store.load_manifest(candidate_id)
        if manifest.get("validation", {}).get("status") != "passed":
            raise RuleOperationError("candidate must pass Suricata validation before promotion")
        if (
            manifest.get("status") != "regression_passed"
            or manifest.get("regression", {}).get("status") != "passed"
        ):
            raise RuleOperationError("candidate must pass a PCAP regression pack before promotion")
        regression = manifest["regression"]
        summary_sha256 = manifest.get("summary", {}).get("sha256")
        if regression.get("candidate_sha256") != summary_sha256:
            raise RuleOperationError("PCAP regression evidence does not match the candidate")
        pack_id = regression.get("pack_id")
        if not isinstance(pack_id, str):
            raise RuleOperationError("PCAP regression evidence has no valid pack ID")
        current_pack = RegressionPackStore(self.ruleops.paths).load(pack_id)
        if current_pack.manifest_sha256 != regression.get("pack_manifest_sha256"):
            raise RuleOperationError("PCAP regression pack changed after the recorded run")

        actions = TransactionActions(
            snapshot=lambda record: self.activator.snapshot(record),
            stage=lambda _record: self._confirm_candidate(candidate_id),
            validate=lambda _record: self._confirm_policy(candidate_id),
            apply=lambda record: self.activator.activate(record, candidate_id),
            verify=lambda record: self._verify_runtime(record),
            rollback=lambda record: self._rollback(record),
        )
        return self.engine.execute(
            "rules.promote",
            actions,
            redacted_arguments={"candidate_id": candidate_id},
        )

    def _confirm_candidate(self, candidate_id: str) -> Mapping[str, Any]:
        manifest = self.ruleops.store.load_manifest(candidate_id)
        summary = summarize_ruleset(self.ruleops.store.read_rules(candidate_id))
        expected = manifest.get("summary", {}).get("sha256")
        if summary.sha256 != expected:
            raise RuleOperationError("candidate hash changed after validation")
        return {"candidate_id": candidate_id, "sha256": summary.sha256}

    def _confirm_policy(self, candidate_id: str) -> Mapping[str, Any]:
        candidate = summarize_ruleset(self.ruleops.store.read_rules(candidate_id))
        baseline = self.ruleops._active_summary_or_empty()
        difference = compare_rulesets(
            baseline,
            candidate,
            minimum_rule_count=self.ruleops.config.minimum_rule_count,
            maximum_reduction_percent=self.ruleops.config.maximum_reduction_percent,
        )
        if not difference.policy_allowed:
            raise RuleOperationError("candidate no longer passes promotion policy")
        return difference.to_dict()

    def _verify_runtime(self, record: TransactionRecord) -> Mapping[str, Any]:
        reload_details = self.reload_verifier.reload_and_verify(record)
        health = self.health_verifier.collect()
        if health.status != HealthStatus.HEALTHY:
            raise RuleOperationError(
                f"post-reload health is {getattr(health.status, 'value', health.status)}"
            )
        return {"reload": reload_details, "health": health.status.value}

    def _rollback(self, record: TransactionRecord) -> Mapping[str, Any]:
        restoration = dict(self.activator.rollback(record))
        # Retry must still reload an already-restored file: a previous process
        # may have crashed between filesystem restoration and runtime reload.
        # Only a transaction that never began activation can safely skip it.
        if restoration.get("reason") != "activation_not_started":
            restoration["reload"] = self.reload_verifier.reload_and_verify(record)
        return restoration
