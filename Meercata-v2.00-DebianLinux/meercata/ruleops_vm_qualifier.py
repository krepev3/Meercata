"""Qualify live RuleOps activation and rollback in a disposable systemd VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.audit import AuditLogger
from meercata.errors import MeercataError, QualificationError, TransactionFailed
from meercata.health import HealthService
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.locking import ControllerLock
from meercata.models import TransactionRecord, TransactionState, utc_now
from meercata.paths import MeercataPaths
from meercata.pcap_regression import RegressionPackStore
from meercata.privileged_client import PrivilegedRuleActivator
from meercata.rule_parser import compare_rulesets, summarize_ruleset
from meercata.rule_promotion import RulePromotionWorkflow
from meercata.rule_store import RuleCandidateStore
from meercata.ruleops import RuleOpsService
from meercata.state_store import StateStore
from meercata.systemd_vm_qualifier import (
    CLOUD_IMAGE_SHA512,
    _require_disposable_vm,
    _verify_packages as _verify_readiness_packages,
)
from meercata.transaction import TransactionEngine

CONFIRMATION = "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 LIVE RULEOPS"
EXPECTED_MEERCATA_PACKAGE = "2.0.0~dev16-1"
MAX_AUDIT_BYTES = 4 * 1024 * 1024
QUALIFICATION_PACK_ID = "dev13-ruleops-v1"
QUALIFICATION_OVERLAYS = {
    "success": (
        "qualification-a.rules",
        "ded3c6a061527f3eee9130072c8425c9d9e2f5c7c98f5db205565795616cc999",
    ),
    "rollback": (
        "qualification-b.rules",
        "c63746a5ceb9cac54fda8417ddbd26ddf22828cccff8a29cc124b4e93631f66f",
    ),
}


class RuleOpsVmCandidatePreparer:
    """Create two fixture candidates through the real validation and regression gates."""

    def __init__(
        self,
        *,
        confirmation: str,
        image_sha512: str,
        paths: MeercataPaths | None = None,
    ) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512
        self.paths = paths or MeercataPaths.production()

    def prepare(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
        )
        packages = _verify_ruleops_packages()
        service = RuleOpsService.from_paths(self.paths)
        active = _read_bounded_regular(
            service.config.active_rules_path,
            128 * 1024 * 1024,
            require_root=True,
        )
        overlays = _load_qualification_overlays(self.paths)
        candidates = _build_fixture_rulesets(active, overlays)
        prepared = {
            label: _prepare_fixture_candidate(service, label, payload)
            for label, payload in candidates.items()
        }
        if prepared["success"]["sha256"] == prepared["rollback"]["sha256"]:
            raise QualificationError("prepared qualification candidate hashes must differ")
        return {
            "schema_version": 1,
            "status": "ruleops-vm-candidates-prepared",
            "project_version": __version__,
            "platform": platform,
            "packages": packages,
            "pack_id": QUALIFICATION_PACK_ID,
            "success_candidate": prepared["success"],
            "rollback_candidate": prepared["rollback"],
        }


class RuleOpsVmQualifier:
    """Run one committed promotion and one forced post-reload rollback."""

    def __init__(
        self,
        *,
        confirmation: str,
        image_sha512: str,
        success_candidate_id: str,
        rollback_candidate_id: str,
        paths: MeercataPaths | None = None,
    ) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512
        self.success_candidate_id = success_candidate_id
        self.rollback_candidate_id = rollback_candidate_id
        self.paths = paths or MeercataPaths.production()

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
        )
        packages = _verify_ruleops_packages()
        candidates = _approved_candidates(
            self.paths,
            self.success_candidate_id,
            self.rollback_candidate_id,
        )
        initial_hash = _hash_regular(candidates["active_rules_path"])
        if initial_hash in {
            candidates["success_sha256"],
            candidates["rollback_sha256"],
        }:
            raise QualificationError(
                "qualification candidates must differ from the initial active ruleset"
            )

        normal_workflow = _workflow(self.paths, force_post_reload_failure=False)
        committed = normal_workflow.promote(self.success_candidate_id)
        _require_state(committed, TransactionState.COMMITTED)
        if _hash_regular(candidates["active_rules_path"]) != candidates["success_sha256"]:
            raise QualificationError("committed candidate is not the active ruleset")
        committed_receipts = _verify_receipts(
            self.paths,
            committed,
            expected_files={"snapshot.json", "activation.json", "reload-applied.json"},
        )

        rollback_workflow = _workflow(self.paths, force_post_reload_failure=True)
        try:
            rollback_workflow.promote(self.rollback_candidate_id)
        except TransactionFailed as exc:
            if exc.rollback_error is not None:
                raise QualificationError("injected failure did not roll back cleanly") from exc
            rolled_back = StateStore(self.paths).load(exc.transaction_id)
        else:
            raise QualificationError("injected post-reload failure unexpectedly committed")
        _require_state(rolled_back, TransactionState.ROLLED_BACK)
        if _hash_regular(candidates["active_rules_path"]) != candidates["success_sha256"]:
            raise QualificationError("rollback did not restore the committed ruleset")
        rollback_receipts = _verify_receipts(
            self.paths,
            rolled_back,
            expected_files={
                "snapshot.json",
                "activation.json",
                "reload-applied.json",
                "rollback.json",
                "reload-rollback.json",
            },
        )
        health = HealthService.from_paths(self.paths).collect()
        if health.status != HealthStatus.HEALTHY:
            raise QualificationError("runtime health is not healthy after rollback")
        last_known_good = StateStore(self.paths).get_last_known_good()
        if (
            not isinstance(last_known_good, Mapping)
            or last_known_good.get("transaction_id") != committed.transaction_id
        ):
            raise QualificationError("rollback changed the committed last-known-good pointer")
        audit = _verify_audit(self.paths, {committed.transaction_id, rolled_back.transaction_id})

        checks = [
            _passed("platform.vm", platform),
            _passed("packages.installed", packages),
            _passed("candidates.approved", candidates),
            _passed(
                "promotion.committed",
                _transaction_details(committed, committed_receipts),
            ),
            _passed(
                "rollback.injected",
                _transaction_details(rolled_back, rollback_receipts),
            ),
            _passed(
                "runtime.restored",
                {
                    "active_sha256": candidates["success_sha256"],
                    "health_status": health.status.value,
                    "health_checks": len(health.checks),
                    "last_known_good_transaction_id": committed.transaction_id,
                    **audit,
                },
            ),
        ]
        return {
            "schema_version": 1,
            "status": "ruleops-vm-qualified",
            "project_version": __version__,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "candidate staging and the reviewed PCAP corpus were provisioned before this bounded qualifier run",
                "the unsigned Meercata artifact was installed directly in the disposable VM",
                "only IDS rule activation and rollback were exercised; IPS and NFQUEUE were not",
                "crash, reboot, disk-full, retention, repository signing, removal, and purge were not exercised",
            ],
        }


class _ForcedPostReloadFailure:
    """Require real healthy state, then force the transaction rollback branch."""

    def __init__(self, health: HealthService) -> None:
        self.health = health

    def collect(self) -> HealthReport:
        report = self.health.collect()
        if report.status != HealthStatus.HEALTHY:
            return report
        return HealthReport(
            report.mode,
            (
                HealthCheck(
                    "qualification_injected_failure",
                    HealthStatus.CRITICAL,
                    "dev13 forced post-reload rollback injection",
                ),
            ),
        )


def _workflow(paths: MeercataPaths, *, force_post_reload_failure: bool) -> RulePromotionWorkflow:
    ruleops = RuleOpsService.from_paths(paths)
    state = StateStore(paths)
    engine = TransactionEngine(
        store=state,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )
    helper = PrivilegedRuleActivator(paths)
    health: Any = HealthService.from_paths(paths)
    if force_post_reload_failure:
        health = _ForcedPostReloadFailure(health)
    return RulePromotionWorkflow(ruleops, engine, helper, helper, health)


def _verify_ruleops_packages() -> dict[str, str]:
    observed = _verify_readiness_packages()
    if observed.get("meercata") != EXPECTED_MEERCATA_PACKAGE:
        raise QualificationError("installed Meercata package is not the dev13 artifact")
    return observed


def _load_qualification_overlays(paths: MeercataPaths) -> dict[str, bytes]:
    pack_dir = paths.regression_packs_dir / QUALIFICATION_PACK_ID
    RegressionPackStore(paths).load(QUALIFICATION_PACK_ID)
    overlays: dict[str, bytes] = {}
    for label, (name, expected_sha256) in QUALIFICATION_OVERLAYS.items():
        payload = _read_bounded_regular(
            pack_dir / name,
            64 * 1024,
            require_root=True,
        )
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise QualificationError("qualification rule overlay hash is not approved")
        summary = summarize_ruleset(payload)
        if (
            summary.active_rules != 1
            or len(summary.signatures) != 1
            or summary.signatures[0].key != (1, 9900013)
            or summary.signatures[0].action != "alert"
        ):
            raise QualificationError("qualification rule overlay is not alert-only")
        overlays[label] = payload
    return overlays


def _build_fixture_rulesets(
    active: bytes,
    overlays: Mapping[str, bytes],
) -> dict[str, bytes]:
    active_summary = summarize_ruleset(active)
    if any(signature.key == (1, 9900013) for signature in active_summary.signatures):
        raise QualificationError("active ruleset already uses qualification SID 9900013")
    separator = b"" if not active or active.endswith(b"\n") else b"\n"
    built = {
        label: active + separator + overlay
        for label, overlay in overlays.items()
    }
    if set(built) != {"success", "rollback"}:
        raise QualificationError("qualification overlays are incomplete")
    if hashlib.sha256(built["success"]).digest() == hashlib.sha256(
        built["rollback"]
    ).digest():
        raise QualificationError("qualification overlays do not produce distinct rulesets")
    return built


def _prepare_fixture_candidate(
    service: RuleOpsService,
    label: str,
    payload: bytes,
) -> dict[str, Any]:
    store = service.store
    candidate_id = store.new_id()
    store.prepare(candidate_id)
    summary = summarize_ruleset(payload)
    baseline = service._active_summary_or_empty()
    difference = compare_rulesets(
        baseline,
        summary,
        minimum_rule_count=service.config.minimum_rule_count,
        maximum_reduction_percent=service.config.maximum_reduction_percent,
    )
    if not difference.policy_allowed:
        raise QualificationError("qualification fixture candidate violates rule policy")
    _write_exclusive_regular(store.rules_file(candidate_id), payload)
    store.save_manifest(
        candidate_id,
        {
            "schema_version": 1,
            "candidate_id": candidate_id,
            "source": service.config.source,
            "created_utc": utc_now(),
            "status": "policy_passed",
            "summary": summary.to_dict(),
            "difference": difference.to_dict(),
            "validation": {"status": "pending"},
            "regression": {"status": "pending"},
            "qualification_fixture": {
                "label": label,
                "pack_id": QUALIFICATION_PACK_ID,
                "overlay": QUALIFICATION_OVERLAYS[label][0],
                "overlay_sha256": QUALIFICATION_OVERLAYS[label][1],
            },
        },
    )
    service.validate(candidate_id)
    approved = service.regress(candidate_id, QUALIFICATION_PACK_ID)
    return {
        "candidate_id": candidate_id,
        "sha256": approved["summary"]["sha256"],
        "status": approved["status"],
        "overlay": QUALIFICATION_OVERLAYS[label][0],
    }


def _write_exclusive_regular(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o640)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        directory = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise QualificationError("cannot persist qualification candidate") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _approved_candidates(
    paths: MeercataPaths,
    success_candidate_id: str,
    rollback_candidate_id: str,
) -> dict[str, Any]:
    if success_candidate_id == rollback_candidate_id:
        raise QualificationError("success and rollback candidate IDs must differ")
    store = RuleCandidateStore(paths)
    packs = RegressionPackStore(paths)
    details = [
        _approved_candidate(store, packs, success_candidate_id),
        _approved_candidate(store, packs, rollback_candidate_id),
    ]
    if details[0]["sha256"] == details[1]["sha256"]:
        raise QualificationError("success and rollback candidate hashes must differ")
    active_path = RuleOpsService.from_paths(paths).config.active_rules_path
    return {
        "success_candidate_id": success_candidate_id,
        "success_sha256": details[0]["sha256"],
        "success_pack_id": details[0]["pack_id"],
        "rollback_candidate_id": rollback_candidate_id,
        "rollback_sha256": details[1]["sha256"],
        "rollback_pack_id": details[1]["pack_id"],
        "active_rules_path": active_path,
    }


def _approved_candidate(
    store: RuleCandidateStore,
    packs: RegressionPackStore,
    candidate_id: str,
) -> dict[str, str]:
    manifest = store.load_manifest(candidate_id)
    validation = manifest.get("validation")
    regression = manifest.get("regression")
    if (
        manifest.get("status") != "regression_passed"
        or not isinstance(validation, dict)
        or validation.get("status") != "passed"
        or not isinstance(regression, dict)
        or regression.get("status") != "passed"
    ):
        raise QualificationError("qualification candidate is not fully approved")
    summary = summarize_ruleset(store.read_rules(candidate_id))
    expected = manifest.get("summary", {}).get("sha256")
    if summary.sha256 != expected or regression.get("candidate_sha256") != expected:
        raise QualificationError("qualification candidate hash evidence is stale")
    pack_id = regression.get("pack_id")
    if not isinstance(pack_id, str):
        raise QualificationError("qualification candidate pack ID is invalid")
    pack = packs.load(pack_id)
    if pack.manifest_sha256 != regression.get("pack_manifest_sha256"):
        raise QualificationError("qualification regression pack changed after approval")
    return {"sha256": summary.sha256, "pack_id": pack_id}


def _verify_receipts(
    paths: MeercataPaths,
    record: TransactionRecord,
    *,
    expected_files: set[str],
) -> dict[str, Any]:
    root = paths.privileged_transactions_dir / record.transaction_id / "rules"
    observed: list[str] = []
    phases: list[str] = []
    for name in sorted(expected_files):
        path = root / name
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise QualificationError("privileged receipt trust boundary is invalid")
        value = _read_json(path)
        if value.get("transaction_id") != record.transaction_id:
            raise QualificationError("privileged receipt transaction ID is invalid")
        if name.startswith("reload-"):
            if value.get("status") != "verified":
                raise QualificationError("rule reload receipt is not verified")
            phases.append(str(value.get("phase")))
        observed.append(name)
    return {"receipt_files": observed, "reload_phases": sorted(phases)}


def _verify_audit(paths: MeercataPaths, transaction_ids: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label, path in (
        ("controller_audit_events", paths.audit_file),
        ("privileged_audit_events", paths.privileged_audit_file),
    ):
        raw = _read_bounded_regular(path, MAX_AUDIT_BYTES, require_root=True)
        matched = 0
        for line in raw.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise QualificationError("qualification audit contains invalid JSON") from exc
            if isinstance(value, dict) and value.get("transaction_id") in transaction_ids:
                matched += 1
        if matched == 0:
            raise QualificationError("qualification transaction audit evidence is missing")
        counts[label] = matched
    return counts


def _hash_regular(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise QualificationError(f"cannot read active ruleset: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128 * 1024 * 1024:
            raise QualificationError("active ruleset trust boundary is invalid")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_json(path: Path) -> Mapping[str, Any]:
    raw = _read_bounded_regular(path, 1024 * 1024, require_root=True)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise QualificationError("privileged receipt is invalid JSON") from exc
    if not isinstance(value, dict):
        raise QualificationError("privileged receipt must be an object")
    return value


def _read_bounded_regular(path: Path, limit: int, *, require_root: bool) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise QualificationError(f"cannot read qualification evidence file: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > limit
            or (require_root and metadata.st_uid != 0)
            or metadata.st_mode & 0o002
        ):
            raise QualificationError("qualification evidence file trust boundary is invalid")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise QualificationError("qualification evidence file exceeds its size limit")
        return raw
    finally:
        os.close(descriptor)


def _require_state(record: TransactionRecord, expected: TransactionState) -> None:
    if record.state != expected:
        raise QualificationError(
            f"qualification transaction is {record.state.value}, expected {expected.value}"
        )


def _transaction_details(
    record: TransactionRecord,
    receipts: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "transaction_id": record.transaction_id,
        "state": record.state.value,
        "history_states": [entry.state.value for entry in record.history],
        **dict(receipts),
    }


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    safe = dict(details)
    safe.pop("active_rules_path", None)
    return {"check_id": check_id, "status": "passed", "details": safe}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify live RuleOps commit and rollback in a disposable Debian 13 VM"
    )
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--image-sha512", required=True)
    parser.add_argument("--prepare-candidates", action="store_true")
    parser.add_argument("--success-candidate")
    parser.add_argument("--rollback-candidate")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        if args.prepare_candidates:
            if args.success_candidate or args.rollback_candidate:
                raise QualificationError(
                    "candidate IDs cannot be supplied during fixture preparation"
                )
            report = RuleOpsVmCandidatePreparer(
                confirmation=args.confirmation,
                image_sha512=args.image_sha512,
            ).prepare()
        else:
            if not args.success_candidate or not args.rollback_candidate:
                raise QualificationError(
                    "success and rollback candidate IDs are required"
                )
            report = RuleOpsVmQualifier(
                confirmation=args.confirmation,
                image_sha512=args.image_sha512,
                success_candidate_id=args.success_candidate,
                rollback_candidate_id=args.rollback_candidate,
            ).qualify()
    except Exception as exc:
        if isinstance(exc, MeercataError):
            print(f"meercata-ruleops-vm-qualifier: {exc}", file=stderr)
            return 3
        raise
    print(json.dumps(report, sort_keys=True), file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
