"""Live transactional nftables helper qualification in a disposable netns."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence, TextIO

from meercata import __version__
from meercata.audit import AuditLogger
from meercata.container_qualifier import DEBIAN_13_IMAGE_DIGEST
from meercata.errors import PrivilegedOperationError, QualificationError, TransactionFailed
from meercata.ips_config import IpsConfig
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.nftables_namespace_qualifier import (
    _apply_text,
    _best_effort_delete,
    _foreign_table_script,
    _list_table,
    _passed,
    _require_disposable_network_namespace,
    _semantic_table_hash,
)
from meercata.nftables_policy import inspect_owned_table
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine

CONFIRMATION = "I_UNDERSTAND_THIS_RUNS_TRANSACTIONAL_NFTABLES_IN_A_DISPOSABLE_NETNS"


class _DirectActivator:
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


class NftablesTransactionQualifier:
    def __init__(self, *, confirmation: str, image_digest: str) -> None:
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_network_namespace(
            self.confirmation,
            self.image_digest,
            expected_confirmation=CONFIRMATION,
        )
        checks: list[dict[str, Any]] = [_passed("platform.namespace", platform)]
        with tempfile.TemporaryDirectory(prefix="meercata-nft-transaction-") as temporary:
            root = Path(temporary)
            paths = MeercataPaths.isolated(root / "state")
            config = IpsConfig("eth0", 42)
            try:
                _apply_text(root, "foreign-add", _foreign_table_script())
                foreign_hash = _semantic_table_hash(_list_table("operator_guard"))
                service = PrivilegedNftablesService(
                    paths, config, require_root=False
                )
                store = StateStore(paths)

                first = IpsNftablesWorkflow(
                    config,
                    _engine(paths, store),
                    _DirectActivator(service),
                ).activate_policy()
                first_observed = inspect_owned_table(_list_table("meercata"))
                if (
                    first.state != TransactionState.COMMITTED
                    or first_observed.transaction_id != first.transaction_id
                ):
                    raise QualificationError("first nftables transaction did not commit exactly")
                checks.append(
                    _passed(
                        "transaction.commit",
                        {
                            "transaction_id": first.transaction_id,
                            "semantic_sha256": first_observed.semantic_sha256,
                            "fail_open": first_observed.fail_open,
                        },
                    )
                )

                direct = _DirectActivator(service)

                class ForcedFailure:
                    snapshot = direct.snapshot
                    apply = direct.apply
                    rollback = direct.rollback

                    def verify(self, record):
                        direct.verify(record)
                        raise PrivilegedOperationError("qualified forced post-apply failure")

                try:
                    IpsNftablesWorkflow(
                        config,
                        _engine(paths, store),
                        ForcedFailure(),
                    ).activate_policy()
                except TransactionFailed as failure:
                    second_id = failure.transaction_id
                else:
                    raise QualificationError("forced nftables transaction unexpectedly committed")
                second = store.load(second_id)
                restored = inspect_owned_table(_list_table("meercata"))
                if (
                    second.state != TransactionState.ROLLED_BACK
                    or restored.transaction_id != first.transaction_id
                    or restored.semantic_sha256 != first_observed.semantic_sha256
                ):
                    raise QualificationError("forced transaction did not restore first policy")
                checks.append(
                    _passed(
                        "transaction.forced-rollback",
                        {
                            "transaction_id": second_id,
                            "state": second.state.value,
                            "restored_transaction_id": restored.transaction_id,
                            "restored_semantic_sha256": restored.semantic_sha256,
                        },
                    )
                )

                receipt_details = _verify_receipts(paths, first.transaction_id, second_id)
                checks.append(_passed("receipts.root-private", receipt_details))

                bypass = service.emergency_bypass(
                    "recovery-failed", "INC-DEV18-QUALIFICATION"
                )
                if bypass.get("removed") is not True:
                    raise QualificationError("emergency bypass did not report removal")
                try:
                    _list_table("meercata")
                except QualificationError:
                    pass
                else:
                    raise QualificationError("Meercata table remains after emergency bypass")
                checks.append(
                    _passed(
                        "emergency.bypass",
                        {
                            "incident_id": bypass["incident_id"],
                            "reason": bypass["reason"],
                            "removed": bypass["removed"],
                        },
                    )
                )

                audit = _verify_audits(paths)
                checks.append(_passed("audit.dual-stream", audit))
                if _semantic_table_hash(_list_table("operator_guard")) != foreign_hash:
                    raise QualificationError("unrelated table changed during transactions")
                checks.append(
                    _passed(
                        "isolation.unrelated-preserved",
                        {"semantic_sha256": foreign_hash, "preserved": True},
                    )
                )
            finally:
                _best_effort_delete(root, "meercata")
                _best_effort_delete(root, "operator_guard")

        if len(checks) != 7:
            raise QualificationError("transaction qualification check count is invalid")
        return {
            "schema_version": 1,
            "status": "nftables-transaction-qualified",
            "project_version": __version__,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "the run mutated nftables only inside a disposable container network namespace",
                "Suricata and a userspace NFQUEUE listener were not started",
                "packet verdicts, listener loss, overload, throughput, and latency remain unqualified",
                "public IPS CLI activation, systemd lifecycle, crash, and reboot behavior remain gated",
            ],
        }


def _engine(paths: MeercataPaths, store: StateStore) -> TransactionEngine:
    return TransactionEngine(
        store=store,
        audit=AuditLogger(paths.audit_file),
        lock=ControllerLock(paths.controller_lock_file),
    )


def _verify_receipts(paths: MeercataPaths, first_id: str, second_id: str) -> dict[str, Any]:
    files = [
        paths.privileged_transactions_dir / first_id / "nftables" / "snapshot.json",
        paths.privileged_transactions_dir / first_id / "nftables" / "activation.json",
        paths.privileged_transactions_dir / second_id / "nftables" / "snapshot.json",
        paths.privileged_transactions_dir / second_id / "nftables" / "activation.json",
        paths.privileged_transactions_dir / second_id / "nftables" / "rollback.json",
    ]
    for path in files:
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
            raise QualificationError("transaction receipt is missing or not root-private")
    first = json.loads(files[1].read_text())
    rollback = json.loads(files[-1].read_text())
    if first.get("state") != "applied" or rollback.get("applied") is not True:
        raise QualificationError("transaction receipt state is invalid")
    return {
        "files": len(files),
        "mode": "0600",
        "first_activation_state": first["state"],
        "second_rollback_applied": rollback["applied"],
    }


def _verify_audits(paths: MeercataPaths) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for name, path in (
        ("controller", paths.audit_file),
        ("privileged", paths.privileged_audit_file),
    ):
        try:
            records = [json.loads(line) for line in path.read_text().splitlines() if line]
        except (OSError, json.JSONDecodeError) as exc:
            raise QualificationError("transaction audit stream is invalid") from exc
        if not records or any(record.get("schema_version") != 1 for record in records):
            raise QualificationError("transaction audit stream is empty or malformed")
        counts[name] = len(records)
    return {
        "controller_events": counts["controller"],
        "privileged_events": counts["privileged"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m meercata.nftables_transaction_qualifier",
        description="Qualify transactional nftables helper behavior in a disposable netns",
    )
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--image-digest", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        report = NftablesTransactionQualifier(
            confirmation=arguments.confirm,
            image_digest=arguments.image_digest,
        ).qualify()
        print(json.dumps(report, indent=2, sort_keys=True), file=stdout)
        return 0
    except QualificationError as exc:
        print(f"meercata-nftables-transaction-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
