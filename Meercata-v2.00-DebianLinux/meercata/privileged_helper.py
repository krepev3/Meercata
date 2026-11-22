"""Root helper CLI exposing only fixed RuleOps operation identifiers."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Sequence, TextIO

from meercata.errors import MeercataError, PrivilegedOperationError
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.privileged_socket import PrivilegedHealthSocketService
from meercata.privileged_rules import PrivilegedRuleService

MAX_HELPER_RESULT_BYTES = 768 * 1024


class PrivilegedHelperService:
    def __init__(
        self,
        rules: Any,
        health: Any,
        nftables: Any,
    ) -> None:
        self.rules = rules
        self.health = health
        self.nftables = nftables

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> "PrivilegedHelperService":
        return cls(
            _LazyRuleService(paths),
            _LazyHealthService(paths),
            _LazyNftablesService(paths),
        )

    def snapshot(self, transaction_id: str) -> dict[str, object]:
        return self.rules.snapshot(transaction_id)

    def activate(self, transaction_id: str) -> dict[str, object]:
        return self.rules.activate(transaction_id)

    def rollback(self, transaction_id: str) -> dict[str, object]:
        return self.rules.rollback(transaction_id)

    def reload(self, transaction_id: str) -> dict[str, object]:
        return self.rules.reload(transaction_id)

    def health_snapshot(self) -> dict[str, object]:
        return self.health.snapshot()

    def nftables_snapshot(self, transaction_id: str) -> dict[str, object]:
        return self.nftables.snapshot(transaction_id)

    def nftables_apply(self, transaction_id: str) -> dict[str, object]:
        return self.nftables.apply(transaction_id)

    def nftables_verify(self, transaction_id: str) -> dict[str, object]:
        return self.nftables.verify(transaction_id)

    def nftables_rollback(self, transaction_id: str) -> dict[str, object]:
        return self.nftables.rollback(transaction_id)

    def emergency_bypass(self, reason: str, incident_id: str) -> dict[str, object]:
        return self.nftables.emergency_bypass(reason, incident_id)


class _LazyNftablesService:
    """Keep IDS-only health/RuleOps usable until an IPS operation is selected."""

    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths
        self._service: PrivilegedNftablesService | None = None

    def _get(self) -> PrivilegedNftablesService:
        if self._service is None:
            self._service = PrivilegedNftablesService.from_paths(self.paths)
        return self._service

    def snapshot(self, transaction_id: str) -> dict[str, object]:
        return self._get().snapshot(transaction_id)

    def apply(self, transaction_id: str) -> dict[str, object]:
        return self._get().apply(transaction_id)

    def verify(self, transaction_id: str) -> dict[str, object]:
        return self._get().verify(transaction_id)

    def rollback(self, transaction_id: str) -> dict[str, object]:
        return self._get().rollback(transaction_id)

    def emergency_bypass(self, reason: str, incident_id: str) -> dict[str, object]:
        service = self._service or PrivilegedNftablesService.for_emergency(self.paths)
        return service.emergency_bypass(reason, incident_id)


class _LazyRuleService:
    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths
        self._service: PrivilegedRuleService | None = None

    def _get(self) -> PrivilegedRuleService:
        if self._service is None:
            self._service = PrivilegedRuleService.from_paths(self.paths)
        return self._service

    def snapshot(self, transaction_id: str) -> dict[str, object]:
        return self._get().snapshot(transaction_id)

    def activate(self, transaction_id: str) -> dict[str, object]:
        return self._get().activate(transaction_id)

    def rollback(self, transaction_id: str) -> dict[str, object]:
        return self._get().rollback(transaction_id)

    def reload(self, transaction_id: str) -> dict[str, object]:
        return self._get().reload(transaction_id)


class _LazyHealthService:
    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths
        self._service: PrivilegedHealthSocketService | None = None

    def snapshot(self) -> dict[str, object]:
        if self._service is None:
            self._service = PrivilegedHealthSocketService.from_paths(self.paths)
        return self._service.snapshot()


ServiceFactory = Callable[[MeercataPaths], Any]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meercata-helper",
        description="Restricted privileged operations for Meercata",
    )
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in (
        "rules.snapshot",
        "rules.activate",
        "rules.rollback",
        "rules.reload",
        "nftables.snapshot",
        "nftables.apply",
        "nftables.verify",
        "nftables.rollback",
    ):
        operation_parser = operations.add_parser(operation)
        operation_parser.add_argument("transaction_id")
    operations.add_parser("health.socket-snapshot")
    emergency = operations.add_parser("emergency.bypass")
    emergency.add_argument("reason")
    emergency.add_argument("incident_id")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    paths: MeercataPaths | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    service_factory: ServiceFactory | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    selected_paths = paths or MeercataPaths.production()
    try:
        service = (service_factory or PrivilegedHelperService.from_paths)(selected_paths)
        operations = {
            "rules.snapshot": service.snapshot,
            "rules.activate": service.activate,
            "rules.rollback": service.rollback,
            "rules.reload": service.reload,
            "health.socket-snapshot": lambda: service.health_snapshot(),
            "nftables.snapshot": service.nftables_snapshot,
            "nftables.apply": service.nftables_apply,
            "nftables.verify": service.nftables_verify,
            "nftables.rollback": service.nftables_rollback,
            "emergency.bypass": service.emergency_bypass,
        }
        if arguments.operation == "health.socket-snapshot":
            details = operations[arguments.operation]()
        elif arguments.operation == "emergency.bypass":
            details = operations[arguments.operation](arguments.reason, arguments.incident_id)
        else:
            details = operations[arguments.operation](arguments.transaction_id)
        payload = json.dumps(
            {
                "schema_version": 1,
                "status": "ok",
                "operation": arguments.operation,
                "details": details,
            },
            sort_keys=True,
        )
        if len(payload.encode("utf-8")) > MAX_HELPER_RESULT_BYTES:
            raise PrivilegedOperationError("helper result exceeds 768 KiB")
        print(payload, file=stdout)
        return 0
    except MeercataError as exc:
        print(f"meercata-helper: {exc}", file=stderr)
        return 3
    except Exception as exc:
        # Do not expose paths, rule text, or command output across the boundary.
        print(f"meercata-helper: internal {type(exc).__name__}", file=stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
