"""Root-only fixed IPS safety guard for listener loss and queue overload."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any, Callable, Sequence, TextIO

from meercata.errors import MeercataError, PrivilegedOperationError
from meercata.ips_config import IpsConfig, load_ips_config
from meercata.nfqueue_functional_qualifier import _read_listeners
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.privileged_rules import _require_production_configuration_trust

ServiceFactory = Callable[[MeercataPaths, IpsConfig], PrivilegedNftablesService]
ListenerReader = Callable[[], list[dict[str, int]]]


class IpsGuardService:
    def __init__(
        self,
        paths: MeercataPaths,
        *,
        service_factory: ServiceFactory | None = None,
        listener_reader: ListenerReader = _read_listeners,
        poll_seconds: float = 0.5,
        require_root: bool | None = None,
    ) -> None:
        if not 0.1 <= poll_seconds <= 5.0:
            raise PrivilegedOperationError("IPS guard poll interval is invalid")
        self.paths = paths
        self.service_factory = service_factory or self._default_service
        self.listener_reader = listener_reader
        self.poll_seconds = poll_seconds
        should_require_root = paths == MeercataPaths.production() if require_root is None else require_root
        if should_require_root and (os.geteuid() != 0 or os.getegid() != 0):
            raise PrivilegedOperationError("IPS guard requires effective root")

    def check_once(self) -> dict[str, Any]:
        if self.paths == MeercataPaths.production():
            _require_production_configuration_trust(self.paths)
        config = load_ips_config(self.paths)
        service = self.service_factory(self.paths, config)
        active = service.verify_active()
        if active["active"] is not True:
            return {"status": "idle", "action": "none", "policy_active": False}
        queue = active["queue"]
        listener = next(
            (item for item in self.listener_reader() if item["queue"] == queue),
            None,
        )
        if listener is None:
            incident = _incident_id("LISTENER")
            bypass = service.emergency_bypass("listener-loss", incident)
            return {
                "status": "bypassed",
                "action": "emergency.bypass",
                "reason": "listener-loss",
                "incident_id": incident,
                "details": bypass,
            }
        if listener["queue_dropped"] > 0 or listener["user_dropped"] > 0:
            incident = _incident_id("OVERLOAD")
            bypass = service.emergency_bypass("queue-overload", incident)
            return {
                "status": "bypassed",
                "action": "emergency.bypass",
                "reason": "queue-overload",
                "incident_id": incident,
                "details": bypass,
            }
        return {
            "status": "healthy",
            "action": "none",
            "policy_active": True,
            "queue": queue,
            "port_id": listener["port_id"],
            "queue_total": listener["queue_total"],
            "queue_dropped": listener["queue_dropped"],
            "user_dropped": listener["user_dropped"],
        }

    def run(self) -> None:
        while True:
            self.check_once()
            time.sleep(self.poll_seconds)

    @staticmethod
    def _default_service(
        paths: MeercataPaths, config: IpsConfig
    ) -> PrivilegedNftablesService:
        return PrivilegedNftablesService(paths, config)


def _incident_id(kind: str) -> str:
    if kind not in {"LISTENER", "OVERLOAD"}:
        raise PrivilegedOperationError("IPS guard incident kind is invalid")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"INC-AUTO-{kind}-{stamp}-{os.getpid()}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meercata-ips-guard",
        description="Monitor an active owned NFQUEUE policy and bypass on unsafe state",
    )
    parser.add_argument("--once", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    paths: MeercataPaths | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        service = IpsGuardService(paths or MeercataPaths.production())
        if arguments.once:
            print(json.dumps(service.check_once(), sort_keys=True), file=stdout)
            return 0
        service.run()
        return 4
    except MeercataError as exc:
        print(f"meercata-ips-guard: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
