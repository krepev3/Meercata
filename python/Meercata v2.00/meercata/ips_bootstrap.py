"""Private root-only IPS policy bootstrap for ordered systemd lifecycle."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Sequence, TextIO

from meercata.audit import AuditLogger
from meercata.errors import MeercataError, PrivilegedOperationError
from meercata.health_config import load_health_config
from meercata.ips_config import IpsConfig, load_ips_config
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import utc_now
from meercata.nfqueue_functional_qualifier import _read_listeners
from meercata.paths import MeercataPaths, ensure_secure_directory
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.privileged_rules import (
    _atomic_json_write,
    _read_json,
    _require_production_configuration_trust,
)
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine

ServiceFactory = Callable[[MeercataPaths, IpsConfig], PrivilegedNftablesService]
ListenerReader = Callable[[], list[dict[str, int]]]


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


class IpsBootstrapService:
    def __init__(
        self,
        paths: MeercataPaths,
        *,
        service_factory: ServiceFactory | None = None,
        listener_reader: ListenerReader = _read_listeners,
        require_root: bool | None = None,
    ) -> None:
        self.paths = paths
        self.service_factory = service_factory or self._default_service
        self.listener_reader = listener_reader
        should_require_root = paths == MeercataPaths.production() if require_root is None else require_root
        if should_require_root and os.geteuid() != 0:
            raise PrivilegedOperationError("IPS bootstrap requires effective root")

    @property
    def state_path(self) -> Path:
        return self.paths.privileged_state_dir / "ips-runtime.json"

    def activate(self) -> dict[str, Any]:
        config = self._config()
        self._require_listener(config.queue)
        service = self.service_factory(self.paths, config)
        active = service.verify_active()
        if active["active"] is True:
            result = {**active, "idempotent": True}
            self._write_state("active", result)
            return result
        store = StateStore(self.paths)
        workflow = IpsNftablesWorkflow(
            config,
            TransactionEngine(
                store=store,
                audit=AuditLogger(self.paths.audit_file),
                lock=ControllerLock(self.paths.controller_lock_file),
            ),
            _DirectActivator(service),
        )
        record = workflow.activate_policy()
        verified = service.verify_active()
        result = {
            **verified,
            "transaction_id": record.transaction_id,
            "idempotent": False,
        }
        self._write_state("active", result)
        return result

    def deactivate(self) -> dict[str, Any]:
        config = self._config()
        service = self.service_factory(self.paths, config)
        lifecycle_id = str(uuid.uuid4())
        result = service.deactivate(lifecycle_id)
        self._write_state("inactive", result)
        return result

    def status(self) -> dict[str, Any]:
        config = self._config()
        service = self.service_factory(self.paths, config)
        policy = service.verify_active()
        listener = next(
            (item for item in self.listener_reader() if item["queue"] == config.queue),
            None,
        )
        state = None
        if self.state_path.exists():
            state = _read_json(self.state_path, "IPS runtime state")
        return {
            "policy": policy,
            "listener_present": listener is not None,
            "queue": config.queue,
            "runtime_state": state,
        }

    def failsafe(self) -> dict[str, Any]:
        """Remove an owned table without depending on readable active config."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        incident_id = f"INC-AUTO-RECOVERY-{stamp}-{os.getpid()}"
        service = PrivilegedNftablesService.for_emergency(self.paths)
        result = service.emergency_bypass("recovery-failed", incident_id)
        self._write_state("inactive", result)
        return result

    def _config(self) -> IpsConfig:
        if self.paths == MeercataPaths.production():
            _require_production_configuration_trust(self.paths)
        health = load_health_config(self.paths)
        config = load_ips_config(self.paths)
        if health.mode != "ips":
            raise PrivilegedOperationError("IPS bootstrap requires health.mode='ips'")
        if health.interface != config.interface or health.queue != config.queue:
            raise PrivilegedOperationError("IPS bootstrap configuration intent is inconsistent")
        return config

    def _require_listener(self, queue: int) -> None:
        listener = next(
            (item for item in self.listener_reader() if item["queue"] == queue),
            None,
        )
        if listener is None:
            raise PrivilegedOperationError(
                "IPS policy activation requires the exact NFQUEUE listener first"
            )
        if listener["queue_dropped"] != 0 or listener["user_dropped"] != 0:
            raise PrivilegedOperationError(
                "IPS policy activation refuses a listener with existing drops"
            )

    def _write_state(self, state: str, details: dict[str, Any]) -> None:
        ensure_secure_directory(self.paths.privileged_state_dir, mode=0o700)
        _atomic_json_write(
            self.state_path,
            {
                "schema_version": 1,
                "state": state,
                "updated_utc": utc_now(),
                "details": details,
            },
            self.paths.privileged_state_dir,
            mode=0o600,
        )

    @staticmethod
    def _default_service(
        paths: MeercataPaths, config: IpsConfig
    ) -> PrivilegedNftablesService:
        return PrivilegedNftablesService(paths, config)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meercata-ips-bootstrap",
        description="Private ordered IPS policy lifecycle",
    )
    parser.add_argument(
        "action", choices=("activate", "deactivate", "failsafe", "status")
    )
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
        service = IpsBootstrapService(paths or MeercataPaths.production())
        result = getattr(service, arguments.action)()
        print(json.dumps(result, sort_keys=True), file=stdout)
        return 0
    except MeercataError as exc:
        print(f"meercata-ips-bootstrap: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
