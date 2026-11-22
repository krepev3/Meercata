"""Unprivileged fixed-argv adapter for the installed RuleOps helper."""

from __future__ import annotations

import json
import math
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import PrivilegedOperationError
from meercata.models import CommandResult, TransactionRecord
from meercata.paths import MeercataPaths
from meercata.suricata_socket import READ_ONLY_COMMANDS

SUDO = "/usr/bin/sudo"
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]


class PrivilegedRuleActivator:
    def __init__(
        self,
        paths: MeercataPaths,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        timeout_seconds: float = 180.0,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise PrivilegedOperationError("helper timeout must be from 1 to 600 seconds")
        self.paths = paths
        self._runner_factory = runner_factory
        self.timeout_seconds = timeout_seconds

    def snapshot(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("rules.snapshot", record.transaction_id)

    def activate(self, record: TransactionRecord, candidate_id: str) -> dict[str, Any]:
        if record.redacted_arguments.get("candidate_id") != candidate_id:
            raise PrivilegedOperationError("candidate ID does not match transaction state")
        return self._run("rules.activate", record.transaction_id)

    def rollback(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("rules.rollback", record.transaction_id)

    def reload_and_verify(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("rules.reload", record.transaction_id)

    def _run(self, operation: str, transaction_id: str) -> dict[str, Any]:
        command_id = f"privileged.{operation}"
        command = CommandDefinition.fixed(
            (
                SUDO,
                "-n",
                str(self.paths.installed_helper_file),
                operation,
                transaction_id,
            ),
            timeout_seconds=self.timeout_seconds,
        )
        result = self._runner_factory({command_id: command}).run(command_id)
        if not result.succeeded:
            raise PrivilegedOperationError(
                f"privileged helper {operation} failed with exit code {result.return_code}"
            )
        return _parse_helper_result(result, operation)


class PrivilegedNftablesActivator:
    """Fixed-argv client for transaction-bound nftables helper operations."""

    def __init__(
        self,
        paths: MeercataPaths,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        timeout_seconds: float = 60.0,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise PrivilegedOperationError("nftables helper timeout must be from 1 to 300 seconds")
        self.paths = paths
        self._runner_factory = runner_factory
        self.timeout_seconds = timeout_seconds

    def snapshot(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("nftables.snapshot", record.transaction_id)

    def apply(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("nftables.apply", record.transaction_id)

    def verify(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("nftables.verify", record.transaction_id)

    def rollback(self, record: TransactionRecord) -> dict[str, Any]:
        return self._run("nftables.rollback", record.transaction_id)

    def emergency_bypass(self, reason: str, incident_id: str) -> dict[str, Any]:
        command_id = "privileged.emergency.bypass"
        command = CommandDefinition.fixed(
            (
                SUDO,
                "-n",
                str(self.paths.installed_helper_file),
                "emergency.bypass",
                reason,
                incident_id,
            ),
            timeout_seconds=self.timeout_seconds,
        )
        result = self._runner_factory({command_id: command}).run(command_id)
        if not result.succeeded:
            raise PrivilegedOperationError(
                f"privileged helper emergency.bypass failed with exit code {result.return_code}"
            )
        return _parse_helper_result(result, "emergency.bypass")

    def _run(self, operation: str, transaction_id: str) -> dict[str, Any]:
        command_id = f"privileged.{operation}"
        command = CommandDefinition.fixed(
            (
                SUDO,
                "-n",
                str(self.paths.installed_helper_file),
                operation,
                transaction_id,
            ),
            timeout_seconds=self.timeout_seconds,
        )
        result = self._runner_factory({command_id: command}).run(command_id)
        if not result.succeeded:
            raise PrivilegedOperationError(
                f"privileged helper {operation} failed with exit code {result.return_code}"
            )
        return _parse_helper_result(result, operation)


def _parse_helper_result(result: CommandResult, expected_operation: str) -> dict[str, Any]:
    if result.stdout_truncated:
        raise PrivilegedOperationError("privileged helper output was truncated")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PrivilegedOperationError("privileged helper returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("operation") != expected_operation
    ):
        raise PrivilegedOperationError("privileged helper returned an invalid result schema")
    details = value.get("details")
    if value.get("status") != "ok" or not isinstance(details, dict):
        raise PrivilegedOperationError("privileged helper did not return a successful result")
    return details


class PrivilegedHealthSocketFactory:
    """Adapts one fixed helper snapshot to the health socket interface."""

    def __init__(
        self,
        paths: MeercataPaths,
        expected_path: Path,
        interface: str,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.paths = paths
        self.expected_path = expected_path
        self.interface = interface
        self._runner_factory = runner_factory
        self.timeout_seconds = timeout_seconds

    def __call__(self, path: Path, _socket_timeout: float) -> "PrivilegedHealthSocketClient":
        if path != self.expected_path:
            raise PrivilegedOperationError("health socket path does not match fixed configuration")
        return PrivilegedHealthSocketClient(
            self.paths,
            self.interface,
            runner_factory=self._runner_factory,
            timeout_seconds=self.timeout_seconds,
        )


class PrivilegedHealthCommandExecutor:
    """Expose fixed systemd/nftables/NFQUEUE health results through one helper."""

    def __init__(
        self,
        paths: MeercataPaths,
        service_unit: str,
        *,
        runner_factory: RunnerFactory = CommandRunner,
    ) -> None:
        if service_unit not in {"suricata.service", "meercata-suricata-ips.service"}:
            raise PrivilegedOperationError("health systemd unit is not allowlisted")
        self.paths = paths
        self.runner_factory = runner_factory
        self.systemd = CommandDefinition.fixed(
            (
                "/usr/bin/systemctl",
                "show",
                service_unit,
                "--property=ActiveState,SubState,MainPID,ExecMainStatus,Result,Type",
                "--no-pager",
            ),
            timeout_seconds=5,
        )
        self.helper = CommandDefinition.fixed(
            (SUDO, "-n", str(paths.installed_helper_file), "health.socket-snapshot"),
            timeout_seconds=10,
        )

    def run(self, command_id: str) -> CommandResult:
        if command_id == "systemd.suricata.show":
            return self.runner_factory({command_id: self.systemd}).run(command_id)
        if command_id not in {"nftables.meercata.list", "nfqueue.listeners.read"}:
            raise PrivilegedOperationError("health command is not allowlisted")
        helper_id = "privileged.health.runtime_snapshot"
        result = self.runner_factory({helper_id: self.helper}).run(helper_id)
        if not result.succeeded:
            return replace(result, command_id=command_id)
        details = _parse_helper_result(result, "health.socket-snapshot")
        if command_id == "nftables.meercata.list":
            value = details.get("nftables")
            if not isinstance(value, dict):
                return replace(result, command_id=command_id, return_code=1, stdout="")
            output = json.dumps(value, sort_keys=True)
        else:
            value = details.get("nfqueue_status")
            if not isinstance(value, str):
                return replace(result, command_id=command_id, return_code=1, stdout="")
            output = value
        return replace(result, command_id=command_id, stdout=output)


class PrivilegedHealthSocketClient:
    def __init__(
        self,
        paths: MeercataPaths,
        interface: str,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.paths = paths
        self.interface = interface
        self._runner_factory = runner_factory
        self.timeout_seconds = timeout_seconds
        self._snapshot: dict[str, Any] | None = None

    def __enter__(self) -> "PrivilegedHealthSocketClient":
        command_id = "privileged.health.socket_snapshot"
        command = CommandDefinition.fixed(
            (
                SUDO,
                "-n",
                str(self.paths.installed_helper_file),
                "health.socket-snapshot",
            ),
            timeout_seconds=self.timeout_seconds,
        )
        result = self._runner_factory({command_id: command}).run(command_id)
        if not result.succeeded:
            raise PrivilegedOperationError(
                f"privileged health helper failed with exit code {result.return_code}"
            )
        self._snapshot = _parse_helper_result(result, "health.socket-snapshot")
        _validate_health_snapshot(self._snapshot)
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self._snapshot = None

    def request(
        self,
        command: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Any:
        if self._snapshot is None:
            raise PrivilegedOperationError("privileged health snapshot is not loaded")
        if command not in READ_ONLY_COMMANDS:
            raise PrivilegedOperationError(
                f"health command is not read-only allowlisted: {command}"
            )
        if command == "command-list":
            if arguments:
                raise PrivilegedOperationError("command-list accepts no arguments")
            return {"commands": sorted(READ_ONLY_COMMANDS - {"command-list"})}
        keys = {
            "version": "version",
            "uptime": "uptime",
            "running-mode": "running_mode",
            "capture-mode": "capture_mode",
            "iface-list": "interfaces",
            "iface-stat": "interface_stats",
            "dump-counters": "counters",
        }
        if command == "iface-stat":
            if arguments != {"iface": self.interface}:
                raise PrivilegedOperationError("iface-stat interface does not match configuration")
        elif arguments:
            raise PrivilegedOperationError(f"{command} accepts no arguments")
        return self._snapshot[keys[command]]


def _validate_health_snapshot(value: Mapping[str, Any]) -> None:
    required = {
        "version",
        "uptime",
        "running_mode",
        "capture_mode",
        "interfaces",
        "interface_stats",
        "counters",
        "nftables",
        "nfqueue_status",
    }
    if set(value) != required:
        raise PrivilegedOperationError("privileged health snapshot has invalid keys")
    for key in ("version", "running_mode", "capture_mode"):
        if not isinstance(value[key], str) or not 1 <= len(value[key]) <= 256:
            raise PrivilegedOperationError(
                f"privileged health snapshot {key} is invalid"
            )
    if (
        type(value["uptime"]) not in {int, float}
        or not math.isfinite(float(value["uptime"]))
        or value["uptime"] < 0
    ):
        raise PrivilegedOperationError("privileged health snapshot uptime is invalid")
    if not isinstance(value["interfaces"], (dict, list)):
        raise PrivilegedOperationError("privileged health interface list is invalid")
    if not isinstance(value["interface_stats"], dict) or not isinstance(
        value["counters"], dict
    ):
        raise PrivilegedOperationError("privileged health statistics are invalid")
    if value["nftables"] is not None and not isinstance(value["nftables"], dict):
        raise PrivilegedOperationError("privileged health nftables snapshot is invalid")
    if value["nfqueue_status"] is not None and not isinstance(
        value["nfqueue_status"], str
    ):
        raise PrivilegedOperationError("privileged health NFQUEUE snapshot is invalid")
