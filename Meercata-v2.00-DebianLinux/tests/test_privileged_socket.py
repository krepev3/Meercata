from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from meercata.errors import PrivilegedOperationError
from meercata.health_config import HealthConfig, HealthThresholds
from meercata.models import CommandResult
from meercata.paths import MeercataPaths
from meercata.privileged_client import PrivilegedHealthSocketFactory
from meercata.privileged_socket import PrivilegedHealthSocketService


def _config(paths: MeercataPaths) -> HealthConfig:
    return HealthConfig(
        "ids",
        "eth0",
        0,
        paths.suricata_log_dir / "eve.json",
        paths.suricata_run_dir / "suricata-command.socket",
        HealthThresholds(),
    )


def _values():
    return {
        "command-list": {
            "commands": [
                "version",
                "uptime",
                "running-mode",
                "capture-mode",
                "iface-list",
                "iface-stat",
                "dump-counters",
            ]
        },
        "version": "8.0.6 RELEASE",
        "uptime": 100,
        "running-mode": "workers",
        "capture-mode": "AF_PACKET",
        "iface-list": {"count": 1, "ifaces": ["eth0"]},
        "iface-stat": {"pkts": 10, "drop": 0},
        "dump-counters": {"decoder": {"pkts": 10}},
    }


class FakeSocket:
    def __init__(self, values, calls):
        self.values = values
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def request(self, command, arguments=None):
        self.calls.append((command, arguments))
        return self.values[command]


def test_privileged_health_service_uses_only_fixed_read_only_commands(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    service = PrivilegedHealthSocketService(
        _config(paths),
        socket_factory=lambda _path, _timeout: FakeSocket(_values(), calls),
    )

    snapshot = service.snapshot()

    assert snapshot["version"] == "8.0.6 RELEASE"
    assert snapshot["interface_stats"]["pkts"] == 10
    assert snapshot["nftables"] is None
    assert snapshot["nfqueue_status"] is None
    assert [item[0] for item in calls] == [
        "command-list",
        "version",
        "uptime",
        "running-mode",
        "capture-mode",
        "iface-list",
        "iface-stat",
        "dump-counters",
    ]
    assert calls[-2][1] == {"iface": "eth0"}


def test_privileged_health_service_uses_nfqueue_capture_identity(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    config = replace(_config(paths), mode="ips", queue=42)
    values = _values()
    values["capture-mode"] = "NFQ"
    values["iface-list"] = {"count": 1, "ifaces": ["NFQ#42"]}
    service = PrivilegedHealthSocketService(
        config,
        socket_factory=lambda _path, _timeout: FakeSocket(values, calls),
        nftables_reader=lambda: {"nftables": []},
        nfqueue_reader=lambda: "42 123 0 2 65535 0 0 1\n",
    )

    service.snapshot()

    assert calls[-2] == ("iface-stat", {"iface": "NFQ#42"})


def test_privileged_health_service_rejects_missing_commands_and_large_snapshot(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    values = _values()
    values["command-list"] = {"commands": ["version"]}
    service = PrivilegedHealthSocketService(
        _config(paths),
        socket_factory=lambda _path, _timeout: FakeSocket(values, []),
    )
    with pytest.raises(PrivilegedOperationError, match="commands are unavailable"):
        service.snapshot()

    values = _values()
    values["dump-counters"] = {"oversized": "x" * (512 * 1024)}
    service = PrivilegedHealthSocketService(
        _config(paths),
        socket_factory=lambda _path, _timeout: FakeSocket(values, []),
    )
    with pytest.raises(PrivilegedOperationError, match="exceeds 512 KiB"):
        service.snapshot()


@pytest.mark.parametrize("uptime", [-1, float("inf"), float("nan"), True])
def test_privileged_health_service_rejects_invalid_uptime(
    tmp_path: Path, uptime: object
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    values = _values()
    values["uptime"] = uptime
    service = PrivilegedHealthSocketService(
        _config(paths),
        socket_factory=lambda _path, _timeout: FakeSocket(values, []),
    )

    with pytest.raises(PrivilegedOperationError, match="uptime is invalid"):
        service.snapshot()


def _helper_result(operation: str, details, *, code=0):
    return CommandResult(
        "privileged.health.socket_snapshot",
        ("/usr/bin/sudo",),
        code,
        json.dumps(
            {
                "schema_version": 1,
                "status": "ok",
                "operation": operation,
                "details": details,
            }
        ),
        "",
        False,
        False,
        False,
        "2026-08-13T00:00:00Z",
        0.1,
    )


class FakeRunner:
    def __init__(self, commands, calls, result):
        self.commands = commands
        self.calls = calls
        self.result = result

    def run(self, command_id):
        self.calls.append((command_id, self.commands[command_id]))
        return self.result


def test_privileged_health_client_uses_exact_no_argument_helper_command(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)
    calls = []
    factory = PrivilegedHealthSocketFactory(
        paths,
        config.socket_path,
        config.interface,
        runner_factory=lambda commands: FakeRunner(
            commands,
            calls,
            _helper_result("health.socket-snapshot", {
                "version": "8.0.6 RELEASE",
                "uptime": 100,
                "running_mode": "workers",
                "capture_mode": "AF_PACKET",
                "interfaces": {"count": 1, "ifaces": ["eth0"]},
                "interface_stats": {"pkts": 10},
                "counters": {"decoder": {"pkts": 10}},
                "nftables": None,
                "nfqueue_status": None,
            }),
        ),
    )

    with factory(config.socket_path, 2) as client:
        assert client.request("version") == "8.0.6 RELEASE"
        assert client.request("iface-stat", {"iface": "eth0"}) == {"pkts": 10}
        with pytest.raises(PrivilegedOperationError, match="not read-only"):
            client.request("shutdown")

    command = calls[0][1]
    assert command.argv == (
        "/usr/bin/sudo",
        "-n",
        str(paths.installed_helper_file),
        "health.socket-snapshot",
    )


def test_privileged_health_client_rejects_wrong_path_interface_and_schema(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)
    factory = PrivilegedHealthSocketFactory(
        paths,
        config.socket_path,
        config.interface,
        runner_factory=lambda commands: FakeRunner(
            commands,
            [],
            _helper_result("rules.snapshot", {}),
        ),
    )
    with pytest.raises(PrivilegedOperationError, match="path does not match"):
        factory(Path("/tmp/wrong.socket"), 2)
    with pytest.raises(PrivilegedOperationError, match="invalid result schema"):
        with factory(config.socket_path, 2):
            pass


def test_privileged_health_client_rejects_truncated_helper_output(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)
    truncated = replace(
        _helper_result("health.socket-snapshot", {}), stdout_truncated=True
    )
    factory = PrivilegedHealthSocketFactory(
        paths,
        config.socket_path,
        config.interface,
        runner_factory=lambda commands: FakeRunner(commands, [], truncated),
    )

    with pytest.raises(PrivilegedOperationError, match="output was truncated"):
        with factory(config.socket_path, 2):
            pass
