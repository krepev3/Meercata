from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from meercata.errors import PrivilegedOperationError
from meercata.models import Actor, CommandResult, TransactionRecord
from meercata.paths import MeercataPaths
from meercata.privileged_client import PrivilegedNftablesActivator, PrivilegedRuleActivator
from meercata.privileged_helper import build_parser, main


def _record(candidate_id: str = "00000000-0000-0000-0000-000000000002"):
    return TransactionRecord.create_locked(
        "rules.promote",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
        {"candidate_id": candidate_id},
        "00000000-0000-0000-0000-000000000001",
    )


def _ips_record():
    return TransactionRecord.create_locked(
        "ips.activate",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
        {
            "interface": "eth0",
            "queue": 42,
            "fail_policy": "open",
            "traffic_scope": "gateway-forward",
        },
        "10000000-0000-0000-0000-000000000001",
    )


def _result(command_id, argv, *, code=0, stdout=None):
    if stdout is None:
        operation = argv[3]
        stdout = json.dumps(
            {
                "schema_version": 1,
                "status": "ok",
                "operation": operation,
                "details": {"candidate_sha256": "a" * 64},
            }
        )
    return CommandResult(
        command_id,
        argv,
        code,
        stdout,
        "",
        False,
        False,
        False,
        "2026-08-12T00:00:00Z",
        0.1,
    )


class ClientRunner:
    def __init__(self, commands, calls, *, code=0, stdout=None):
        self.commands = commands
        self.calls = calls
        self.code = code
        self.stdout = stdout

    def run(self, command_id):
        definition = self.commands[command_id]
        self.calls.append((command_id, definition))
        return _result(command_id, definition.argv, code=self.code, stdout=self.stdout)


def _factory(calls, *, code=0, stdout=None):
    return lambda commands: ClientRunner(commands, calls, code=code, stdout=stdout)


def test_privileged_client_uses_fixed_sudo_argv_and_parses_json(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    client = PrivilegedRuleActivator(paths, runner_factory=_factory(calls))

    details = client.snapshot(_record())

    assert details["candidate_sha256"] == "a" * 64
    command_id, definition = calls[0]
    assert command_id == "privileged.rules.snapshot"
    assert definition.argv == (
        "/usr/bin/sudo",
        "-n",
        str(paths.installed_helper_file),
        "rules.snapshot",
        "00000000-0000-0000-0000-000000000001",
    )
    assert definition.working_directory == Path("/")


def test_privileged_client_reload_uses_transaction_uuid_only(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    client = PrivilegedRuleActivator(paths, runner_factory=_factory(calls))

    client.reload_and_verify(_record())

    assert calls[0][1].argv == (
        "/usr/bin/sudo",
        "-n",
        str(paths.installed_helper_file),
        "rules.reload",
        "00000000-0000-0000-0000-000000000001",
    )


def test_privileged_nftables_client_uses_only_fixed_helper_arguments(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    calls = []
    client = PrivilegedNftablesActivator(paths, runner_factory=_factory(calls))

    client.snapshot(_ips_record())
    client.emergency_bypass("listener-loss", "INC-NFQ-001")

    assert calls[0][1].argv == (
        "/usr/bin/sudo",
        "-n",
        str(paths.installed_helper_file),
        "nftables.snapshot",
        "10000000-0000-0000-0000-000000000001",
    )
    assert calls[1][1].argv == (
        "/usr/bin/sudo",
        "-n",
        str(paths.installed_helper_file),
        "emergency.bypass",
        "listener-loss",
        "INC-NFQ-001",
    )


def test_privileged_client_denies_candidate_mismatch_before_execution(tmp_path: Path) -> None:
    calls = []
    client = PrivilegedRuleActivator(
        MeercataPaths.isolated(tmp_path), runner_factory=_factory(calls)
    )

    with pytest.raises(PrivilegedOperationError, match="does not match"):
        client.activate(_record(), "00000000-0000-0000-0000-000000000099")

    assert calls == []


@pytest.mark.parametrize(
    "code, stdout, message",
    [
        (1, "", "exit code 1"),
        (0, "not-json", "invalid JSON"),
        (0, '{"schema_version":2}', "invalid result schema"),
    ],
)
def test_privileged_client_rejects_helper_failure_or_invalid_output(
    tmp_path: Path, code: int, stdout: str, message: str
) -> None:
    client = PrivilegedRuleActivator(
        MeercataPaths.isolated(tmp_path),
        runner_factory=_factory([], code=code, stdout=stdout),
    )

    with pytest.raises(PrivilegedOperationError, match=message):
        client.snapshot(_record())


class FakeHelperService:
    def __init__(self, *, fail=False):
        self.calls = []
        self.fail = fail

    def snapshot(self, transaction_id):
        self.calls.append(("snapshot", transaction_id))
        if self.fail:
            raise PrivilegedOperationError("denied")
        return {"active_existed": True}

    def activate(self, transaction_id):
        self.calls.append(("activate", transaction_id))
        return {"state": "applied"}

    def rollback(self, transaction_id):
        self.calls.append(("rollback", transaction_id))
        return {"applied": True}

    def reload(self, transaction_id):
        self.calls.append(("reload", transaction_id))
        return {"status": "verified"}

    def health_snapshot(self):
        self.calls.append(("health", None))
        return {"version": "8.0.6"}

    def nftables_snapshot(self, transaction_id):
        self.calls.append(("nftables.snapshot", transaction_id))
        return {"active_existed": False}

    def nftables_apply(self, transaction_id):
        self.calls.append(("nftables.apply", transaction_id))
        return {"state": "applied"}

    def nftables_verify(self, transaction_id):
        self.calls.append(("nftables.verify", transaction_id))
        return {"status": "verified"}

    def nftables_rollback(self, transaction_id):
        self.calls.append(("nftables.rollback", transaction_id))
        return {"applied": True}

    def emergency_bypass(self, reason, incident_id):
        self.calls.append(("emergency.bypass", reason, incident_id))
        return {"state": "removed"}


def test_helper_cli_dispatches_only_allowlisted_operation(tmp_path: Path) -> None:
    stdout = io.StringIO()
    service = FakeHelperService()

    result = main(
        ["rules.activate", "00000000-0000-0000-0000-000000000001"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        service_factory=lambda _paths: service,
    )

    value = json.loads(stdout.getvalue())
    assert result == 0
    assert value["status"] == "ok"
    assert value["operation"] == "rules.activate"
    assert service.calls == [
        ("activate", "00000000-0000-0000-0000-000000000001")
    ]
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["shell", "00000000-0000-0000-0000-000000000001"]
        )


def test_helper_cli_returns_bounded_expected_error(tmp_path: Path) -> None:
    stderr = io.StringIO()

    result = main(
        ["rules.snapshot", "00000000-0000-0000-0000-000000000001"],
        paths=MeercataPaths.isolated(tmp_path),
        stderr=stderr,
        service_factory=lambda _paths: FakeHelperService(fail=True),
    )

    assert result == 3
    assert stderr.getvalue() == "meercata-helper: denied\n"


def test_helper_cli_dispatches_health_without_an_operand(tmp_path: Path) -> None:
    stdout = io.StringIO()
    service = FakeHelperService()

    result = main(
        ["health.socket-snapshot"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        service_factory=lambda _paths: service,
    )

    value = json.loads(stdout.getvalue())
    assert result == 0
    assert value["operation"] == "health.socket-snapshot"
    assert service.calls == [("health", None)]


def test_helper_cli_dispatches_nftables_and_emergency_operations(tmp_path: Path) -> None:
    service = FakeHelperService()
    transaction_id = "10000000-0000-0000-0000-000000000001"
    stdout = io.StringIO()

    assert main(
        ["nftables.apply", transaction_id],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        service_factory=lambda _paths: service,
    ) == 0
    assert json.loads(stdout.getvalue())["operation"] == "nftables.apply"

    stdout = io.StringIO()
    assert main(
        ["emergency.bypass", "recovery-failed", "INC-OPS-001"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        service_factory=lambda _paths: service,
    ) == 0
    assert json.loads(stdout.getvalue())["operation"] == "emergency.bypass"
    assert service.calls == [
        ("nftables.apply", transaction_id),
        ("emergency.bypass", "recovery-failed", "INC-OPS-001"),
    ]
