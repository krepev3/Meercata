from __future__ import annotations

from pathlib import Path

import pytest

from meercata.errors import IpsConfigurationError, PrivilegedOperationError
from meercata.ips_engine import IpsEngineLauncher
from meercata.models import CommandResult
from meercata.paths import MeercataPaths


def _write_config(paths: MeercataPaths, *, mode: str = "ips") -> None:
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        f'''schema_version = 1
[health]
mode = "{mode}"
interface = "enp1s0"
queue = 42
[ips]
fail_policy = "open"
traffic_scope = "gateway-forward"
''',
        encoding="utf-8",
    )


def _result(command_id: str, stdout: str = "") -> CommandResult:
    return CommandResult(
        command_id,
        ("/usr/bin/suricata",),
        0,
        stdout,
        "",
        False,
        False,
        False,
        "2026-08-25T00:00:00Z",
        0.01,
    )


class _Runner:
    def __init__(self, commands) -> None:
        self.commands = commands

    def run(self, command_id: str) -> CommandResult:
        if command_id == "suricata.build-info":
            return _result(command_id, "NFQueue support: yes\n")
        return _result(command_id)


def test_engine_uses_fixed_nfqueue_command_and_clean_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _write_config(paths)
    captured = {}

    def execve(executable, argv, environment):
        captured.update(executable=executable, argv=tuple(argv), environment=environment)
        raise RuntimeError("exec captured")

    launcher = IpsEngineLauncher(
        paths,
        runner_factory=_Runner,
        execve=execve,
        require_root=False,
    )
    monkeypatch.setenv("NOTIFY_SOCKET", "@/org/freedesktop/systemd1/notify")

    command = launcher.command()
    assert command[1:5] == (
        "-c",
        str(paths.suricata_config_file),
        "-q",
        "42",
    )
    assert launcher.test()["nfqueue_support"] is True
    with pytest.raises(RuntimeError, match="exec captured"):
        launcher.run()
    assert captured["argv"] == command
    assert captured["environment"] == {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NOTIFY_SOCKET": "@/org/freedesktop/systemd1/notify",
        "PATH": "/usr/sbin:/usr/bin",
    }


def test_engine_run_rejects_missing_or_unbounded_notification_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _write_config(paths)
    launcher = IpsEngineLauncher(paths, require_root=False)
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    with pytest.raises(PrivilegedOperationError, match="notification socket"):
        launcher.run()
    monkeypatch.setenv("NOTIFY_SOCKET", "relative")
    with pytest.raises(PrivilegedOperationError, match="notification socket"):
        launcher.run()


def test_engine_rejects_non_ips_configuration(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _write_config(paths, mode="ids")

    with pytest.raises((IpsConfigurationError, PrivilegedOperationError)):
        IpsEngineLauncher(paths, require_root=False).command()
