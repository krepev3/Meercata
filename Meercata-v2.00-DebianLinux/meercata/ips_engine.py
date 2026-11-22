"""Fixed Suricata NFQUEUE engine launcher for the private IPS systemd unit."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import MeercataError, PrivilegedOperationError
from meercata.health_config import load_health_config
from meercata.ips_config import load_ips_config
from meercata.paths import MeercataPaths
from meercata.privileged_rules import _require_production_configuration_trust

SURICATA = Path("/usr/bin/suricata")
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]
Execve = Callable[[str, Sequence[str], dict[str, str]], None]


class IpsEngineLauncher:
    def __init__(
        self,
        paths: MeercataPaths,
        *,
        runner_factory: RunnerFactory = CommandRunner,
        execve: Execve = os.execve,
        require_root: bool | None = None,
    ) -> None:
        self.paths = paths
        self.runner_factory = runner_factory
        self.execve = execve
        should_require_root = paths == MeercataPaths.production() if require_root is None else require_root
        if should_require_root and (os.geteuid() != 0 or os.getegid() != 0):
            raise PrivilegedOperationError("IPS engine launcher requires effective root")

    def command(self) -> tuple[str, ...]:
        if self.paths == MeercataPaths.production():
            _require_production_configuration_trust(self.paths)
        health = load_health_config(self.paths)
        ips = load_ips_config(self.paths)
        if health.mode != "ips":
            raise PrivilegedOperationError("installed IPS engine requires health.mode='ips'")
        if health.interface != ips.interface or health.queue != ips.queue:
            raise PrivilegedOperationError("IPS engine configuration intent is inconsistent")
        return (
            str(SURICATA),
            "-c",
            str(self.paths.suricata_config_file),
            "-q",
            str(ips.queue),
            "-l",
            str(self.paths.suricata_log_dir),
            "--pidfile",
            str(self.paths.suricata_run_dir / "suricata.pid"),
            "--init-errors-fatal",
        )

    def test(self) -> dict[str, object]:
        command = self.command()
        build = self.runner_factory(
            {
                "suricata.build-info": CommandDefinition.fixed(
                    (str(SURICATA), "--build-info"), timeout_seconds=15
                ),
                "suricata.config-test": CommandDefinition.fixed(
                    (
                        str(SURICATA),
                        "-T",
                        "-c",
                        str(self.paths.suricata_config_file),
                        "--init-errors-fatal",
                    ),
                    timeout_seconds=90,
                ),
            }
        )
        build_result = build.run("suricata.build-info")
        if (
            not build_result.succeeded
            or build_result.stdout_truncated
            or "NFQueue support:" not in build_result.stdout
            or "yes" not in build_result.stdout.split("NFQueue support:", 1)[1][:40]
        ):
            raise PrivilegedOperationError("installed Suricata lacks NFQueue support")
        test_result = build.run("suricata.config-test")
        if not test_result.succeeded or test_result.stdout_truncated or test_result.stderr_truncated:
            raise PrivilegedOperationError("installed Suricata configuration test failed")
        return {
            "status": "validated",
            "queue": int(command[command.index("-q") + 1]),
            "config": str(self.paths.suricata_config_file),
            "nfqueue_support": True,
        }

    def run(self) -> None:
        command = self.command()
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NOTIFY_SOCKET": _notify_socket(),
            "PATH": "/usr/sbin:/usr/bin",
        }
        self.execve(str(SURICATA), command, environment)
        raise PrivilegedOperationError("Suricata exec unexpectedly returned")


def _notify_socket() -> str:
    value = os.environ.get("NOTIFY_SOCKET")
    if (
        not isinstance(value, str)
        or not value.startswith(("/", "@"))
        or not 2 <= len(os.fsencode(value)) <= 107
    ):
        raise PrivilegedOperationError(
            "IPS engine requires a bounded systemd notification socket"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meercata-ips-engine",
        description="Launch the fixed installed Suricata NFQUEUE engine",
    )
    parser.add_argument("action", choices=("test", "run"))
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
        launcher = IpsEngineLauncher(paths or MeercataPaths.production())
        if arguments.action == "test":
            import json

            print(json.dumps(launcher.test(), sort_keys=True), file=stdout)
            return 0
        launcher.run()
        return 4
    except MeercataError as exc:
        print(f"meercata-ips-engine: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
