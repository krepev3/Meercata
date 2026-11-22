"""Qualify live Suricata readiness and read-only health in a disposable VM."""

from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import QualificationError

CONFIRMATION = "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 VM"
CLOUD_IMAGE_SHA512 = (
    "0ce1f1d675733027d3e17a4665cb95e1d7173bdf67fb8a87ff822ff5ee025bc2"
    "a90ecb270465ef395755e41c868b40072eb9ac493810196d9cf68f941afb93dc"
)
EXPECTED_PACKAGES = {
    "meercata": "2.0.0~dev16-1",
    "suricata": "1:8.0.6-1~bpo13+1",
    "suricata-update": "1.3.8-1~bpo13+1",
}
SURICATA_DROP_IN = (
    "/usr/lib/systemd/system/suricata.service.d/50-meercata-production.conf"
)
SOCKET_PATH = Path("/run/suricata/suricata-command.socket")


class SystemdVmQualifier:
    """Perform bounded checks; only the health oneshot and timer are started."""

    def __init__(self, *, confirmation: str, image_sha512: str) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512

    def qualify(self) -> dict[str, Any]:
        platform_details = _require_disposable_vm(
            self.confirmation, self.image_sha512
        )
        checks = [
            _passed("platform.vm", platform_details),
            _passed("packages.installed", _verify_packages()),
            _passed("suricata.readiness", _verify_suricata_readiness()),
            _passed("health.cli", _verify_service_user_health()),
            _passed("health.systemd", _verify_systemd_health()),
        ]
        return {
            "schema_version": 1,
            "status": "systemd-vm-readiness-qualified",
            "project_version": __version__,
            "platform": platform_details,
            "checks": checks,
            "limitations": [
                "the unsigned Meercata artifact was copied into the disposable VM and installed directly with dpkg",
                "only IDS AF_PACKET traffic and read-only socket commands were exercised; IPS and NFQUEUE were not",
                "rule activation, live reload, failure rollback, and transaction recovery were not exercised",
                "Suricata crash throttling, enabled-timer reboot persistence, package removal, and reboot recovery were not exercised",
            ],
        }


def _require_disposable_vm(
    confirmation: str,
    image_sha512: str,
    *,
    expected_confirmation: str = CONFIRMATION,
    expected_image_sha512: str = CLOUD_IMAGE_SHA512,
) -> dict[str, Any]:
    if confirmation != expected_confirmation:
        raise QualificationError("disposable VM confirmation phrase is invalid")
    if image_sha512 != expected_image_sha512:
        raise QualificationError("Debian cloud image SHA-512 is not approved")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise QualificationError("systemd VM qualification requires root")
    if _read_small(Path("/proc/1/comm"), 64).strip() != "systemd":
        raise QualificationError("systemd is not PID 1")
    os_release = _parse_os_release(_read_small(Path("/etc/os-release"), 8192))
    if os_release.get("ID") != "debian" or os_release.get("VERSION_ID") != "13":
        raise QualificationError("qualification requires Debian 13")
    architecture = platform.machine()
    if architecture != "x86_64":
        raise QualificationError("qualification requires x86_64")
    result = _run(
        "platform.virtualization",
        ("/usr/bin/systemd-detect-virt", "--vm"),
        timeout_seconds=10,
    )
    virtualization = result.stdout.strip()
    if virtualization not in {"kvm", "qemu"}:
        raise QualificationError("qualification requires a KVM/QEMU virtual machine")
    return {
        "os_id": "debian",
        "version_id": "13",
        "architecture": architecture,
        "pid1": "systemd",
        "virtualization": virtualization,
        "cloud_image_sha512": image_sha512,
        "effective_uid": os.geteuid(),
        "effective_gid": os.getegid(),
    }


def _verify_packages() -> dict[str, str]:
    result = _run(
        "packages.query",
        (
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${Package}\t${Version}\t${db:Status-Status}\\n",
            *EXPECTED_PACKAGES,
        ),
    )
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] in observed or parts[2] != "installed":
            raise QualificationError("installed package query is invalid")
        observed[parts[0]] = parts[1]
    if observed != EXPECTED_PACKAGES:
        raise QualificationError("installed package versions are not approved")
    return observed


def _verify_suricata_readiness() -> dict[str, Any]:
    properties = _systemctl_show(
        "suricata.service",
        (
            "ActiveState",
            "SubState",
            "Type",
            "MainPID",
            "ExecMainStatus",
            "Result",
            "NRestarts",
            "DropInPaths",
        ),
    )
    if (
        properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or properties.get("Type") != "notify"
        or properties.get("ExecMainStatus") != "0"
        or properties.get("Result") != "success"
        or SURICATA_DROP_IN not in properties.get("DropInPaths", "").split()
    ):
        raise QualificationError("Suricata is not readiness-qualified")
    try:
        main_pid = int(properties.get("MainPID", "0"))
        restarts = int(properties.get("NRestarts", "-1"))
    except ValueError as exc:
        raise QualificationError("Suricata systemd counters are invalid") from exc
    if main_pid <= 1 or restarts < 0:
        raise QualificationError("Suricata systemd process identity is invalid")
    metadata = SOCKET_PATH.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o002
    ):
        raise QualificationError("Suricata Unix socket trust boundary is invalid")
    return {
        "active_state": "active",
        "sub_state": "running",
        "type": "notify",
        "main_pid": main_pid,
        "exec_main_status": 0,
        "result": "success",
        "restart_count": restarts,
        "drop_in": SURICATA_DROP_IN,
        "socket_path": str(SOCKET_PATH),
        "socket_root_owned": True,
        "socket_world_writable": False,
    }


def _verify_service_user_health() -> dict[str, Any]:
    result = _run(
        "health.service-user",
        (
            "/usr/bin/setpriv",
            "--reuid=meercata",
            "--regid=meercata",
            "--init-groups",
            "/usr/bin/meercata",
            "health",
            "--json",
        ),
        timeout_seconds=30,
        max_output_bytes=1024 * 1024,
    )
    report = _health_report(result.stdout)
    checks = report["checks"]
    return {
        "status": report["status"],
        "exit_code": report["exit_code"],
        "mode": report["mode"],
        "checks": len(checks),
        "healthy_checks": sum(item.get("status") == "healthy" for item in checks),
        "socket_version": _health_observed(checks, "suricata_socket", "version"),
        "capture_mode": _health_observed(checks, "capture_mode"),
        "capture_interface": _health_observed(checks, "capture_interface"),
    }


def _verify_systemd_health() -> dict[str, Any]:
    _run(
        "health.oneshot.start",
        ("/usr/bin/systemctl", "start", "meercata-health.service"),
        timeout_seconds=40,
    )
    service = _systemctl_show(
        "meercata-health.service",
        ("ActiveState", "SubState", "Result", "ExecMainStatus", "User", "Group"),
    )
    if service != {
        "ActiveState": "inactive",
        "SubState": "dead",
        "Result": "success",
        "ExecMainStatus": "0",
        "User": "meercata",
        "Group": "meercata",
    }:
        raise QualificationError("systemd health oneshot did not pass")
    _run(
        "health.timer.restart",
        ("/usr/bin/systemctl", "restart", "meercata-health.timer"),
        timeout_seconds=20,
    )
    timer = _systemctl_show(
        "meercata-health.timer",
        ("ActiveState", "SubState", "Result", "Unit", "TimersMonotonic"),
    )
    schedules = timer.get("TimersMonotonic", "")
    if (
        timer.get("ActiveState") != "active"
        or timer.get("SubState") not in {"waiting", "running"}
        or timer.get("Result") != "success"
        or timer.get("Unit") != "meercata-health.service"
        or "OnBootUSec=2min" not in schedules
        or "OnUnitActiveUSec=1min" not in schedules
    ):
        raise QualificationError("systemd health timer policy is invalid")
    return {
        "oneshot_result": "success",
        "oneshot_exit_status": 0,
        "service_user": "meercata",
        "timer_active": True,
        "timer_sub_state": timer["SubState"],
        "on_boot": "2min",
        "interval": "1min",
    }


def _health_report(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise QualificationError("health CLI returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("status") != "healthy"
        or value.get("exit_code") != 0
        or value.get("mode") != "ids"
        or not isinstance(value.get("checks"), list)
        or not value["checks"]
        or any(item.get("status") != "healthy" for item in value["checks"])
    ):
        raise QualificationError("health CLI did not report fully healthy IDS")
    return value


def _health_observed(checks: list[Any], check_id: str, key: str | None = None) -> Any:
    matches = [item for item in checks if item.get("id") == check_id]
    if len(matches) != 1:
        raise QualificationError("health report check inventory is invalid")
    observed = matches[0].get("observed")
    if key is None:
        return observed
    if not isinstance(observed, dict) or key not in observed:
        raise QualificationError("health report observation is invalid")
    return observed[key]


def _systemctl_show(unit: str, names: Sequence[str]) -> dict[str, str]:
    result = _run(
        f"systemd.show.{unit}",
        (
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=" + ",".join(names),
        ),
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise QualificationError("systemd property output is invalid")
        key, value = line.split("=", 1)
        if key in values:
            values[key] += "\n" + value
        else:
            values[key] = value
    if set(values) != set(names):
        raise QualificationError("systemd property inventory is incomplete")
    return values


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip('"')
    return values


def _read_small(path: Path, maximum: int) -> str:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise QualificationError(f"unsafe qualification input: {path}")
    with path.open("rb") as handle:
        content = handle.read(maximum + 1)
    if not content or len(content) > maximum:
        raise QualificationError(f"unsafe qualification input: {path}")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QualificationError(f"invalid qualification input: {path}") from exc


def _run(
    command_id: str,
    argv: tuple[str, ...],
    *,
    timeout_seconds: float = 20,
    max_output_bytes: int = 256 * 1024,
):
    result = CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=timeout_seconds)},
        max_output_bytes=max_output_bytes,
    ).run(command_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"qualification command failed: {command_id}")
    return result


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.systemd_vm_qualifier",
        description="Qualify live systemd/Suricata readiness in a disposable Debian 13 VM",
    )
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--image-sha512", required=True)
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
        report = SystemdVmQualifier(
            confirmation=arguments.confirmation,
            image_sha512=arguments.image_sha512,
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, QualificationError) as exc:
        print(f"meercata-systemd-vm: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
