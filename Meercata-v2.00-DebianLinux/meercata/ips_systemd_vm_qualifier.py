"""Qualify the private IPS systemd lifecycle in a disposable Debian VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import QualificationError
from meercata.nfqueue_functional_qualifier import _read_listeners
from meercata.paths import ensure_secure_directory
from meercata.privileged_rules import _atomic_json_write, _read_json
from meercata.systemd_vm_qualifier import _require_disposable_vm

CONFIRMATION = "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 IPS SYSTEMD VM"
QUALIFIED_PROJECT_VERSION = "2.0.0.dev21"
CLOUD_IMAGE_SHA512 = (
    "77429b411b39b43f914dc9d14bf34aa315489a1a12b5429f72e5b483bdda23c6"
    "5698d33443c85d3f3ad7c3a0828ae60845406d6b99646342554d17abae29c2a3"
)
EXPECTED_PACKAGES = {
    "meercata": "2.0.0~dev21-1",
    "suricata": "1:8.0.6-1~bpo13+1",
    "suricata-update": "1.3.8-1~bpo13+1",
}
STATE_PATH = Path("/var/lib/meercata/qualification/ips-systemd-v1.json")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
TARGET = "meercata-ips.target"
ENGINE = "meercata-suricata-ips.service"
ACTIVATION = "meercata-ips-activate.service"
GUARD = "meercata-ips-guard.service"
BOOT_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
PROTECTED_FILES = (
    Path("/etc/meercata/meercata.toml"),
    Path("/etc/suricata/suricata.yaml"),
    Path("/usr/lib/meercata/package-manifest.json"),
    Path("/usr/lib/systemd/system/meercata-suricata-ips.service"),
    Path("/usr/lib/systemd/system/meercata-ips-activate.service"),
    Path("/usr/lib/systemd/system/meercata-ips-guard.service"),
    Path("/usr/lib/systemd/system/meercata-ips.target"),
)


class IpsSystemdVmQualifier:
    """Exercise activation and fail-open recovery, then prove reboot recovery."""

    def __init__(self, *, confirmation: str, image_sha512: str) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512

    def prepare(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
            expected_image_sha512=CLOUD_IMAGE_SHA512,
        )
        packages = _verify_packages()
        protected = _protected_inventory()
        mutated = False
        try:
            _run("ips.distro-disable", ("/usr/bin/systemctl", "disable", "--now", "suricata.service"))
            _run("ips.target-stop", ("/usr/bin/systemctl", "stop", TARGET))
            _wait_inactive(timeout=90)
            mutated = True
            initial = _start_and_verify()
            guard_failure = _exercise_failure(GUARD, "guard")
            rearmed = _rearm("guard")
            engine_failure = _exercise_failure(ENGINE, "engine")
            _run("ips.stop-after-engine", ("/usr/bin/systemctl", "stop", TARGET), timeout=120)
            stopped = _wait_inactive(timeout=90)
            _run("ips.enable", ("/usr/bin/systemctl", "enable", TARGET))
            _run("ips.final-start", ("/usr/bin/systemctl", "start", TARGET), timeout=150)
            final = _wait_active(timeout=120)
        except Exception:
            if mutated:
                _best_effort_stop()
            raise
        state = {
            "schema_version": 1,
            "status": "reboot-prepared",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "image_sha512": self.image_sha512,
            "boot_id": _boot_id(),
            "packages": packages,
            "protected_files": protected,
            "initial": initial,
            "guard_failure": guard_failure,
            "rearmed": rearmed,
            "engine_failure": engine_failure,
            "stopped": stopped,
            "final": final,
        }
        ensure_secure_directory(STATE_PATH.parent, mode=0o700)
        _atomic_json_write(STATE_PATH, state, STATE_PATH.parent, mode=0o600)
        return {
            "schema_version": 1,
            "status": "reboot-required",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "platform": platform,
            "state_path": str(STATE_PATH),
            "boot_id": state["boot_id"],
            "initial": initial,
            "guard_failure": guard_failure,
            "engine_failure": engine_failure,
            "stopped": stopped,
            "final": final,
        }

    def verify(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
            expected_image_sha512=CLOUD_IMAGE_SHA512,
        )
        state = _read_json(STATE_PATH, "IPS systemd qualification state")
        _validate_state(state, self.image_sha512)
        current_boot = _boot_id()
        if current_boot == state["boot_id"]:
            raise QualificationError("kernel boot ID did not change; reboot is unproven")
        packages = _verify_packages()
        if packages != state["packages"]:
            raise QualificationError("installed package identity changed across reboot")
        protected = _protected_inventory()
        if protected != state["protected_files"]:
            raise QualificationError("protected IPS files changed across reboot")
        reboot = _wait_active(timeout=180)
        health = _verify_health()
        checks = [
            _passed("platform.vm", platform),
            _passed("packages.installed", packages),
            _passed("lifecycle.initial", state["initial"]),
            _passed("failure.guard", state["guard_failure"]),
            _passed("lifecycle.rearmed", state["rearmed"]),
            _passed("failure.engine", state["engine_failure"]),
            _passed("lifecycle.stop", state["stopped"]),
            _passed(
                "reboot.recovered",
                {"before_boot_id": state["boot_id"], "after_boot_id": current_boot, **reboot},
            ),
            _passed("health.ips", health),
            _passed("protected.integrity", {"files": protected}),
        ]
        _run("ips.cleanup", ("/usr/bin/systemctl", "disable", "--now", TARGET), timeout=120)
        cleanup = _wait_inactive(timeout=90)
        checks.append(_passed("cleanup.fail-open", cleanup))
        return {
            "schema_version": 1,
            "status": "ips-systemd-vm-qualified",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "the unsigned artifact was installed only in a disposable qualification VM",
                "bounded guard and engine SIGKILL failures were exercised; kernel panic and power loss were not",
                "Dev20 separately qualifies measured NFQUEUE goodput, controlled overload, and listener-loss traffic continuity",
                "HA failover, hardware bypass, disk exhaustion, and long-duration soak remain outside this gate",
            ],
        }


def _verify_packages() -> dict[str, str]:
    result = _run(
        "ips.packages",
        (
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${Package}\t${Version}\t${db:Status-Status}\\n",
            *EXPECTED_PACKAGES,
        ),
    )
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or fields[2] != "installed" or fields[0] in observed:
            raise QualificationError("installed IPS package query is invalid")
        observed[fields[0]] = fields[1]
    if observed != EXPECTED_PACKAGES:
        raise QualificationError("installed IPS package versions are not approved")
    return observed


def _start_and_verify() -> dict[str, Any]:
    _run("ips.target-start", ("/usr/bin/systemctl", "start", TARGET), timeout=150)
    return _wait_active(timeout=120)


def _rearm(label: str) -> dict[str, Any]:
    if label not in {"guard", "engine"}:
        raise QualificationError("IPS re-arm label is not allowlisted")
    _run(f"ips.stop-after-{label}", ("/usr/bin/systemctl", "stop", TARGET), timeout=120)
    _wait_inactive(timeout=90)
    _run(f"ips.start-after-{label}", ("/usr/bin/systemctl", "start", TARGET), timeout=150)
    return _wait_active(timeout=120)


def _exercise_failure(unit: str, label: str) -> dict[str, Any]:
    before = _runtime_status()
    _run(
        f"ips.kill-{label}",
        ("/usr/bin/systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", unit),
    )
    inactive = _wait_policy(active=False, timeout=90)
    return {
        "unit": unit,
        "signal": "SIGKILL",
        "before_transaction_id": before["policy"]["transaction_id"],
        "policy_active_after": False,
        "listener_present_after": inactive["listener_present"],
        "fail_open": True,
    }


def _wait_active(*, timeout: float) -> dict[str, Any]:
    status = _wait_policy(active=True, timeout=timeout)
    units = {
        TARGET: _unit_state(TARGET),
        ENGINE: _unit_state(ENGINE),
        ACTIVATION: _unit_state(ACTIVATION),
        GUARD: _unit_state(GUARD),
    }
    if (
        units[TARGET]["ActiveState"] != "active"
        or units[ENGINE]["ActiveState"] != "active"
        or units[ENGINE]["SubState"] != "running"
        or units[ACTIVATION]["ActiveState"] != "active"
        or units[GUARD]["ActiveState"] != "active"
        or units[GUARD]["SubState"] != "running"
    ):
        raise QualificationError("private IPS systemd units are not fully active")
    queue = status["policy"]["queue"]
    listener = next((item for item in _read_listeners() if item["queue"] == queue), None)
    if listener is None or listener["queue_dropped"] or listener["user_dropped"]:
        raise QualificationError("active IPS queue listener is absent or already dropped packets")
    return {
        "target_active": True,
        "engine_pid": int(units[ENGINE]["MainPID"]),
        "guard_pid": int(units[GUARD]["MainPID"]),
        "transaction_id": status["policy"]["transaction_id"],
        "semantic_sha256": status["policy"]["semantic_sha256"],
        "queue": queue,
        "queue_dropped": 0,
        "user_dropped": 0,
    }


def _wait_inactive(*, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    _wait_policy(active=False, timeout=timeout)
    deadline = started + timeout
    while time.monotonic() < deadline:
        engine = _unit_state(ENGINE)
        activation = _unit_state(ACTIVATION)
        guard = _unit_state(GUARD)
        if all(
            unit["ActiveState"] in {"inactive", "failed"}
            for unit in (engine, activation, guard)
        ):
            final_status = _runtime_status()
            return {
                "policy_active": False,
                "engine_active": False,
                "activation_active": False,
                "guard_active": False,
                "fail_open": True,
                "listener_present": final_status["listener_present"],
            }
        time.sleep(0.5)
    raise QualificationError("IPS component remained active after target stop")


def _wait_policy(*, active: bool, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            last = _runtime_status()
            if last["policy"].get("active") is active:
                return last
        except QualificationError:
            pass
        time.sleep(0.5)
    raise QualificationError(f"IPS policy did not become {'active' if active else 'inactive'}")


def _runtime_status() -> dict[str, Any]:
    result = _run(
        "ips.bootstrap-status",
        ("/usr/lib/meercata/bin/meercata-ips-bootstrap", "status"),
        timeout=30,
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise QualificationError("IPS bootstrap status returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("policy"), dict)
        or type(value.get("listener_present")) is not bool
    ):
        raise QualificationError("IPS bootstrap status schema is invalid")
    return value


def _unit_state(unit: str) -> dict[str, str]:
    if unit not in {TARGET, ENGINE, ACTIVATION, GUARD}:
        raise QualificationError("IPS systemd unit is not allowlisted")
    result = _run(
        f"ips.show.{unit}",
        (
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,MainPID,Result,ExecMainStatus",
            "--no-pager",
        ),
    )
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            properties[key] = value
    required = {"ActiveState", "SubState"}
    if unit != TARGET:
        required.add("MainPID")
    if not required <= set(properties):
        raise QualificationError("IPS systemd state response is incomplete")
    return properties


def _verify_health() -> dict[str, Any]:
    result = _run(
        "ips.health",
        (
            "/usr/bin/setpriv",
            "--reuid=meercata",
            "--regid=meercata",
            "--init-groups",
            "/usr/bin/meercata",
            "health",
            "--json",
        ),
        timeout=45,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise QualificationError("IPS health returned invalid JSON") from exc
    if (
        not isinstance(report, dict)
        or report.get("mode") != "ips"
        or report.get("status") != "healthy"
        or report.get("exit_code") != 0
        or not isinstance(report.get("checks"), list)
        or any(item.get("status") != "healthy" for item in report["checks"])
    ):
        raise QualificationError("installed IPS health is not fully healthy")
    return {"status": "healthy", "checks": len(report["checks"]), "mode": "ips"}


def _protected_inventory() -> dict[str, str]:
    inventory: dict[str, str] = {}
    for path in PROTECTED_FILES:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise QualificationError(f"cannot read protected IPS file: {path}") from exc
        if not data or len(data) > 4 * 1024 * 1024:
            raise QualificationError(f"protected IPS file size is invalid: {path}")
        inventory[str(path)] = hashlib.sha256(data).hexdigest()
    return inventory


def _validate_state(value: Mapping[str, Any], image_sha512: str) -> None:
    required = {
        "schema_version", "status", "project_version", "image_sha512", "boot_id",
        "packages", "protected_files", "initial", "guard_failure", "rearmed",
        "engine_failure", "stopped", "final",
    }
    if (
        set(value) != required
        or value.get("schema_version") != 1
        or value.get("status") != "reboot-prepared"
        or value.get("project_version") != QUALIFIED_PROJECT_VERSION
        or value.get("image_sha512") != image_sha512
        or BOOT_ID_PATTERN.fullmatch(str(value.get("boot_id"))) is None
        or value.get("packages") != EXPECTED_PACKAGES
        or not isinstance(value.get("protected_files"), dict)
        or any(
            not isinstance(value.get(name), dict) or not value.get(name)
            for name in (
                "initial",
                "guard_failure",
                "rearmed",
                "engine_failure",
                "stopped",
                "final",
            )
        )
    ):
        raise QualificationError("IPS systemd prepared state is invalid")


def _boot_id() -> str:
    try:
        value = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise QualificationError("cannot read kernel boot ID") from exc
    if BOOT_ID_PATTERN.fullmatch(value) is None:
        raise QualificationError("kernel boot ID is invalid")
    return value


def _run(command_id: str, argv: tuple[str, ...], *, timeout: float = 60):
    result = CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=timeout)},
        max_output_bytes=1024 * 1024,
    ).run(command_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"{command_id} failed")
    return result


def _best_effort_stop() -> None:
    try:
        _run("ips.recovery-stop", ("/usr/bin/systemctl", "stop", TARGET), timeout=120)
    except Exception:
        pass


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="meercata-ips-systemd-vm-qualifier")
    parser.add_argument("phase", choices=("prepare", "verify"))
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--image-sha512", default=CLOUD_IMAGE_SHA512)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        qualifier = IpsSystemdVmQualifier(
            confirmation=args.confirm,
            image_sha512=args.image_sha512,
        )
        report = getattr(qualifier, args.phase)()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, QualificationError) as exc:
        print(f"meercata-ips-systemd-vm-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
