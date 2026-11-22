"""Qualify Suricata crash throttling and reboot recovery in a disposable VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import QualificationError
from meercata.systemd_vm_qualifier import (
    CLOUD_IMAGE_SHA512,
    _require_disposable_vm,
    _systemctl_show,
    _verify_packages,
    _verify_service_user_health,
    _verify_suricata_readiness,
)


CONFIRMATION = "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 RECOVERY VM"
# This destructive gate and its schema are evidence-bound to the dev16 artifact.
# A later package must use a new recorded gate instead of relabelling this result.
QUALIFIED_PROJECT_VERSION = "2.0.0.dev16"
STATE_PATH = Path("/var/lib/meercata/qualification/systemd-recovery-v1.json")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
SURICATA_UNIT = "suricata.service"
HEALTH_TIMER = "meercata-health.timer"
HEALTH_SERVICE = "meercata-health.service"
MAX_STATE_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT = 256 * 1024
_BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
PROTECTED_FILES = {
    "configuration": (Path("/etc/meercata/meercata.toml"), 1024 * 1024),
    "active_rules": (
        Path("/var/lib/suricata/rules/suricata.rules"),
        128 * 1024 * 1024,
    ),
    "package_manifest": (
        Path("/usr/lib/meercata/package-manifest.json"),
        2 * 1024 * 1024,
    ),
}


class RecoveryVmQualifier:
    """Run the guarded prepare and post-reboot verification phases."""

    def __init__(self, *, confirmation: str, image_sha512: str) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512

    def prepare(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
        )
        packages = _verify_packages()
        policy = _verify_supervision_policy()
        baseline = _verify_suricata_readiness()
        _verify_service_user_health()
        protected = _protected_inventory(PROTECTED_FILES)
        mutated = False
        try:
            mutated = True
            automatic = _exercise_automatic_restart(baseline)
            limited = _exercise_start_limit(automatic)
            recovered = _recover_after_limit()
        except Exception:
            if mutated:
                _best_effort_recover()
            raise
        timer = _enable_health_timer()
        state = {
            "schema_version": 1,
            "status": "reboot-prepared",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "image_sha512": self.image_sha512,
            "boot_id": _boot_id(),
            "packages": packages,
            "policy": policy,
            "automatic_restart": automatic,
            "start_limit": limited,
            "manual_recovery": recovered,
            "timer": timer,
            "protected_files": protected,
        }
        _write_prepared_state(STATE_PATH, state)
        return {
            "schema_version": 1,
            "status": "reboot-required",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "platform": platform,
            "state_path": str(STATE_PATH),
            "boot_id": state["boot_id"],
            "automatic_restart": automatic,
            "start_limit": limited,
            "manual_recovery": recovered,
            "timer": timer,
        }

    def verify(self) -> dict[str, Any]:
        platform = _require_disposable_vm(
            self.confirmation,
            self.image_sha512,
            expected_confirmation=CONFIRMATION,
        )
        state = _load_prepared_state(STATE_PATH)
        _validate_prepared_state(state, self.image_sha512)
        current_boot_id = _boot_id()
        if current_boot_id == state["boot_id"]:
            raise QualificationError("kernel boot ID did not change; reboot is unproven")
        packages = _verify_packages()
        if packages != state["packages"]:
            raise QualificationError("installed package identity changed across reboot")
        policy = _verify_supervision_policy()
        if policy != state["policy"]:
            raise QualificationError("supervision policy changed across reboot")
        readiness = _wait_for_readiness(timeout_seconds=120)
        timer = _wait_for_post_reboot_timer(timeout_seconds=190)
        health = _wait_for_health(timeout_seconds=60)
        protected = _protected_inventory(PROTECTED_FILES)
        if protected != state["protected_files"]:
            raise QualificationError("protected files changed across reboot")
        checks = [
            _passed("platform.vm", platform),
            _passed("packages.installed", packages),
            _passed("supervision.policy", policy),
            _passed("crash.auto-restart", state["automatic_restart"]),
            _passed("crash.start-limit", state["start_limit"]),
            _passed("recovery.manual", state["manual_recovery"]),
            _passed(
                "reboot.boot-changed",
                {"before": state["boot_id"], "after": current_boot_id},
            ),
            _passed("reboot.services", {**readiness, **timer}),
            _passed("health.after-reboot", health),
            _passed("protected.integrity", {"files": protected}),
        ]
        return {
            "schema_version": 1,
            "status": "recovery-vm-qualified",
            "project_version": QUALIFIED_PROJECT_VERSION,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "the Meercata artifact was installed only in a disposable qualification VM",
                "bounded SIGKILL failures were exercised; OOM, kernel panic, disk failure, and abrupt power loss were not",
                "only IDS service and health-timer recovery were exercised; IPS and NFQUEUE were not",
                "interrupted RuleOps transactions, HA failover, retention, removal, and purge were not exercised",
            ],
        }


def _verify_supervision_policy() -> dict[str, Any]:
    properties = _systemctl_show(
        SURICATA_UNIT,
        (
            "Type",
            "Restart",
            "RestartUSec",
            "StartLimitBurst",
            "StartLimitIntervalUSec",
            "TimeoutStartUSec",
            "TimeoutStopUSec",
            "OOMPolicy",
        ),
    )
    expected = {
        "Type": "notify",
        "Restart": "on-failure",
        "RestartUSec": "10s",
        "StartLimitBurst": "3",
        "StartLimitIntervalUSec": "5min",
        "TimeoutStartUSec": "1min 30s",
        "TimeoutStopUSec": "1min",
        "OOMPolicy": "stop",
    }
    if properties != expected:
        raise QualificationError("installed Suricata supervision policy is invalid")
    return {
        "type": "notify",
        "restart": "on-failure",
        "restart_delay_seconds": 10,
        "start_limit_burst": 3,
        "start_limit_interval_seconds": 300,
        "startup_timeout_seconds": 90,
        "shutdown_timeout_seconds": 60,
        "oom_policy": "stop",
    }


def _service_state() -> dict[str, Any]:
    properties = _systemctl_show(
        SURICATA_UNIT,
        (
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
        ),
    )
    try:
        main_pid = int(properties["MainPID"])
        restarts = int(properties["NRestarts"])
        exit_status = int(properties["ExecMainStatus"])
    except ValueError as exc:
        raise QualificationError("Suricata service counters are invalid") from exc
    if main_pid < 0 or restarts < 0 or exit_status < 0:
        raise QualificationError("Suricata service counters are out of range")
    return {
        "active_state": properties["ActiveState"],
        "sub_state": properties["SubState"],
        "main_pid": main_pid,
        "restart_count": restarts,
        "result": properties["Result"],
        "exit_status": exit_status,
    }


def _exercise_automatic_restart(baseline: Mapping[str, Any]) -> dict[str, Any]:
    before_pid = _positive_integer(baseline.get("main_pid"), "baseline PID")
    before_restarts = _nonnegative_integer(
        baseline.get("restart_count"), "baseline restart count"
    )
    _kill_suricata()
    after = _wait_for_restart(
        before_pid,
        before_restarts,
        timeout_seconds=150,
    )
    return {
        "signal": "SIGKILL",
        "before_pid": before_pid,
        "after_pid": after["main_pid"],
        "before_restart_count": before_restarts,
        "after_restart_count": after["restart_count"],
        "active_state": "active",
        "sub_state": "running",
    }


def _exercise_start_limit(automatic: Mapping[str, Any]) -> dict[str, Any]:
    current_pid = _positive_integer(automatic.get("after_pid"), "restarted PID")
    restart_count = _nonnegative_integer(
        automatic.get("after_restart_count"), "restart count"
    )
    for injection in range(1, 6):
        _kill_suricata()
        outcome = _wait_for_restart_or_limit(
            current_pid,
            restart_count,
            timeout_seconds=130,
        )
        if outcome["kind"] == "limited":
            return {
                "additional_sigkills": injection,
                "active_state": "failed",
                "result": "start-limit-enforced",
                "service_result": outcome["state"]["result"],
                "restart_count": outcome["state"]["restart_count"],
                "start_attempt_exit_code": outcome["start_attempt_exit_code"],
                "burst": 3,
                "interval_seconds": 300,
            }
        current_pid = outcome["state"]["main_pid"]
        restart_count = outcome["state"]["restart_count"]
    raise QualificationError("Suricata start limit was not reached within the bound")


def _recover_after_limit() -> dict[str, Any]:
    _run("systemd.reset-failed", ("/usr/bin/systemctl", "reset-failed", SURICATA_UNIT))
    _run(
        "systemd.recovery.start",
        ("/usr/bin/systemctl", "start", SURICATA_UNIT),
        timeout_seconds=110,
    )
    readiness = _wait_for_readiness(timeout_seconds=120)
    health = _wait_for_health(timeout_seconds=60)
    return {
        "reset_failed": True,
        "active_state": readiness["active_state"],
        "sub_state": readiness["sub_state"],
        "main_pid": readiness["main_pid"],
        "health_status": health["status"],
        "healthy_checks": health["healthy_checks"],
    }


def _kill_suricata() -> None:
    _run(
        "systemd.kill-suricata",
        (
            "/usr/bin/systemctl",
            "kill",
            "--kill-who=main",
            "--signal=SIGKILL",
            SURICATA_UNIT,
        ),
    )


def _wait_for_restart(
    previous_pid: int,
    previous_restarts: int,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        state = _service_state()
        if (
            state["active_state"] == "active"
            and state["sub_state"] == "running"
            and state["main_pid"] > 1
            and state["main_pid"] != previous_pid
            and state["restart_count"] > previous_restarts
        ):
            return state
        time.sleep(1)
    raise QualificationError("Suricata did not restart within the bounded wait")


def _wait_for_restart_or_limit(
    previous_pid: int,
    previous_restarts: int,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        state = _service_state()
        if state["active_state"] == "failed" and state["restart_count"] >= 3:
            rejection = _require_start_attempt_rejected(state)
            return {"kind": "limited", "state": state, **rejection}
        # The first injected failure already proves a complete ready restart.
        # Subsequent failures may be injected as soon as systemd has launched a
        # new main process, keeping all start attempts inside the fixed rolling
        # rate-limit window even when full-ruleset validation is slow.
        if (
            state["active_state"] in {"activating", "active"}
            and state["main_pid"] > 1
            and state["main_pid"] != previous_pid
            and state["restart_count"] > previous_restarts
        ):
            return {"kind": "restarted", "state": state}
        time.sleep(1)
    raise QualificationError("Suricata restart/start-limit result timed out")


def _require_start_attempt_rejected(before: Mapping[str, Any]) -> dict[str, int]:
    command_id = "systemd.start-limit.rejected-start"
    result = CommandRunner(
        {
            command_id: CommandDefinition.fixed(
                ("/usr/bin/systemctl", "start", SURICATA_UNIT),
                timeout_seconds=20,
            )
        },
        max_output_bytes=MAX_COMMAND_OUTPUT,
    ).run(command_id)
    if result.succeeded or result.timed_out or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError("Suricata start limit did not reject a new start")
    after = _service_state()
    if (
        after["active_state"] != "failed"
        or after["main_pid"] != 0
        or after["restart_count"] != before["restart_count"]
    ):
        raise QualificationError("rejected start changed Suricata service state")
    return {"start_attempt_exit_code": result.return_code}


def _wait_for_readiness(*, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: QualificationError | None = None
    while time.monotonic() < deadline:
        try:
            return _verify_suricata_readiness()
        except QualificationError as exc:
            last_error = exc
            time.sleep(1)
    raise QualificationError("Suricata readiness did not recover in time") from last_error


def _wait_for_health(*, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: QualificationError | None = None
    while time.monotonic() < deadline:
        try:
            return _verify_service_user_health()
        except QualificationError as exc:
            last_error = exc
            time.sleep(2)
    raise QualificationError("healthy IDS state did not recover in time") from last_error


def _enable_health_timer() -> dict[str, Any]:
    _run(
        "health.timer.enable",
        ("/usr/bin/systemctl", "enable", "--now", HEALTH_TIMER),
        timeout_seconds=30,
    )
    _run(
        "health.timer.restart",
        ("/usr/bin/systemctl", "restart", HEALTH_TIMER),
        timeout_seconds=30,
    )
    return _timer_state(require_trigger=False)


def _timer_state(*, require_trigger: bool) -> dict[str, Any]:
    enabled = _run(
        "health.timer.enabled",
        ("/usr/bin/systemctl", "is-enabled", HEALTH_TIMER),
    ).stdout.strip()
    properties = _systemctl_show(
        HEALTH_TIMER,
        (
            "ActiveState",
            "SubState",
            "Unit",
            "TimersMonotonic",
            "LastTriggerUSecMonotonic",
        ),
    )
    schedules = properties["TimersMonotonic"]
    trigger = properties["LastTriggerUSecMonotonic"]
    triggered = trigger not in {"", "0", "infinity"}
    if (
        enabled != "enabled"
        or properties["ActiveState"] != "active"
        or properties["SubState"] not in {"waiting", "running"}
        or properties["Unit"] != HEALTH_SERVICE
        or "OnBootUSec=2min" not in schedules
        or "OnUnitActiveUSec=1min" not in schedules
        or (require_trigger and not triggered)
    ):
        raise QualificationError("health timer persistence/execution is invalid")
    return {
        "timer_enabled": True,
        "timer_active": True,
        "timer_sub_state": properties["SubState"],
        "timer_unit": HEALTH_SERVICE,
        "on_boot": "2min",
        "interval": "1min",
        "triggered_this_boot": triggered,
    }


def _wait_for_post_reboot_timer(*, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: QualificationError | None = None
    while time.monotonic() < deadline:
        try:
            timer = _timer_state(require_trigger=True)
            service = _systemctl_show(
                HEALTH_SERVICE,
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
                raise QualificationError("post-reboot health oneshot did not pass")
            return {**timer, "health_oneshot_result": "success"}
        except QualificationError as exc:
            last_error = exc
            time.sleep(2)
    raise QualificationError("health timer did not execute successfully after reboot") from last_error


def _protected_inventory(
    paths: Mapping[str, tuple[Path, int]],
    *,
    required_uid: int | None = 0,
) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for label, (path, maximum) in paths.items():
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
            or metadata.st_mode & 0o002
            or (required_uid is not None and metadata.st_uid != required_uid)
        ):
            raise QualificationError(f"protected file is unsafe: {label}")
        content = path.read_bytes()
        if len(content) != metadata.st_size:
            raise QualificationError(f"protected file changed while reading: {label}")
        inventory[label] = {
            "path": str(path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
    return inventory


def _boot_id(path: Path = BOOT_ID_PATH) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128:
        raise QualificationError("kernel boot ID source is unsafe")
    value = path.read_text(encoding="ascii").strip()
    if _BOOT_ID.fullmatch(value) is None:
        raise QualificationError("kernel boot ID is invalid")
    return value


def _write_prepared_state(
    path: Path,
    value: Mapping[str, Any],
    *,
    required_uid: int | None = 0,
) -> None:
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o022
            or (required_uid is not None and metadata.st_uid != required_uid)
        ):
            raise QualificationError("qualification state directory is unsafe")
    else:
        parent.mkdir(mode=0o700)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_STATE_BYTES:
        raise QualificationError("qualification state is oversized")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_prepared_state(
    path: Path,
    *,
    required_uid: int | None = 0,
) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_STATE_BYTES
        or (required_uid is not None and metadata.st_uid != required_uid)
    ):
        raise QualificationError("prepared qualification state is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("prepared qualification state is invalid") from exc
    if not isinstance(value, dict):
        raise QualificationError("prepared qualification state is invalid")
    return value


def _validate_prepared_state(value: Mapping[str, Any], image_sha512: str) -> None:
    required = {
        "schema_version",
        "status",
        "project_version",
        "image_sha512",
        "boot_id",
        "packages",
        "policy",
        "automatic_restart",
        "start_limit",
        "manual_recovery",
        "timer",
        "protected_files",
    }
    if (
        set(value) != required
        or value.get("schema_version") != 1
        or value.get("status") != "reboot-prepared"
        or value.get("project_version") != QUALIFIED_PROJECT_VERSION
        or value.get("image_sha512") != image_sha512
        or not isinstance(value.get("boot_id"), str)
        or _BOOT_ID.fullmatch(value["boot_id"]) is None
    ):
        raise QualificationError("prepared qualification state identity is invalid")
    for key in required - {
        "schema_version",
        "status",
        "project_version",
        "image_sha512",
        "boot_id",
    }:
        if not isinstance(value.get(key), dict) or not value[key]:
            raise QualificationError("prepared qualification state inventory is invalid")


def _best_effort_recover() -> None:
    for command_id, argv in (
        (
            "recovery.best-effort.reset",
            ("/usr/bin/systemctl", "reset-failed", SURICATA_UNIT),
        ),
        (
            "recovery.best-effort.start",
            ("/usr/bin/systemctl", "start", SURICATA_UNIT),
        ),
    ):
        CommandRunner(
            {
                command_id: CommandDefinition.fixed(
                    argv,
                    timeout_seconds=120,
                )
            },
            max_output_bytes=MAX_COMMAND_OUTPUT,
        ).run(command_id)


def _run(
    command_id: str,
    argv: tuple[str, ...],
    *,
    timeout_seconds: float = 30,
):
    result = CommandRunner(
        {
            command_id: CommandDefinition.fixed(
                argv,
                timeout_seconds=timeout_seconds,
            )
        },
        max_output_bytes=MAX_COMMAND_OUTPUT,
    ).run(command_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"recovery qualification command failed: {command_id}")
    return result


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 1:
        raise QualificationError(f"{label} is invalid")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QualificationError(f"{label} is invalid")
    return value


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.recovery_vm_qualifier",
        description="Qualify Suricata crash throttling and reboot recovery",
    )
    parser.add_argument("phase", choices=("prepare", "verify"))
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
    qualifier = RecoveryVmQualifier(
        confirmation=arguments.confirmation,
        image_sha512=arguments.image_sha512,
    )
    try:
        report = qualifier.prepare() if arguments.phase == "prepare" else qualifier.verify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, QualificationError) as exc:
        print(f"meercata-recovery-vm: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
