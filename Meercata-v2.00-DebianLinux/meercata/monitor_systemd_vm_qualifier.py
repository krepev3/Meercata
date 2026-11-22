"""Installed monitoring, retention, and reboot gate for a disposable Debian VM."""

from __future__ import annotations

import argparse
import errno
import gzip
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import QualificationError
from meercata.monitor_delivery import (
    DeliveryConfig, HttpsDeliveryTransport, _list_envelopes, _read_envelope, _read_receipts,
)
from meercata.paths import ensure_secure_directory
from meercata.monitor_tls_qualifier import _Collector, _CollectorState, _generate_pki
from meercata.recovery_vm_qualifier import (
    _boot_id,
    _load_prepared_state,
    _protected_inventory,
    _write_prepared_state,
)
from meercata.systemd_vm_qualifier import (
    _require_disposable_vm,
    _systemctl_show,
    _verify_service_user_health,
    _verify_suricata_readiness,
)

CONFIRMATION = "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 MONITOR SYSTEMD VM"
QUALIFIED_PROJECT_VERSION = "2.0.0.dev25"
CLOUD_IMAGE_SHA512 = (
    "37cb32b320820417eb04b335afcf489bfb4cecce4a957190d09cb2bffbe02b56a1"
    "cadd62d78c6ead92aa7839d5ea65e4260f994bbb4b54490df59fdf11ee1d97"
)
WORK = Path("/var/lib/meercata/qualification/monitor-systemd-v1")
STATE = WORK / "prepared.json"
CONFIG = Path("/etc/meercata/meercata.toml")
TOKEN = Path("/etc/meercata/credentials/dev25-token")
CA = Path("/etc/meercata/credentials/dev25-ca.pem")
MONITOR_STATE = Path("/var/lib/meercata/monitor/state.json")
LOG_DIR = Path("/var/log/meercata/monitor")
EVENTS = LOG_DIR / "transitions.jsonl"
RECEIPTS = LOG_DIR / "delivery-receipts.jsonl"
OUTBOX = Path("/var/lib/meercata/monitor/outbox")
PORT = 18443
ENDPOINT = f"https://localhost:{PORT}/v1/meercata-events"
SERVICES = (
    "meercata-monitor.service",
    "meercata-monitor-freshness.service",
    "meercata-monitor-delivery.service",
    "meercata-monitor-delivery-health.service",
)
TIMERS = tuple(unit.removesuffix(".service") + ".timer" for unit in SERVICES)
PROTECTED = {
    "configuration": (CONFIG, 1024 * 1024),
    "suricata_configuration": (Path("/etc/suricata/suricata.yaml"), 4 * 1024 * 1024),
    "rules": (Path("/var/lib/suricata/rules/suricata.rules"), 128 * 1024 * 1024),
    "manifest": (Path("/usr/lib/meercata/package-manifest.json"), 2 * 1024 * 1024),
    "sudoers": (Path("/etc/sudoers.d/meercata"), 64 * 1024),
}
CHECK_IDS = (
    "platform.vm", "packages.installed", "permissions.isolation",
    "monitoring.systemd", "delivery.systemd", "credentials.rotation",
    "tls.ca-rotation", "scheduler.freshness", "retention.rotation",
    "storage.full", "recovery.restart", "timers.before-reboot",
    "reboot.monitoring", "protected.integrity", "cleanup.disabled",
)
_PROBE_STARTS: dict[str, int] = {}


class MonitorSystemdVmQualifier:
    """Operate only fixed units and paths after the disposable-VM guard passes."""

    def __init__(self, *, confirmation: str, image_sha512: str) -> None:
        self.confirmation = confirmation
        self.image_sha512 = image_sha512

    def _guard(self) -> dict[str, Any]:
        if __version__ != QUALIFIED_PROJECT_VERSION:
            raise QualificationError("this gate requires the dev25 package")
        return _require_disposable_vm(
            self.confirmation, self.image_sha512,
            expected_confirmation=CONFIRMATION,
            expected_image_sha512=CLOUD_IMAGE_SHA512,
        )

    def prepare(self) -> dict[str, Any]:
        platform = self._guard()
        packages = _packages()
        _verify_suricata_readiness()
        _verify_service_user_health()
        protected = _protected_inventory(PROTECTED)
        _preflight()
        ensure_secure_directory(WORK.parent, mode=0o700)
        WORK.mkdir(mode=0o700)
        original = CONFIG.read_bytes()
        metadata = CONFIG.stat()
        (WORK / "original.toml").write_bytes(original)
        (WORK / "original.toml").chmod(0o600)
        checks = [_passed("platform.vm", platform), _passed("packages.installed", packages)]
        try:
            first = _generate_pki(WORK / "pki1", serial=2501, name="Dev25 CA 1")
            second = _generate_pki(WORK / "pki2", serial=2502, name="Dev25 CA 2")
            token = secrets.token_urlsafe(32)
            _install_credential(TOKEN, (token + "\n").encode())
            _install_credential(CA, first["ca_cert"].read_bytes())
            _replace_file(CONFIG, original + _delivery_table(), metadata.st_uid,
                          metadata.st_gid, stat.S_IMODE(metadata.st_mode))
            checks.append(_passed("permissions.isolation", _permissions()))
            collector_state = _CollectorState(token)
            with _Collector(collector_state, first["server_cert"], first["server_key"], port=PORT):
                _progress("installed producer and delivery")
                _start(SERVICES[0], 0)
                report = _journal_report(SERVICES[0])
                _require(report.get("status") == "healthy", "producer is not healthy")
                checks.append(_passed("monitoring.systemd", {
                    "status": "healthy", "service_user": "meercata",
                    "sequence": report["sequence"], "journal_json": True,
                }))
                _start(SERVICES[2], 0)
                delivery = _journal_report(SERVICES[2])
                _require(delivery.get("delivered", 0) >= 1 and delivery.get("pending") == 0,
                         "installed HTTPS delivery did not drain the outbox")
                checks.append(_passed("delivery.systemd", {
                    "delivered": delivery["delivered"], "pending": 0,
                    "collector_events": len(collector_state.events), "verified_tls": True,
                }))
                _progress("installed credential rotation")
                token = _rotate_token(collector_state, token)
                checks.append(_passed("credentials.rotation", {
                    "retired_http_status": 401, "installed_delivery_reloaded": True,
                    "credential_mode": "0640", "credential_root_owned": True,
                }))
                # No manual service starts between this boundary and the four journal reports.
                boundary = time.monotonic_ns() // 1000
                _enable_timers()
                _progress("stock timer execution in this boot")
                timers = _wait_timers(timeout=420, since_monotonic=boundary)
                checks.append(_passed("timers.before-reboot", {"timers": timers}))
                _progress("real stale-scheduler detection (three-minute threshold)")
                freshness = _freshness_failure()
                checks.append(_passed("scheduler.freshness", freshness))
                _progress("logrotate retention and installed writer recovery")
                checks.append(_passed("retention.rotation", _rotation()))
                _progress("bounded disk-full injection in guest-only tmpfs")
                checks.append(_passed("storage.full", _disk_full()))
                _start(SERVICES[2], 0)
                before = MONITOR_STATE.read_bytes()
                _start(SERVICES[0], 0)
                after = json.loads(MONITOR_STATE.read_bytes())
                _require(after["sequence"] == json.loads(before)["sequence"],
                         "restarted producer duplicated an unchanged transition")
                checks.append(_passed("recovery.restart", {
                    "sequence_preserved": True, "duplicate_transition": False,
                    "pending": _service_json("delivery-status")["pending"],
                }))
                _pause()
            _progress("installed CA rotation and persistent outage retry")
            with _Collector(collector_state, second["server_cert"], second["server_key"], port=PORT):
                _transition()
                _start(SERVICES[2], 0)
                failed = _journal_report(SERVICES[2])
                _require(failed.get("retried", 0) >= 1 and failed.get("delivered") == 0,
                         "retired CA did not block installed delivery")
                _install_credential(CA, second["ca_cert"].read_bytes())
                time.sleep(2)
                _start(SERVICES[2], 0)
                recovered = _journal_report(SERVICES[2])
                _require(recovered.get("delivered", 0) >= 1 and recovered.get("pending") == 0,
                         "installed worker did not reload the rotated CA")
                _recover_suricata()
                _start(SERVICES[0], 0)
                _start(SERVICES[2], 0)
            # Leave an ordinary durable transition queued during an actual outage.
            _transition()
            _recover_suricata()
            _start(SERVICES[0], 0)
            _start(SERVICES[2], 0)
            pending = _service_json("delivery-status")
            _require(pending["pending"] >= 1 and pending["dead_letters"] == 0,
                     "no pending retry was retained for reboot")
            checks.append(_passed("tls.ca-rotation", {
                "retired_ca_blocked": True, "rotated_ca_delivered": True,
                "pending_before_reboot": pending["pending"],
            }))
            _enable_timers()
            pending_ids = [_read_envelope(path)["event_id"] for path in _list_envelopes(OUTBOX, 1000)]
            state = {
                "schema_version": 1, "status": "reboot-prepared",
                "project_version": QUALIFIED_PROJECT_VERSION,
                "image_sha512": self.image_sha512, "boot_id": _boot_id(),
                "packages": packages, "protected_files": protected,
                "active_files": _protected_inventory(PROTECTED),
                "checks": checks, "pending": len(pending_ids), "pending_event_ids": pending_ids,
                "sequence": json.loads(MONITOR_STATE.read_bytes())["sequence"],
            }
            _write_prepared_state(STATE, state)
            return {
                "schema_version": 1, "status": "reboot-required",
                "project_version": QUALIFIED_PROJECT_VERSION, "platform": platform,
                "boot_id": state["boot_id"], "pending": pending["pending"],
                "checks": checks,
            }
        except BaseException:
            try:
                _cleanup(original)
            except Exception as cleanup_error:
                _progress(f"cleanup also failed: {cleanup_error}")
            raise

    def verify(self) -> dict[str, Any]:
        platform = self._guard()
        state = _load_prepared_state(STATE)
        _validate_state(state, self.image_sha512)
        boot = _boot_id()
        _require(boot != state["boot_id"], "kernel boot ID did not change; reboot is unproven")
        _require(_packages() == state["packages"], "packages changed across reboot")
        _require(_protected_inventory(PROTECTED) == state["active_files"],
                 "protected files changed across reboot")
        original = (WORK / "original.toml").read_bytes()
        _require(hashlib.sha256(original).hexdigest() ==
                 state["protected_files"]["configuration"]["sha256"],
                 "original configuration backup changed")
        token = TOKEN.read_text().strip()
        pki = WORK / "pki2"
        try:
            collector_state = _CollectorState(token)
            with _Collector(collector_state, pki / "server.pem", pki / "server.key", port=PORT):
                _progress("post-reboot stock timers, service identity, and outbox recovery")
                timers = _wait_timers(timeout=480)
                status = _service_json("delivery-status")
                _require(status["pending"] == 0 and status["dead_letters"] == 0,
                         "outbox did not recover after reboot")
                expected_ids = set(state["pending_event_ids"])
                receipts = _read_receipts(RECEIPTS)
                _require(expected_ids <= set(collector_state.events) and all(
                    receipts.get(event_id, {}).get("status") == "delivered"
                    for event_id in expected_ids
                ), "pre-reboot event identities lack post-reboot collector acceptance and receipts")
                observed = json.loads(MONITOR_STATE.read_bytes())
                _require(observed["sequence"] >= state["sequence"],
                         "monitor sequence regressed across reboot")
                _verify_service_user_health()
            checks = list(state["checks"])
            checks.append(_passed("reboot.monitoring", {
                "before_boot_id": state["boot_id"], "after_boot_id": boot,
                "timers": timers, "pending": 0, "dead_letters": 0,
                "recovered_events": len(expected_ids), "recovered_event_ids": sorted(expected_ids),
                "sequence_before": state["sequence"], "sequence_after": observed["sequence"],
            }))
        finally:
            _cleanup(original)
        protected = _protected_inventory(PROTECTED)
        _require(protected == state["protected_files"], "protected files were not restored")
        checks.append(_passed("protected.integrity", {"files": protected}))
        checks.append(_passed("cleanup.disabled", _verify_cleanup()))
        checks.sort(key=lambda check: CHECK_IDS.index(check["check_id"]))
        _require(tuple(check["check_id"] for check in checks) == CHECK_IDS,
                 "qualification check inventory is incomplete")
        return {
            "schema_version": 1, "status": "monitor-systemd-vm-qualified",
            "project_version": QUALIFIED_PROJECT_VERSION, "platform": platform,
            "checks": checks,
            "limitations": [
                "installed only in a disposable checksum-pinned Debian 13 QEMU/KVM guest",
                "loopback collector, generated credentials, and generated CAs only; no production collector or external DNS/proxy was qualified",
                "forced rotations prove finite generation retention, not elapsed weekly retention or a 24–72-hour soak",
                "disk-full injection covered a bounded log tmpfs; whole-root exhaustion, power loss, and storage hardware failures remain open",
                "deployment traffic capacity, NIC/multi-queue behavior, release signing custody, and public mutation gates remain separate",
            ],
        }


def _preflight() -> None:
    _require(not WORK.exists() and not WORK.is_symlink(), "qualification workspace already exists")
    _require(not TOKEN.exists() and not TOKEN.is_symlink() and
             not CA.exists() and not CA.is_symlink(), "qualification credentials already exist")
    config = tomllib.loads(CONFIG.read_text())
    _require("monitor_delivery" not in config, "qualification requires a config without delivery")
    for timer in (*TIMERS, "meercata-health.timer"):
        result = _command(("/usr/bin/systemctl", "is-enabled", timer), allowed=(0, 1))
        _require(result.stdout.strip() == "disabled", "qualification requires disabled timers")
    for directory in (OUTBOX, Path("/var/lib/meercata/monitor/dead-letter"), LOG_DIR):
        _require(not any(directory.iterdir()), "qualification requires empty monitoring state/logs")
    _require(not MONITOR_STATE.exists(), "qualification requires an uninitialized monitor")


def _packages() -> dict[str, str]:
    result = _command(("/usr/bin/dpkg-query", "--show",
                       "--showformat=${Package}\t${Version}\t${db:Status-Status}\\n",
                       "meercata", "suricata", "suricata-update", "systemd", "logrotate"))
    packages: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        _require(len(fields) == 3 and fields[2] == "installed" and fields[0] not in packages,
                 "installed package inventory is invalid")
        packages[fields[0]] = fields[1]
    _require(set(packages) == {"meercata", "suricata", "suricata-update", "systemd", "logrotate"}
             and packages["meercata"] == "2.0.0~dev25-1", "installed dev25 package is required")
    return packages


def _delivery_table() -> bytes:
    return (
        f'\n[monitor_delivery]\nendpoint="{ENDPOINT}"\n'
        f'token_file="{TOKEN}"\nca_file="{CA}"\n'
        'timeout_seconds=2\nbase_retry_seconds=1\nmax_retry_seconds=2\n'
        'max_attempts=20\nbatch_size=100\n'
    ).encode()


def _replace_file(path: Path, data: bytes, uid: int, gid: int, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=".dev25-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _install_credential(path: Path, data: bytes) -> None:
    _require(path in {TOKEN, CA}, "credential destination is not allowlisted")
    account = pwd.getpwnam("meercata")
    _replace_file(path, data, 0, account.pw_gid, 0o640)


def _permissions() -> dict[str, Any]:
    account = pwd.getpwnam("meercata")
    for path in (TOKEN, CA):
        meta = path.lstat()
        _require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
                 meta.st_gid == account.pw_gid and stat.S_IMODE(meta.st_mode) == 0o640,
                 "credential ownership or mode is unsafe")
    script = (
        "import os; from pathlib import Path; "
        "assert not os.access('/var/lib/meercata/privileged',os.R_OK); "
        "assert not os.access('/var/lib/meercata/privileged',os.W_OK); "
        "assert not os.access('/var/log/meercata/privileged',os.R_OK); "
        "assert not os.access('/var/log/meercata/privileged',os.W_OK); "
        "assert not os.access('/etc/meercata/meercata.toml',os.W_OK); "
        "assert Path('/etc/meercata/credentials/dev25-token').read_bytes(); "
        "assert Path('/etc/meercata/credentials/dev25-ca.pem').read_bytes()"
    )
    _as_service(("/usr/bin/python3", "-I", "-c", script))
    for unit in SERVICES:
        props = _systemctl_show(unit, ("User", "Group", "ProtectSystem"))
        _require(props == {"User": "meercata", "Group": "meercata", "ProtectSystem": "strict"},
                 "installed service identity or filesystem policy is invalid")
        if unit != SERVICES[0]:
            policy = _systemctl_show(unit, ("NoNewPrivileges", "CapabilityBoundingSet"))
            _require(policy == {"NoNewPrivileges": "yes", "CapabilityBoundingSet": ""},
                     "read-only/delivery service privilege policy is invalid")
    return {"service_user": "meercata", "credentials_readable": True,
            "privileged_state_denied": True, "configuration_write_denied": True,
            "services_checked": len(SERVICES)}


def _enable_timers() -> None:
    _command(("/usr/bin/systemctl", "enable", *TIMERS))
    _command(("/usr/bin/systemctl", "start", *TIMERS))


def _start(unit: str, exit_status: int) -> dict[str, str]:
    _require(unit in SERVICES, "service is not allowlisted")
    # Manual probes must get their own invocation even if a stock timer is
    # concurrently running this oneshot. Timer-only checks never call this helper.
    # An already collected inactive unit has no failure state to reset (exit 1).
    _command(("/usr/bin/systemctl", "reset-failed", unit), allowed=(0, 1))
    _PROBE_STARTS[unit] = time.monotonic_ns() // 1000
    _command(("/usr/bin/systemctl", "restart", unit), allowed=(0, 1), timeout=90)
    props = _systemctl_show(unit, ("Result", "ExecMainStatus"))
    _require(props == {"Result": "success" if exit_status == 0 else "exit-code",
                       "ExecMainStatus": str(exit_status)},
             f"installed service returned an unexpected result: {unit}: {props}")
    return props


def _journal_report(unit: str, *, since_monotonic: int | None = None) -> dict[str, Any]:
    _require(unit in SERVICES, "journal unit is not allowlisted")
    since = _PROBE_STARTS.get(unit, 0) if since_monotonic is None else since_monotonic
    _require(type(since) is int and since > 0, "service invocation time boundary is invalid")
    # Successful inactive oneshots can lose systemctl's InvocationID during GC.
    # Journald retains both the invocation ID and monotonic emission timestamp.
    result = _command(("/usr/bin/journalctl", "--boot", "--unit=" + unit,
                       "--output=json", "--all", "--no-pager", "--lines=20"))
    for line in reversed(result.stdout.splitlines()):
        try:
            record = json.loads(line)
            if int(record.get("__MONOTONIC_TIMESTAMP", "0")) < since:
                continue
            invocation = record.get("_SYSTEMD_INVOCATION_ID", "")
            if not isinstance(invocation, str) or re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
                continue
            value = json.loads(record.get("MESSAGE", ""))
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict) and value.get("schema_version") == 1:
            return value
    raise QualificationError("installed service emitted no JSON observation in this boot")


def _service_json(action: str) -> dict[str, Any]:
    _require(action in {"delivery-status", "delivery-health", "status", "freshness"},
             "monitor query is not allowlisted")
    result = _as_service(("/usr/bin/meercata", "monitor", action, "--json"), allowed=(0, 1, 2, 3))
    value = json.loads(result.stdout)
    _require(isinstance(value, dict) and value.get("schema_version") == 1,
             "monitor query did not emit its JSON contract")
    return value


def _transition() -> None:
    _command(("/usr/bin/systemctl", "stop", "suricata.service"), timeout=90)
    _start(SERVICES[0], 2)
    _require(_journal_report(SERVICES[0]).get("transition_emitted") is True,
             "service failure did not produce a new durable transition")


def _recover_suricata() -> None:
    # The gate deliberately repeats normal starts inside the production rate-limit
    # window. Reset only this disposable guest's failure accounting between probes.
    _command(("/usr/bin/systemctl", "reset-failed", "suricata.service"))
    _command(("/usr/bin/systemctl", "start", "suricata.service"), timeout=150)
    _wait(lambda: _verify_service_user_health(), timeout=90,
          label="fully healthy Suricata after recovery")


def _rotate_token(state: _CollectorState, old: str) -> str:
    new = secrets.token_urlsafe(32)
    state.token = new
    rejected = HttpsDeliveryTransport().send(
        DeliveryConfig(ENDPOINT, TOKEN, timeout_seconds=2, ca_file=CA), old,
        "f" * 64, {"qualification": "retired-token"},
    )
    _require(rejected.http_status == 401, "collector accepted a retired token")
    _install_credential(TOKEN, (new + "\n").encode())
    _transition()
    _start(SERVICES[2], 0)
    _require(_journal_report(SERVICES[2]).get("delivered", 0) >= 1,
             "installed worker did not reload the rotated token")
    _recover_suricata()
    _start(SERVICES[0], 0)
    _start(SERVICES[2], 0)
    return new


def _freshness_failure() -> dict[str, Any]:
    _command(("/usr/bin/systemctl", "stop", TIMERS[0], SERVICES[0]))
    _wait(lambda: _require(_service_json("freshness").get("status") == "stale",
                          "observation is still fresh") or True,
          timeout=210, label="stale producer", interval=2)
    _start(SERVICES[1], 2)
    stale = _journal_report(SERVICES[1])
    _require(stale.get("age_seconds", 0) > 180, "freshness failure was not time-based")
    _start(SERVICES[0], 0)
    _start(SERVICES[1], 0)
    _command(("/usr/bin/systemctl", "start", TIMERS[0]))
    return {"producer_timer_stopped": True, "stale_exit_code": 2,
            "age_seconds": stale["age_seconds"], "recovered_exit_code": 0}


def _pause() -> None:
    _command(("/usr/bin/systemctl", "stop", *TIMERS, *SERVICES), timeout=120)


def _rotation() -> dict[str, Any]:
    _pause()
    records = {path: path.read_bytes().splitlines(keepends=True)[-1] for path in (EVENTS, RECEIPTS)}
    saved_state = MONITOR_STATE.read_bytes()
    for _ in range(14):
        for path, record in records.items():
            if path.stat().st_size == 0:
                with path.open("ab") as stream:
                    stream.write(record)
        _command(("/usr/sbin/logrotate", "--force", "--state=" + str(WORK / "logrotate.state"),
                  "/etc/logrotate.d/meercata-monitor"))
    account = pwd.getpwnam("meercata")
    for path, record in records.items():
        archives = list(LOG_DIR.glob(path.name + ".[0-9]*"))
        _require({p.name.removeprefix(path.name + ".") for p in archives} ==
                 {"1", *(str(i) + ".gz" for i in range(2, 13))},
                 "logrotate did not preserve exactly twelve generations")
        for archive in archives:
            content = gzip.decompress(archive.read_bytes()) if archive.suffix == ".gz" else archive.read_bytes()
            _require(record in content, "rotated log content was not preserved")
            meta = archive.stat()
            _require(meta.st_uid == account.pw_uid and stat.S_IMODE(meta.st_mode) == 0o600,
                     "rotated log ownership/mode is unsafe")
        meta = path.stat()
        _require(meta.st_uid == account.pw_uid and stat.S_IMODE(meta.st_mode) == 0o600,
                 "new active log is not writable only by the service identity")
    _require(MONITOR_STATE.read_bytes() == saved_state, "rotation altered durable state")
    _transition()
    _start(SERVICES[2], 0)
    _recover_suricata()
    _start(SERVICES[0], 0)
    _start(SERVICES[2], 0)
    _require(EVENTS.stat().st_size > 0 and RECEIPTS.stat().st_size > 0,
             "installed writers did not resume after rotation")
    return {"forced_rotations": 14, "generations_per_log": 12,
            "compressed_generations_per_log": 11, "active_mode": "0600",
            "state_preserved": True, "installed_writers_recovered": True}


def _disk_full() -> dict[str, Any]:
    _pause()
    before = MONITOR_STATE.read_bytes()
    account = pwd.getpwnam("meercata")
    _command(("/usr/bin/mount", "-t", "tmpfs", "-o",
              f"size=65536,mode=0700,uid={account.pw_uid},gid={account.pw_gid}",
              "meercata-dev25-full", str(LOG_DIR)))
    try:
        full = False
        with (LOG_DIR / "qualification-fill").open("wb", buffering=0) as stream:
            try:
                for _ in range(32):
                    stream.write(b"x" * 4096)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                full = True
        _require(full, "bounded filesystem did not reach ENOSPC")
        _command(("/usr/bin/systemctl", "stop", "suricata.service"), timeout=90)
        _start(SERVICES[0], 3)
        _require(MONITOR_STATE.read_bytes() == before, "failed log append changed monitor state")
    finally:
        _command(("/usr/bin/umount", str(LOG_DIR)))
        _recover_suricata()
    _start(SERVICES[0], 0)
    return {"tmpfs_bytes": 65536, "enospc_observed": True,
            "installed_producer_exit_code": 3, "state_preserved": True,
            "recovered_exit_code": 0}


def _wait_timers(*, timeout: float, since_monotonic: int = 1) -> dict[str, Any]:
    def observe() -> dict[str, Any]:
        results: dict[str, Any] = {}
        for timer, service in zip(TIMERS, SERVICES):
            enabled = _command(("/usr/bin/systemctl", "is-enabled", timer)).stdout.strip()
            props = _systemctl_show(timer, ("ActiveState", "Unit"))
            # systemctl formats a nonzero monotonic timestamp as a human-readable duration.
            # Query systemd's uint64 property directly for comparison with journal microseconds.
            unit_path = timer.replace("-", "_2d").replace(".", "_2e")
            native = _command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
                               f"/org/freedesktop/systemd1/unit/{unit_path}",
                               "org.freedesktop.systemd1.Timer", "LastTriggerUSecMonotonic"))
            timestamp = re.fullmatch(r"t ([0-9]+)", native.stdout.strip())
            _require(timestamp is not None, f"invalid timer trigger timestamp: {timer}")
            triggered = int(timestamp[1])
            _require(enabled == "enabled" and props["ActiveState"] == "active" and
                     props["Unit"] == service and triggered >= since_monotonic,
                     f"timer has not triggered in the observation window: {timer}")
            service_result = _systemctl_show(service, ("Result", "ExecMainStatus"))
            _require(service_result == {"Result": "success", "ExecMainStatus": "0"},
                     f"timer service has not succeeded: {service}")
            report = _journal_report(service, since_monotonic=triggered)
            _require(report.get("exit_code", 0) == 0, f"timer service is not healthy: {service}")
            results[timer] = {"enabled": True, "active": True,
                              "triggered_this_boot": True, "service_exit_code": 0}
        _require(_service_json("delivery-status")["pending"] == 0, "delivery timer has pending work")
        return results
    return _wait(observe, timeout=timeout, label="all four installed timers", interval=3)


def _validate_state(value: Mapping[str, Any], image_sha512: str) -> None:
    required = {"schema_version", "status", "project_version", "image_sha512", "boot_id",
                "packages", "protected_files", "active_files", "checks", "pending", "sequence",
                "pending_event_ids"}
    _require(set(value) == required and type(value.get("schema_version")) is int and
             value.get("schema_version") == 1 and
             value.get("status") == "reboot-prepared" and
             value.get("project_version") == QUALIFIED_PROJECT_VERSION and
             value.get("image_sha512") == image_sha512 and
             isinstance(value.get("boot_id"), str) and
             re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]) is not None,
             "prepared state identity is invalid")
    for key in ("packages", "protected_files", "active_files"):
        _require(isinstance(value.get(key), dict) and bool(value[key]), "prepared state inventory is invalid")
    checks = value.get("checks")
    _require(isinstance(checks, list) and len(checks) == 12 and
             {c.get("check_id") for c in checks if isinstance(c, dict)} == set(CHECK_IDS[:12]) and
             all(c.get("status") == "passed" and isinstance(c.get("details"), dict) for c in checks),
             "prepared check inventory is invalid")
    _require(type(value.get("pending")) is int and value["pending"] >= 1 and
             type(value.get("sequence")) is int and value["sequence"] >= 1,
             "prepared counters are invalid")
    event_ids = value.get("pending_event_ids")
    _require(isinstance(event_ids, list) and len(event_ids) == value["pending"] <= 1000 and
             all(isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{64}", event_id)
                 for event_id in event_ids) and len(set(event_ids)) == len(event_ids),
             "prepared event identities are invalid")


def _cleanup(original: bytes) -> None:
    # Called only after the guard and preflight succeeded. Preserve monitoring data.
    def restore_config() -> None:
        metadata = CONFIG.stat()
        _replace_file(CONFIG, original, metadata.st_uid, metadata.st_gid,
                      stat.S_IMODE(metadata.st_mode))

    def remove_credentials() -> None:
        for path in (TOKEN, CA, *WORK.glob("pki*/*.key")):
            path.unlink(missing_ok=True)

    failures: list[str] = []
    operations = (
        _pause,
        lambda: _command(("/usr/bin/systemctl", "disable", *TIMERS)),
        restore_config,
        remove_credentials,
        _recover_suricata,
    )
    for operation in operations:
        try:
            operation()
        except Exception as exc:
            failures.append(str(exc))
    _require(not failures, "qualification cleanup failed: " + "; ".join(failures))


def _verify_cleanup() -> dict[str, Any]:
    for timer in TIMERS:
        result = _command(("/usr/bin/systemctl", "is-enabled", timer), allowed=(0, 1))
        _require(result.stdout.strip() == "disabled", "qualification timer remains enabled")
        _require(_systemctl_show(timer, ("ActiveState",))["ActiveState"] == "inactive",
                 "qualification timer remains active")
    _require(not TOKEN.exists() and not CA.exists() and not list(WORK.glob("pki*/*.key")),
             "disposable credentials remain after qualification")
    return {"disabled_timers": 4, "inactive_timers": 4,
            "credentials_removed": True, "suricata_recovered": True}


def _as_service(argv: tuple[str, ...], *, allowed: tuple[int, ...] = (0,)):
    return _command(("/usr/bin/setpriv", "--reuid=meercata", "--regid=meercata",
                     "--init-groups", *argv), allowed=allowed, timeout=60)


def _command(argv: tuple[str, ...], *, allowed: tuple[int, ...] = (0,), timeout: float = 90):
    result = CommandRunner({"monitor.vm": CommandDefinition.fixed(argv, timeout_seconds=timeout)},
                           max_output_bytes=1024 * 1024).run("monitor.vm")
    _require(result.return_code in allowed and not result.timed_out and not result.stdout_truncated and
             not result.stderr_truncated,
             f"qualification command failed: {argv[0:2]} (return={result.return_code}, timeout={result.timed_out})")
    return result


def _wait(operation: Callable[[], Any], *, timeout: float, label: str, interval: float = 2) -> Any:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return operation()
        except (QualificationError, OSError) as exc:
            last = exc
            time.sleep(interval)
    raise QualificationError(f"timed out waiting for {label}: {last}") from last


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def _progress(message: str) -> None:
    print(f"meercata-monitor-systemd-vm: {message}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qualify installed monitoring only in a disposable Debian 13 VM")
    parser.add_argument("phase", choices=("prepare", "verify"))
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--image-sha512", required=True)
    return parser


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        qualifier = MonitorSystemdVmQualifier(confirmation=args.confirmation, image_sha512=args.image_sha512)
        report = getattr(qualifier, args.phase)()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, ValueError, QualificationError) as exc:
        print(f"meercata-monitor-systemd-vm: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
