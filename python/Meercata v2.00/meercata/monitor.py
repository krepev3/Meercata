"""Durable, deduplicated health transitions for CLI/systemd monitoring."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from meercata.errors import MonitorError
from meercata.health import HealthService
from meercata.health_models import HealthReport
from meercata.locking import ControllerLock
from meercata.monitor_delivery import DeliveryOutbox
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within

MONITOR_SCHEMA_VERSION = 1
MAX_MONITOR_STATE_BYTES = 256 * 1024
MAX_MONITOR_EVENT_BYTES = 256 * 1024
MAX_MONITOR_LOG_BYTES = 8 * 1024 * 1024
MAX_MONITOR_EVENTS = 10_000
MAX_EVENT_QUERY = 100
MONITOR_FRESHNESS_SECONDS = 180
MONITOR_FUTURE_TOLERANCE_SECONDS = 30


class HealthProvider(Protocol):
    def collect(self) -> HealthReport: ...


class MonitorService:
    def __init__(
        self,
        paths: MeercataPaths,
        health: HealthProvider,
        *,
        wall_clock: Any = time.time,
    ) -> None:
        self.paths = paths
        self.health = health
        self.wall_clock = wall_clock

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> MonitorService:
        return cls(paths, HealthService.from_paths(paths))

    def run(self) -> dict[str, Any]:
        try:
            report = self.health.collect()
        except Exception as exc:
            report = HealthReport.configuration_error(
                f"monitor health collection failed: {type(exc).__name__}"
            )
        report_value = report.to_dict()
        fingerprint = _condition_fingerprint(report)
        report_sha256 = _json_sha256(report_value)
        lock = ControllerLock(self.paths.monitor_lock_file)
        lock.acquire("health-monitor")
        with lock:
            state = _read_state_if_present(self.paths.monitor_state_file)
            last_event = _read_events(self.paths.monitor_events_file, limit=1)
            if last_event:
                event_state = _validate_state(last_event[-1].get("state_after"))
                if state is None or event_state["sequence"] > state["sequence"]:
                    state = event_state
                DeliveryOutbox(self.paths).ensure(last_event[-1])
            transition: dict[str, Any] | None = None
            if state is None or state["fingerprint"] != fingerprint:
                transition = _transition(report, state, fingerprint, report_sha256)
                _append_event(self.paths.monitor_events_file, transition)
                DeliveryOutbox(self.paths).ensure(transition)
                state_after = transition["state_after"]
            else:
                state_after = dict(state)
                state_after.update(
                    {
                        "last_observed_utc": report.generated_utc,
                        "consecutive_observations": state["consecutive_observations"] + 1,
                        "health_report_sha256": report_sha256,
                        "exit_code": report.exit_code,
                    }
                )
            _atomic_state_write(self.paths.monitor_state_file, state_after)
        return {
            "schema_version": MONITOR_SCHEMA_VERSION,
            "generated_utc": report.generated_utc,
            "status": report.status.value,
            "exit_code": report.exit_code,
            "transition_emitted": transition is not None,
            "sequence": state_after["sequence"],
            "transition": transition,
            "state": state_after,
            "health": report_value,
        }

    def status(self) -> dict[str, Any]:
        state = _read_state_if_present(self.paths.monitor_state_file)
        if state is None:
            return {"schema_version": MONITOR_SCHEMA_VERSION, "status": "uninitialized"}
        return state

    def events(self, limit: int) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= MAX_EVENT_QUERY:
            raise MonitorError(f"monitor event limit must be from 1 to {MAX_EVENT_QUERY}")
        return _read_events(self.paths.monitor_events_file, limit=limit)

    def freshness(self) -> dict[str, Any]:
        now = int(self.wall_clock())
        state = _read_state_if_present(self.paths.monitor_state_file)
        generated = datetime.fromtimestamp(now, timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        if state is None:
            return {
                "schema_version": MONITOR_SCHEMA_VERSION,
                "generated_utc": generated,
                "status": "uninitialized",
                "exit_code": 3,
                "age_seconds": None,
                "threshold_seconds": MONITOR_FRESHNESS_SECONDS,
                "last_observed_utc": None,
                "sequence": None,
            }
        try:
            observed = datetime.fromisoformat(
                state["last_observed_utc"].replace("Z", "+00:00")
            )
            observed_epoch = int(observed.timestamp())
        except (ValueError, OverflowError) as exc:
            raise MonitorError("monitor observation time is invalid") from exc
        age = now - observed_epoch
        if age < -MONITOR_FUTURE_TOLERANCE_SECONDS:
            status, exit_code = "unknown", 3
        elif age > MONITOR_FRESHNESS_SECONDS:
            status, exit_code = "stale", 2
        else:
            status, exit_code = "fresh", 0
        return {
            "schema_version": MONITOR_SCHEMA_VERSION,
            "generated_utc": generated,
            "status": status,
            "exit_code": exit_code,
            "age_seconds": age,
            "threshold_seconds": MONITOR_FRESHNESS_SECONDS,
            "last_observed_utc": state["last_observed_utc"],
            "sequence": state["sequence"],
        }


def _transition(
    report: HealthReport,
    previous: Mapping[str, Any] | None,
    fingerprint: str,
    report_sha256: str,
) -> dict[str, Any]:
    previous_status = previous.get("status") if previous else None
    if previous is None:
        reason = "baseline"
    elif report.status.value == "healthy" and previous_status != "healthy":
        reason = "recovered"
    elif report.status.value != previous_status:
        reason = "status-changed"
    else:
        reason = "conditions-changed"
    sequence = 1 if previous is None else int(previous["sequence"]) + 1
    state_after = {
        "schema_version": MONITOR_SCHEMA_VERSION,
        "sequence": sequence,
        "mode": report.mode,
        "status": report.status.value,
        "exit_code": report.exit_code,
        "fingerprint": fingerprint,
        "opened_utc": report.generated_utc,
        "last_transition_utc": report.generated_utc,
        "last_observed_utc": report.generated_utc,
        "consecutive_observations": 1,
        "health_report_sha256": report_sha256,
    }
    affected = [
        {
            "id": check.check_id,
            "status": check.status.value,
            "summary": check.summary[:512],
            "remediation": None if check.remediation is None else check.remediation[:1024],
        }
        for check in report.checks
        if check.required and check.status.value != "healthy"
    ]
    return {
        "schema_version": MONITOR_SCHEMA_VERSION,
        "event": "health-transition",
        "sequence": sequence,
        "reason": reason,
        "generated_utc": report.generated_utc,
        "generated_local": report.generated_local,
        "previous": (
            None
            if previous is None
            else {
                "status": previous["status"],
                "fingerprint": previous["fingerprint"],
            }
        ),
        "current": {"status": report.status.value, "fingerprint": fingerprint},
        "affected_checks": affected,
        "health_report_sha256": report_sha256,
        "state_after": state_after,
    }


def _condition_fingerprint(report: HealthReport) -> str:
    value = {
        "mode": report.mode,
        "status": report.status.value,
        "checks": sorted(
            (check.check_id, check.status.value, check.required) for check in report.checks
        ),
    }
    return _json_sha256(value)


def _json_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "sequence",
        "mode",
        "status",
        "exit_code",
        "fingerprint",
        "opened_utc",
        "last_transition_utc",
        "last_observed_utc",
        "consecutive_observations",
        "health_report_sha256",
    }:
        raise MonitorError("monitor state schema is invalid")
    if value.get("schema_version") != MONITOR_SCHEMA_VERSION:
        raise MonitorError("monitor state version is unsupported")
    if type(value.get("sequence")) is not int or value["sequence"] < 1:
        raise MonitorError("monitor state sequence is invalid")
    if value.get("mode") not in {"ids", "ips", "unknown"}:
        raise MonitorError("monitor state mode is invalid")
    statuses = {"healthy": 0, "degraded": 1, "critical": 2, "unknown": 3}
    if value.get("status") not in statuses or value.get("exit_code") != statuses[value["status"]]:
        raise MonitorError("monitor state status is invalid")
    for name in ("fingerprint", "health_report_sha256"):
        item = value.get(name)
        if not isinstance(item, str) or len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
            raise MonitorError(f"monitor state {name} is invalid")
    for name in ("opened_utc", "last_transition_utc", "last_observed_utc"):
        item = value.get(name)
        if not isinstance(item, str) or not item.endswith("Z") or len(item) > 64:
            raise MonitorError(f"monitor state {name} is invalid")
    count = value.get("consecutive_observations")
    if type(count) is not int or not 1 <= count <= 2**63 - 1:
        raise MonitorError("monitor observation count is invalid")
    return dict(value)


def _read_state_if_present(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    raw = _read_regular(path, MAX_MONITOR_STATE_BYTES, "monitor state")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MonitorError("monitor state is not valid JSON") from exc
    return _validate_state(value)


def _read_events(path: Path, *, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = _read_regular(path, MAX_MONITOR_LOG_BYTES, "monitor transition log")
    lines = raw.splitlines()
    if len(lines) > MAX_MONITOR_EVENTS:
        raise MonitorError("monitor transition log contains too many events")
    result: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line or len(line) > MAX_MONITOR_EVENT_BYTES:
            raise MonitorError("monitor transition record size is invalid")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MonitorError("monitor transition log contains invalid JSON") from exc
        result.append(_validate_event(value))
    return result


def _validate_event(value: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "event",
        "sequence",
        "reason",
        "generated_utc",
        "generated_local",
        "previous",
        "current",
        "affected_checks",
        "health_report_sha256",
        "state_after",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MonitorError("monitor transition record schema is invalid")
    if value.get("schema_version") != 1 or value.get("event") != "health-transition":
        raise MonitorError("monitor transition record identity is invalid")
    if value.get("reason") not in {
        "baseline",
        "recovered",
        "status-changed",
        "conditions-changed",
    }:
        raise MonitorError("monitor transition reason is invalid")
    state = _validate_state(value.get("state_after"))
    if value.get("sequence") != state["sequence"]:
        raise MonitorError("monitor transition sequence is invalid")
    current = value.get("current")
    if not isinstance(current, dict) or current != {
        "status": state["status"],
        "fingerprint": state["fingerprint"],
    }:
        raise MonitorError("monitor transition current state is invalid")
    previous = value.get("previous")
    if previous is not None and (
        not isinstance(previous, dict)
        or set(previous) != {"status", "fingerprint"}
        or previous.get("status") not in {"healthy", "degraded", "critical", "unknown"}
        or not _is_sha256(previous.get("fingerprint"))
    ):
        raise MonitorError("monitor transition previous state is invalid")
    if value["reason"] == "baseline" and previous is not None:
        raise MonitorError("monitor baseline transition has previous state")
    affected = value.get("affected_checks")
    if not isinstance(affected, list) or len(affected) > 64:
        raise MonitorError("monitor affected checks are invalid")
    for check in affected:
        if (
            not isinstance(check, dict)
            or set(check) != {"id", "status", "summary", "remediation"}
            or not isinstance(check.get("id"), str)
            or not 1 <= len(check["id"]) <= 128
            or check.get("status") not in {"degraded", "critical", "unknown"}
            or not isinstance(check.get("summary"), str)
            or len(check["summary"]) > 512
            or (
                check.get("remediation") is not None
                and (
                    not isinstance(check["remediation"], str)
                    or len(check["remediation"]) > 1024
                )
            )
        ):
            raise MonitorError("monitor affected check schema is invalid")
    if value.get("health_report_sha256") != state["health_report_sha256"]:
        raise MonitorError("monitor transition report hash is invalid")
    for name in ("generated_utc", "generated_local"):
        item = value.get(name)
        if not isinstance(item, str) or not item or len(item) > 64:
            raise MonitorError(f"monitor transition {name} is invalid")
    return dict(value)


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise MonitorError(f"{label} is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
    except MonitorError:
        raise
    except OSError as exc:
        raise MonitorError(f"cannot read {label}: {exc}") from exc
    if len(raw) > maximum:
        raise MonitorError(f"{label} exceeds its size limit")
    return raw


def _append_event(path: Path, event: Mapping[str, Any]) -> None:
    require_within(path, path.parent)
    payload = (
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_MONITOR_EVENT_BYTES:
        raise MonitorError("monitor transition exceeds its size limit")
    ensure_secure_directory(path.parent, mode=0o700)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise MonitorError("monitor transition target is not regular")
            if metadata.st_size + len(payload) > MAX_MONITOR_LOG_BYTES:
                raise MonitorError("monitor transition log requires rotation")
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    except MonitorError:
        raise
    except OSError as exc:
        raise MonitorError(f"cannot append monitor transition: {exc}") from exc


def _atomic_state_write(path: Path, value: Mapping[str, Any]) -> None:
    require_within(path, path.parent)
    checked = _validate_state(value)
    payload = (
        json.dumps(checked, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_MONITOR_STATE_BYTES:
        raise MonitorError("monitor state exceeds its size limit")
    ensure_secure_directory(path.parent, mode=0o700)
    temporary_path: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".state.", suffix=".tmp", dir=path.parent)
        temporary_path = Path(name)
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise MonitorError(f"cannot persist monitor state: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short monitor write")
        offset += written


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
