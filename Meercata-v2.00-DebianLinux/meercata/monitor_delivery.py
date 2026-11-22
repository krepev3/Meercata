"""Crash-safe bounded HTTPS delivery for durable monitor transitions."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from meercata.errors import MonitorDeliveryError
from meercata.health_config import _read_config
from meercata.locking import ControllerLock
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within

DELIVERY_SCHEMA_VERSION = 1
MAX_OUTBOX_ITEMS = 1_000
MAX_DEAD_LETTERS = 1_000
MAX_ENVELOPE_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_RECEIPT_LOG_BYTES = 8 * 1024 * 1024
MAX_RECEIPTS = 10_000
MAX_DELIVERY_QUERY = 100
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CA_BYTES = 256 * 1024
DELIVERY_PENDING_WARNING = 100
DELIVERY_PENDING_CRITICAL = 500
DELIVERY_AGE_WARNING_SECONDS = 300
DELIVERY_AGE_CRITICAL_SECONDS = 1800
_ERROR_PATTERN = re.compile(r"[a-z0-9.-]{1,64}\Z")
_DELIVERY_KEYS = {
    "endpoint",
    "token_file",
    "timeout_seconds",
    "max_attempts",
    "base_retry_seconds",
    "max_retry_seconds",
    "batch_size",
    "ca_file",
}


@dataclass(frozen=True, slots=True)
class DeliveryConfig:
    endpoint: str
    token_file: Path
    timeout_seconds: float = 10.0
    max_attempts: int = 8
    base_retry_seconds: int = 30
    max_retry_seconds: int = 3600
    batch_size: int = 20
    ca_file: Path | None = None


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    delivered: bool
    retryable: bool
    code: str
    http_status: int | None = None


class DeliveryTransport(Protocol):
    def send(
        self,
        config: DeliveryConfig,
        token: str,
        event_id: str,
        event: Mapping[str, Any],
    ) -> DeliveryResult: ...


class HttpsDeliveryTransport:
    """POST one event over verified TLS without redirects or response-body trust."""

    def send(
        self,
        config: DeliveryConfig,
        token: str,
        event_id: str,
        event: Mapping[str, Any],
    ) -> DeliveryResult:
        target = urlsplit(config.endpoint)
        body = json.dumps(
            {
                "schema_version": DELIVERY_SCHEMA_VERSION,
                "source": "meercata",
                "event_id": event_id,
                "event": event,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        connection: http.client.HTTPSConnection | None = None
        try:
            context = ssl.create_default_context(
                cafile=None if config.ca_file is None else str(config.ca_file)
            )
            connection = http.client.HTTPSConnection(
                target.hostname,
                target.port or 443,
                timeout=config.timeout_seconds,
                context=context,
            )
            connection.request(
                "POST",
                target.path,
                body=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": event_id,
                    "User-Agent": "Meercata/2 monitor-delivery-v1",
                },
            )
            response = connection.getresponse()
            response.read(MAX_RESPONSE_BYTES + 1)
            status_code = response.status
        except (OSError, ssl.SSLError, socket.timeout, http.client.HTTPException):
            return DeliveryResult(False, True, "transport-error")
        finally:
            if connection is not None:
                connection.close()
        if 200 <= status_code <= 299:
            return DeliveryResult(True, False, "accepted", status_code)
        retryable = status_code in {408, 425, 429} or 500 <= status_code <= 599
        return DeliveryResult(
            False,
            retryable,
            "remote-retryable" if retryable else "remote-rejected",
            status_code,
        )


class DeliveryOutbox:
    """Persist transition envelopes and deliver them with durable receipts."""

    def __init__(
        self,
        paths: MeercataPaths,
        *,
        config_loader: Callable[[MeercataPaths], DeliveryConfig] = None,
        transport: DeliveryTransport | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.paths = paths
        self.config_loader = config_loader or load_delivery_config
        self.transport = transport or HttpsDeliveryTransport()
        self.wall_clock = wall_clock

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> DeliveryOutbox:
        return cls(paths)

    def ensure(self, event: Mapping[str, Any]) -> dict[str, Any]:
        checked_event = _validate_transition(event)
        event_id = _event_id(checked_event)
        sequence = checked_event["sequence"]
        lock = ControllerLock(self.paths.monitor_delivery_lock_file)
        lock.acquire("monitor-delivery-enqueue")
        with lock:
            receipts = _read_receipts(self.paths.monitor_receipts_file)
            completed = receipts.get(event_id)
            if completed is not None and completed["status"] in {
                "delivered",
                "dead-letter",
            }:
                return {
                    "event_id": event_id,
                    "sequence": sequence,
                    "queued": False,
                    "status": completed["status"],
                }
            ensure_secure_directory(self.paths.monitor_outbox_dir, mode=0o700)
            ensure_secure_directory(self.paths.monitor_dead_letter_dir, mode=0o700)
            pending = _envelope_path(self.paths.monitor_outbox_dir, sequence, event_id)
            dead = _envelope_path(self.paths.monitor_dead_letter_dir, sequence, event_id)
            if dead.exists():
                envelope = _read_envelope(dead)
                _require_envelope_identity(envelope, event_id, checked_event)
                return {
                    "event_id": event_id,
                    "sequence": sequence,
                    "queued": False,
                    "status": "dead-letter",
                }
            if pending.exists():
                envelope = _read_envelope(pending)
                _require_envelope_identity(envelope, event_id, checked_event)
                return {
                    "event_id": event_id,
                    "sequence": sequence,
                    "queued": False,
                    "status": "pending",
                }
            if len(_list_envelopes(self.paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS)) >= MAX_OUTBOX_ITEMS:
                raise MonitorDeliveryError("monitor delivery outbox is full")
            envelope = {
                "schema_version": DELIVERY_SCHEMA_VERSION,
                "event_id": event_id,
                "sequence": sequence,
                "created_utc": checked_event["generated_utc"],
                "attempts": 0,
                "next_attempt_epoch": 0,
                "last_error": None,
                "event": checked_event,
            }
            _atomic_json_write(pending, _validate_envelope(envelope))
            return {
                "event_id": event_id,
                "sequence": sequence,
                "queued": True,
                "status": "pending",
            }

    def deliver(self) -> dict[str, Any]:
        config = self.config_loader(self.paths)
        token = _read_token(config.token_file, production=self.paths == MeercataPaths.production())
        if config.ca_file is not None:
            _validate_ca_file(
                config.ca_file, production=self.paths == MeercataPaths.production()
            )
        lock = ControllerLock(self.paths.monitor_delivery_lock_file)
        lock.acquire("monitor-delivery-run")
        with lock:
            ensure_secure_directory(self.paths.monitor_outbox_dir, mode=0o700)
            ensure_secure_directory(self.paths.monitor_dead_letter_dir, mode=0o700)
            receipts = _read_receipts(self.paths.monitor_receipts_file)
            _reconcile_completed(self.paths, receipts)
            pending_paths = _list_envelopes(
                self.paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS
            )
            now = int(self.wall_clock())
            attempted = delivered = retried = dead_lettered = 0
            for path in pending_paths:
                if attempted >= config.batch_size:
                    break
                envelope = _read_envelope(path)
                if envelope["next_attempt_epoch"] > now:
                    continue
                attempted += 1
                result = self.transport.send(
                    config,
                    token,
                    envelope["event_id"],
                    envelope["event"],
                )
                attempts = envelope["attempts"] + 1
                if result.delivered:
                    _append_receipt(
                        self.paths.monitor_receipts_file,
                        _receipt(envelope, "delivered", attempts, result, now),
                    )
                    _unlink_synced(path)
                    delivered += 1
                elif not result.retryable or attempts >= config.max_attempts:
                    updated = dict(envelope)
                    updated.update(
                        {
                            "attempts": attempts,
                            "next_attempt_epoch": 0,
                            "last_error": result.code,
                        }
                    )
                    envelope = _validate_envelope(updated)
                    _atomic_json_write(path, envelope)
                    _append_receipt(
                        self.paths.monitor_receipts_file,
                        _receipt(envelope, "dead-letter", attempts, result, now),
                    )
                    _move_to_dead_letter(self.paths, path, envelope)
                    dead_lettered += 1
                else:
                    delay = min(
                        config.base_retry_seconds * (2 ** (attempts - 1)),
                        config.max_retry_seconds,
                    )
                    updated = dict(envelope)
                    updated.update(
                        {
                            "attempts": attempts,
                            "next_attempt_epoch": now + delay,
                            "last_error": result.code,
                        }
                    )
                    _atomic_json_write(path, _validate_envelope(updated))
                    retried += 1
            remaining = len(
                _list_envelopes(self.paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS)
            )
        return {
            "schema_version": DELIVERY_SCHEMA_VERSION,
            "generated_utc": _utc(now),
            "status": "delivery-complete",
            "attempted": attempted,
            "delivered": delivered,
            "retried": retried,
            "dead_lettered": dead_lettered,
            "pending": remaining,
        }

    def status(self) -> dict[str, Any]:
        lock = ControllerLock(self.paths.monitor_delivery_lock_file)
        lock.acquire("monitor-delivery-status")
        with lock:
            pending = _list_envelopes(self.paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS)
            dead = _list_envelopes(
                self.paths.monitor_dead_letter_dir, MAX_DEAD_LETTERS
            )
            receipts = _read_receipts(self.paths.monitor_receipts_file)
            next_attempts = [
                _read_envelope(path)["next_attempt_epoch"] for path in pending
            ]
        earliest = None if not next_attempts else min(next_attempts)
        return {
            "schema_version": DELIVERY_SCHEMA_VERSION,
            "status": "delivery-status",
            "pending": len(pending),
            "dead_letters": len(dead),
            "receipts": len(receipts),
            "next_attempt_utc": (
                None
                if earliest is None
                else _utc(int(self.wall_clock()) if earliest == 0 else earliest)
            ),
        }

    def dead_letters(self, limit: int) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= MAX_DELIVERY_QUERY:
            raise MonitorDeliveryError(
                f"dead-letter limit must be from 1 to {MAX_DELIVERY_QUERY}"
            )
        lock = ControllerLock(self.paths.monitor_delivery_lock_file)
        lock.acquire("monitor-dead-letter-query")
        with lock:
            paths = _list_envelopes(
                self.paths.monitor_dead_letter_dir, MAX_DEAD_LETTERS
            )
            return [_read_envelope(path) for path in paths[-limit:]]

    def health(self) -> dict[str, Any]:
        now = int(self.wall_clock())
        lock = ControllerLock(self.paths.monitor_delivery_lock_file)
        lock.acquire("monitor-delivery-health")
        with lock:
            pending_paths = _list_envelopes(
                self.paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS
            )
            dead_paths = _list_envelopes(
                self.paths.monitor_dead_letter_dir, MAX_DEAD_LETTERS
            )
            envelopes = [_read_envelope(path) for path in pending_paths]
            for path in dead_paths:
                _read_envelope(path)
            receipts = _read_receipts(self.paths.monitor_receipts_file)
        ages: list[int] = []
        unknown_time = False
        for envelope in envelopes:
            try:
                timestamp = datetime.fromisoformat(
                    envelope["created_utc"].replace("Z", "+00:00")
                )
                if timestamp.utcoffset() is None:
                    unknown_time = True
                    continue
                created = int(timestamp.timestamp())
            except (ValueError, OverflowError):
                unknown_time = True
                continue
            age = now - created
            if age < -30:
                unknown_time = True
            ages.append(age)
        oldest_age = None if not ages else max(ages)
        retrying = sum(envelope["attempts"] > 0 for envelope in envelopes)
        due = sum(envelope["next_attempt_epoch"] <= now for envelope in envelopes)
        if unknown_time:
            status, exit_code = "unknown", 3
        elif (
            dead_paths
            or len(envelopes) >= DELIVERY_PENDING_CRITICAL
            or (
                oldest_age is not None
                and oldest_age > DELIVERY_AGE_CRITICAL_SECONDS
            )
        ):
            status, exit_code = "critical", 2
        elif (
            retrying
            or len(envelopes) >= DELIVERY_PENDING_WARNING
            or (
                oldest_age is not None
                and oldest_age > DELIVERY_AGE_WARNING_SECONDS
            )
        ):
            status, exit_code = "degraded", 1
        else:
            status, exit_code = "healthy", 0
        last_receipt = None
        if receipts:
            last_receipt = max(
                receipts.values(), key=lambda receipt: receipt["generated_utc"]
            )
        return {
            "schema_version": DELIVERY_SCHEMA_VERSION,
            "generated_utc": _utc(now),
            "status": status,
            "exit_code": exit_code,
            "pending": len(envelopes),
            "due_pending": due,
            "retrying": retrying,
            "dead_letters": len(dead_paths),
            "oldest_pending_age_seconds": oldest_age,
            "last_receipt": (
                None
                if last_receipt is None
                else {
                    "status": last_receipt["status"],
                    "generated_utc": last_receipt["generated_utc"],
                }
            ),
            "thresholds": {
                "pending_warning": DELIVERY_PENDING_WARNING,
                "pending_critical": DELIVERY_PENDING_CRITICAL,
                "age_warning_seconds": DELIVERY_AGE_WARNING_SECONDS,
                "age_critical_seconds": DELIVERY_AGE_CRITICAL_SECONDS,
            },
        }


def load_delivery_config(paths: MeercataPaths) -> DeliveryConfig:
    try:
        raw = _read_config(paths.controller_config_file)
    except Exception as exc:
        raise MonitorDeliveryError(str(exc)) from exc
    allowed_top = {"schema_version", "health", "rules", "ips", "monitor_delivery"}
    unknown = set(raw) - allowed_top
    if unknown:
        raise MonitorDeliveryError(
            f"unknown top-level configuration keys: {', '.join(sorted(unknown))}"
        )
    if raw.get("schema_version") != 1 or type(raw.get("schema_version")) is not int:
        raise MonitorDeliveryError("configuration schema_version must be integer 1")
    values = raw.get("monitor_delivery")
    if not isinstance(values, dict):
        raise MonitorDeliveryError("configuration requires a [monitor_delivery] table")
    unknown_delivery = set(values) - _DELIVERY_KEYS
    if unknown_delivery:
        raise MonitorDeliveryError(
            "unknown monitor_delivery keys: " + ", ".join(sorted(unknown_delivery))
        )
    endpoint = _endpoint(values.get("endpoint"))
    token_value = values.get("token_file", str(paths.monitor_delivery_token_file))
    if not isinstance(token_value, str) or not Path(token_value).is_absolute():
        raise MonitorDeliveryError("monitor_delivery.token_file must be absolute")
    try:
        token_file = require_within(Path(token_value), paths.monitor_delivery_token_dir)
    except Exception as exc:
        raise MonitorDeliveryError(
            "monitor_delivery.token_file is outside the credential directory"
        ) from exc
    timeout = _number(values.get("timeout_seconds", 10), "timeout_seconds", 1, 30)
    max_attempts = _integer(values.get("max_attempts", 8), "max_attempts", 1, 20)
    base_retry = _integer(
        values.get("base_retry_seconds", 30), "base_retry_seconds", 1, 3600
    )
    max_retry = _integer(
        values.get("max_retry_seconds", 3600), "max_retry_seconds", base_retry, 86400
    )
    batch_size = _integer(values.get("batch_size", 20), "batch_size", 1, 100)
    ca_value = values.get("ca_file")
    ca_file: Path | None = None
    if ca_value is not None:
        if not isinstance(ca_value, str) or not Path(ca_value).is_absolute():
            raise MonitorDeliveryError("monitor_delivery.ca_file must be absolute")
        try:
            ca_file = require_within(
                Path(ca_value), paths.monitor_delivery_token_dir
            )
        except Exception as exc:
            raise MonitorDeliveryError(
                "monitor_delivery.ca_file is outside the credential directory"
            ) from exc
    return DeliveryConfig(
        endpoint,
        token_file,
        timeout,
        max_attempts,
        base_retry,
        max_retry,
        batch_size,
        ca_file,
    )


def _endpoint(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise MonitorDeliveryError("monitor_delivery.endpoint must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise MonitorDeliveryError("monitor_delivery.endpoint port is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not _valid_hostname(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or any(character.isspace() for character in value)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise MonitorDeliveryError(
            "monitor_delivery.endpoint must be HTTPS without credentials, query, or fragment"
        )
    return value


def _valid_hostname(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if not 1 <= len(value) <= 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        is not None
        for label in labels
    )


def _read_token(path: Path, *, production: bool) -> str:
    raw = _read_regular(path, 8192, "monitor delivery token")
    metadata = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(metadata.st_mode)
    if production and metadata.st_uid != 0:
        raise MonitorDeliveryError("monitor delivery token must be owned by root")
    if mode & 0o007 or mode & 0o111:
        raise MonitorDeliveryError("monitor delivery token permissions are too broad")
    try:
        token = raw.decode("ascii").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise MonitorDeliveryError("monitor delivery token must be ASCII") from exc
    if (
        not 16 <= len(token) <= 4096
        or "\n" in token
        or "\r" in token
        or any(character.isspace() for character in token)
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise MonitorDeliveryError("monitor delivery token format is invalid")
    return token


def _validate_ca_file(path: Path, *, production: bool) -> None:
    raw = _read_regular(path, MAX_CA_BYTES, "monitor delivery CA bundle")
    metadata = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(metadata.st_mode)
    if production and metadata.st_uid != 0:
        raise MonitorDeliveryError("monitor delivery CA bundle must be owned by root")
    if mode & 0o022 or mode & 0o111:
        raise MonitorDeliveryError("monitor delivery CA bundle permissions are unsafe")
    if b"-----BEGIN CERTIFICATE-----" not in raw or b"-----END CERTIFICATE-----" not in raw:
        raise MonitorDeliveryError("monitor delivery CA bundle is not PEM certificate data")


def _validate_transition(value: Mapping[str, Any]) -> dict[str, Any]:
    from meercata.monitor import _validate_event

    return _validate_event(dict(value))


def _event_id(event: Mapping[str, Any]) -> str:
    payload = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_envelope(value: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "event_id",
        "sequence",
        "created_utc",
        "attempts",
        "next_attempt_epoch",
        "last_error",
        "event",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MonitorDeliveryError("monitor delivery envelope schema is invalid")
    event = _validate_transition(value.get("event"))
    if value.get("schema_version") != DELIVERY_SCHEMA_VERSION:
        raise MonitorDeliveryError("monitor delivery envelope version is unsupported")
    if value.get("event_id") != _event_id(event):
        raise MonitorDeliveryError("monitor delivery event identity is invalid")
    if value.get("sequence") != event["sequence"]:
        raise MonitorDeliveryError("monitor delivery sequence is invalid")
    if value.get("created_utc") != event["generated_utc"]:
        raise MonitorDeliveryError("monitor delivery creation time is invalid")
    attempts = value.get("attempts")
    if type(attempts) is not int or not 0 <= attempts <= 20:
        raise MonitorDeliveryError("monitor delivery attempt count is invalid")
    next_attempt = value.get("next_attempt_epoch")
    if type(next_attempt) is not int or not 0 <= next_attempt <= 2**63 - 1:
        raise MonitorDeliveryError("monitor delivery retry time is invalid")
    error = value.get("last_error")
    if error is not None and (
        not isinstance(error, str) or _ERROR_PATTERN.fullmatch(error) is None
    ):
        raise MonitorDeliveryError("monitor delivery error code is invalid")
    checked = dict(value)
    checked["event"] = event
    return checked


def _require_envelope_identity(
    envelope: Mapping[str, Any], event_id: str, event: Mapping[str, Any]
) -> None:
    if envelope["event_id"] != event_id or envelope["event"] != event:
        raise MonitorDeliveryError("monitor delivery envelope conflicts with transition")


def _envelope_path(directory: Path, sequence: int, event_id: str) -> Path:
    return directory / f"{sequence:020d}-{event_id[:16]}.json"


def _list_envelopes(directory: Path, maximum: int) -> list[Path]:
    if not directory.exists():
        return []
    try:
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise MonitorDeliveryError("monitor delivery directory is unsafe")
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except MonitorDeliveryError:
        raise
    except OSError as exc:
        raise MonitorDeliveryError(f"cannot inspect monitor delivery directory: {exc}") from exc
    if len(entries) > maximum:
        raise MonitorDeliveryError("monitor delivery directory contains too many items")
    pattern = re.compile(r"[0-9]{20}-[0-9a-f]{16}\.json\Z")
    if any(pattern.fullmatch(path.name) is None for path in entries):
        raise MonitorDeliveryError("monitor delivery directory contains an unknown entry")
    return entries


def _read_envelope(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_ENVELOPE_BYTES, "monitor delivery envelope")
    try:
        return _validate_envelope(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MonitorDeliveryError("monitor delivery envelope is not valid JSON") from exc


def _atomic_json_write(path: Path, value: Mapping[str, Any]) -> None:
    require_within(path, path.parent)
    payload = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise MonitorDeliveryError("monitor delivery envelope exceeds its size limit")
    ensure_secure_directory(path.parent, mode=0o700)
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".delivery.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except OSError as exc:
        raise MonitorDeliveryError(f"cannot persist monitor delivery envelope: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _read_receipts(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    raw = _read_regular(path, MAX_RECEIPT_LOG_BYTES, "monitor delivery receipts")
    lines = raw.splitlines()
    if len(lines) > MAX_RECEIPTS:
        raise MonitorDeliveryError("monitor delivery receipt log contains too many records")
    result: dict[str, dict[str, Any]] = {}
    for line in lines:
        if not line or len(line) > MAX_RECEIPT_BYTES:
            raise MonitorDeliveryError("monitor delivery receipt size is invalid")
        try:
            receipt = _validate_receipt(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MonitorDeliveryError("monitor delivery receipt is not valid JSON") from exc
        result[receipt["event_id"]] = receipt
    return result


def _validate_receipt(value: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "event_id",
        "sequence",
        "status",
        "attempts",
        "generated_utc",
        "result_code",
        "http_status",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MonitorDeliveryError("monitor delivery receipt schema is invalid")
    if value.get("schema_version") != DELIVERY_SCHEMA_VERSION:
        raise MonitorDeliveryError("monitor delivery receipt version is unsupported")
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-f]{64}", event_id) is None:
        raise MonitorDeliveryError("monitor delivery receipt identity is invalid")
    if type(value.get("sequence")) is not int or value["sequence"] < 1:
        raise MonitorDeliveryError("monitor delivery receipt sequence is invalid")
    if value.get("status") not in {"delivered", "dead-letter"}:
        raise MonitorDeliveryError("monitor delivery receipt status is invalid")
    if type(value.get("attempts")) is not int or not 1 <= value["attempts"] <= 20:
        raise MonitorDeliveryError("monitor delivery receipt attempts are invalid")
    if not isinstance(value.get("generated_utc"), str) or not value["generated_utc"].endswith("Z"):
        raise MonitorDeliveryError("monitor delivery receipt time is invalid")
    if not isinstance(value.get("result_code"), str) or _ERROR_PATTERN.fullmatch(value["result_code"]) is None:
        raise MonitorDeliveryError("monitor delivery receipt result is invalid")
    http_status = value.get("http_status")
    if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
        raise MonitorDeliveryError("monitor delivery receipt HTTP status is invalid")
    return dict(value)


def _receipt(
    envelope: Mapping[str, Any],
    status: str,
    attempts: int,
    result: DeliveryResult,
    now: int,
) -> dict[str, Any]:
    return _validate_receipt(
        {
            "schema_version": DELIVERY_SCHEMA_VERSION,
            "event_id": envelope["event_id"],
            "sequence": envelope["sequence"],
            "status": status,
            "attempts": attempts,
            "generated_utc": _utc(now),
            "result_code": result.code,
            "http_status": result.http_status,
        }
    )


def _append_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise MonitorDeliveryError("monitor delivery receipt exceeds its size limit")
    ensure_secure_directory(path.parent, mode=0o700)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise MonitorDeliveryError("monitor delivery receipt target is not regular")
            if metadata.st_size + len(payload) > MAX_RECEIPT_LOG_BYTES:
                raise MonitorDeliveryError("monitor delivery receipt log requires rotation")
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    except MonitorDeliveryError:
        raise
    except OSError as exc:
        raise MonitorDeliveryError(f"cannot append monitor delivery receipt: {exc}") from exc


def _reconcile_completed(
    paths: MeercataPaths, receipts: Mapping[str, Mapping[str, Any]]
) -> None:
    for path in _list_envelopes(paths.monitor_outbox_dir, MAX_OUTBOX_ITEMS):
        envelope = _read_envelope(path)
        receipt = receipts.get(envelope["event_id"])
        if receipt is None:
            continue
        if receipt["status"] == "delivered":
            _unlink_synced(path)
        elif receipt["status"] == "dead-letter":
            _move_to_dead_letter(paths, path, envelope)


def _move_to_dead_letter(
    paths: MeercataPaths, pending: Path, envelope: Mapping[str, Any]
) -> None:
    dead = _envelope_path(
        paths.monitor_dead_letter_dir, envelope["sequence"], envelope["event_id"]
    )
    if not dead.exists() and len(
        _list_envelopes(paths.monitor_dead_letter_dir, MAX_DEAD_LETTERS)
    ) >= MAX_DEAD_LETTERS:
        raise MonitorDeliveryError("monitor dead-letter directory is full")
    os.replace(pending, dead)
    _sync_directory(paths.monitor_outbox_dir)
    _sync_directory(paths.monitor_dead_letter_dir)


def _unlink_synced(path: Path) -> None:
    path.unlink()
    _sync_directory(path.parent)


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise MonitorDeliveryError(f"{label} is not a bounded regular file")
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
    except MonitorDeliveryError:
        raise
    except OSError as exc:
        raise MonitorDeliveryError(f"cannot read {label}: {exc}") from exc
    if len(raw) > maximum:
        raise MonitorDeliveryError(f"{label} exceeds its size limit")
    return raw


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short monitor delivery write")
        offset += written


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise MonitorDeliveryError(
            f"monitor_delivery.{name} must be an integer from {minimum} to {maximum}"
        )
    return value


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if type(value) not in {int, float}:
        raise MonitorDeliveryError(f"monitor_delivery.{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise MonitorDeliveryError(
            f"monitor_delivery.{name} must be between {minimum:g} and {maximum:g}"
        )
    return number
