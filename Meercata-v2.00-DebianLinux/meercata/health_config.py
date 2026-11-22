"""Strict TOML configuration for read-only health collection."""

from __future__ import annotations

import os
import re
import stat
import tomllib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from meercata.errors import HealthConfigurationError, UnsafePathError
from meercata.paths import MeercataPaths, require_within

MAX_CONFIG_BYTES = 1024 * 1024
INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")


@dataclass(frozen=True, slots=True)
class HealthThresholds:
    eve_stale_warning_seconds: float = 30.0
    eve_stale_critical_seconds: float = 120.0
    packet_stall_seconds: float = 30.0
    disk_warning_percent_free: float = 15.0
    disk_critical_percent_free: float = 5.0
    memory_warning_percent_used: float = 85.0
    memory_critical_percent_used: float = 95.0
    process_rss_warning_percent: float = 25.0
    process_rss_critical_percent: float = 40.0
    process_cpu_warning_percent: float = 80.0
    process_cpu_critical_percent: float = 95.0
    packet_drop_warning_percent: float = 1.0
    packet_drop_critical_percent: float = 5.0
    reassembly_gap_warning_percent: float = 0.01
    reassembly_gap_critical_percent: float = 0.1
    watch_interval_seconds: float = 5.0
    socket_timeout_seconds: float = 2.0

    def validate(self) -> None:
        if any(
            not math.isfinite(float(getattr(self, name)))
            for name in self.__dataclass_fields__
        ):
            raise HealthConfigurationError("health thresholds must be finite numbers")
        positive = {
            "eve_stale_warning_seconds": self.eve_stale_warning_seconds,
            "eve_stale_critical_seconds": self.eve_stale_critical_seconds,
            "packet_stall_seconds": self.packet_stall_seconds,
            "watch_interval_seconds": self.watch_interval_seconds,
            "socket_timeout_seconds": self.socket_timeout_seconds,
        }
        if any(value <= 0 for value in positive.values()):
            raise HealthConfigurationError("health time thresholds must be positive")
        ordered_low_high = (
            (self.eve_stale_warning_seconds, self.eve_stale_critical_seconds),
            (self.memory_warning_percent_used, self.memory_critical_percent_used),
            (self.process_rss_warning_percent, self.process_rss_critical_percent),
            (self.process_cpu_warning_percent, self.process_cpu_critical_percent),
            (self.packet_drop_warning_percent, self.packet_drop_critical_percent),
            (self.reassembly_gap_warning_percent, self.reassembly_gap_critical_percent),
        )
        if any(warning >= critical for warning, critical in ordered_low_high):
            raise HealthConfigurationError("warning thresholds must be below critical thresholds")
        if not 0 < self.disk_critical_percent_free < self.disk_warning_percent_free <= 100:
            raise HealthConfigurationError("disk free thresholds are invalid")
        percentages = (
            self.memory_warning_percent_used,
            self.memory_critical_percent_used,
            self.process_rss_warning_percent,
            self.process_rss_critical_percent,
            self.process_cpu_warning_percent,
            self.process_cpu_critical_percent,
            self.packet_drop_warning_percent,
            self.packet_drop_critical_percent,
            self.reassembly_gap_warning_percent,
            self.reassembly_gap_critical_percent,
        )
        if any(not 0 <= value <= 100 for value in percentages):
            raise HealthConfigurationError("percentage thresholds must be between 0 and 100")
        if not 0.5 <= self.watch_interval_seconds <= 300:
            raise HealthConfigurationError("watch interval must be between 0.5 and 300 seconds")
        if not 0.1 <= self.socket_timeout_seconds <= 30:
            raise HealthConfigurationError("socket timeout must be between 0.1 and 30 seconds")


@dataclass(frozen=True, slots=True)
class HealthConfig:
    mode: str
    interface: str
    queue: int
    eve_path: Path
    socket_path: Path
    thresholds: HealthThresholds

    @property
    def expected_capture_mode(self) -> str:
        return "NFQ" if self.mode == "ips" else "AF_PACKET"


_HEALTH_KEYS = {
    "mode",
    "interface",
    "queue",
    "eve_path",
    "socket_path",
    *HealthThresholds.__dataclass_fields__.keys(),
}


def load_health_config(paths: MeercataPaths) -> HealthConfig:
    raw = _read_config(paths.controller_config_file)
    # Each subsystem validates its own table. Known sibling tables are accepted
    # so one strict controller file can serve the whole CLI.
    unknown_top = set(raw) - {
        "schema_version",
        "health",
        "rules",
        "ips",
        "monitor_delivery",
    }
    if unknown_top:
        raise HealthConfigurationError(
            f"unknown top-level configuration keys: {', '.join(sorted(unknown_top))}"
        )
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        raise HealthConfigurationError("configuration schema_version must be integer 1")
    health = raw.get("health")
    if not isinstance(health, dict):
        raise HealthConfigurationError("configuration requires a [health] table")
    unknown_health = set(health) - _HEALTH_KEYS
    if unknown_health:
        raise HealthConfigurationError(
            f"unknown health configuration keys: {', '.join(sorted(unknown_health))}"
        )
    mode = _required_string(health, "mode").lower()
    if mode not in {"ids", "ips"}:
        raise HealthConfigurationError("health.mode must be 'ids' or 'ips'")
    interface = _required_string(health, "interface")
    if INTERFACE_PATTERN.fullmatch(interface) is None:
        raise HealthConfigurationError("health.interface is invalid")
    queue = _integer(health.get("queue", 0), "queue", minimum=0, maximum=65535)
    eve_path = _managed_path(
        health.get("eve_path", str(paths.suricata_log_dir / "eve.json")),
        "eve_path",
        paths.suricata_log_dir,
    )
    socket_path = _managed_path(
        health.get(
            "socket_path",
            str(paths.suricata_run_dir / "suricata-command.socket"),
        ),
        "socket_path",
        paths.suricata_run_dir,
    )
    threshold_values: dict[str, float] = {}
    for name, field_info in HealthThresholds.__dataclass_fields__.items():
        default = field_info.default
        threshold_values[name] = _number(health.get(name, default), name)
    thresholds = HealthThresholds(**threshold_values)
    thresholds.validate()
    return HealthConfig(mode, interface, queue, eve_path, socket_path, thresholds)


def _read_config(path: Path) -> Mapping[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise HealthConfigurationError("controller configuration is not a regular file")
            if metadata.st_size > MAX_CONFIG_BYTES:
                raise HealthConfigurationError("controller configuration exceeds 1 MiB")
            chunks: list[bytes] = []
            remaining = MAX_CONFIG_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
    except HealthConfigurationError:
        raise
    except OSError as exc:
        raise HealthConfigurationError(f"cannot read controller configuration: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise HealthConfigurationError("controller configuration exceeds 1 MiB")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise HealthConfigurationError(f"invalid controller TOML: {exc}") from exc
    return value


def _required_string(values: Mapping[str, Any], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value:
        raise HealthConfigurationError(f"health.{name} must be a non-empty string")
    return value


def _integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise HealthConfigurationError(
            f"health.{name} must be an integer from {minimum} to {maximum}"
        )
    return value


def _number(value: Any, name: str) -> float:
    if type(value) not in {int, float}:
        raise HealthConfigurationError(f"health.{name} must be numeric")
    return float(value)


def _managed_path(value: Any, name: str, root: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise HealthConfigurationError(f"health.{name} must be an absolute path")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise HealthConfigurationError(f"health.{name} must be an absolute path")
    try:
        return require_within(candidate, root)
    except (UnsafePathError, OSError, ValueError) as exc:
        raise HealthConfigurationError(f"health.{name} is outside {root}") from exc
