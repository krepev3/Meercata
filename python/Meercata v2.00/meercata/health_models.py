"""Versioned health schema and deterministic severity aggregation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping

from meercata.models import local_now, utc_now

HEALTH_SCHEMA_VERSION = 1


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @property
    def exit_code(self) -> int:
        return {
            HealthStatus.HEALTHY: 0,
            HealthStatus.DEGRADED: 1,
            HealthStatus.CRITICAL: 2,
            HealthStatus.UNKNOWN: 3,
        }[self]


@dataclass(frozen=True, slots=True)
class HealthCheck:
    check_id: str
    status: HealthStatus
    summary: str
    required: bool = True
    observed: Any = None
    expected: Any = None
    metrics: Mapping[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "status": self.status.value,
            "required": self.required,
            "summary": self.summary,
            "observed": self.observed,
            "expected": self.expected,
            "metrics": dict(self.metrics),
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class HealthReport:
    mode: str
    checks: tuple[HealthCheck, ...]
    generated_utc: str = field(default_factory=utc_now)
    generated_local: str = field(default_factory=local_now)
    schema_version: int = HEALTH_SCHEMA_VERSION

    @property
    def status(self) -> HealthStatus:
        required = [check.status for check in self.checks if check.required]
        if not required:
            return HealthStatus.UNKNOWN
        for candidate in (
            HealthStatus.CRITICAL,
            HealthStatus.UNKNOWN,
            HealthStatus.DEGRADED,
        ):
            if candidate in required:
                return candidate
        return HealthStatus.HEALTHY

    @property
    def exit_code(self) -> int:
        return self.status.exit_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_utc": self.generated_utc,
            "generated_local": self.generated_local,
            "mode": self.mode,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "checks": [check.to_dict() for check in self.checks],
        }

    @classmethod
    def configuration_error(cls, summary: str) -> HealthReport:
        return cls(
            mode="unknown",
            checks=(
                HealthCheck(
                    "configuration",
                    HealthStatus.UNKNOWN,
                    summary,
                    remediation="Create or correct /etc/meercata/meercata.toml.",
                ),
            ),
        )


def render_health_report(report: HealthReport) -> str:
    rows = [
        (
            check.status.value.upper(),
            "required" if check.required else "optional",
            check.check_id,
            check.summary,
        )
        for check in report.checks
    ]
    headers = ("Status", "Level", "Check", "Summary")
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def render_row(row: Iterable[str]) -> str:
        return " | ".join(
            value.ljust(widths[index]) for index, value in enumerate(row)
        )

    separator = "-+-".join("-" * width for width in widths)
    prefix = (
        f"Meercata health: {report.status.value.upper()} "
        f"(mode={report.mode}, exit={report.exit_code})"
    )
    return "\n".join((prefix, render_row(headers), separator, *(render_row(row) for row in rows)))
