"""Deterministic disposable qualification for durable monitor transitions."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence, TextIO

from meercata import __version__
from meercata.errors import MonitorError, QualificationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.monitor import MAX_MONITOR_LOG_BYTES, MonitorService
from meercata.paths import MeercataPaths


class _Reports:
    def __init__(self, reports: Sequence[HealthReport]) -> None:
        self.reports = tuple(reports)
        self.index = 0

    def collect(self) -> HealthReport:
        report = self.reports[min(self.index, len(self.reports) - 1)]
        self.index += 1
        return report


def qualify() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="meercata-monitor-qualification-") as root:
        paths = MeercataPaths.isolated(Path(root))
        service = MonitorService(
            paths,
            _Reports(
                (
                    _report(HealthStatus.CRITICAL, "service", 1),
                    _report(HealthStatus.CRITICAL, "service", 2),
                    _report(HealthStatus.CRITICAL, "disk", 3),
                    _report(HealthStatus.HEALTHY, "service", 4),
                    _report(HealthStatus.HEALTHY, "service", 5),
                )
            ),
        )
        baseline = service.run()
        duplicate = service.run()
        changed = service.run()
        recovered = service.run()
        paths.monitor_state_file.unlink()
        repaired = service.run()
        events = service.events(10)
        checks = [
            _passed(
                "transition.baseline",
                {
                    "sequence": baseline["sequence"],
                    "status": baseline["status"],
                    "affected": len(baseline["transition"]["affected_checks"]),
                },
            ),
            _passed(
                "transition.deduplicated",
                {
                    "transition_emitted": duplicate["transition_emitted"],
                    "consecutive": duplicate["state"]["consecutive_observations"],
                },
            ),
            _passed(
                "transition.conditions-changed",
                {
                    "sequence": changed["sequence"],
                    "reason": changed["transition"]["reason"],
                },
            ),
            _passed(
                "transition.recovered",
                {
                    "sequence": recovered["sequence"],
                    "reason": recovered["transition"]["reason"],
                    "status": recovered["status"],
                },
            ),
            _passed(
                "crash.state-repaired",
                {
                    "sequence": repaired["sequence"],
                    "transition_emitted": repaired["transition_emitted"],
                    "events": len(events),
                },
            ),
            _unsafe_state_check(),
            _retention_check(),
        ]
    return {
        "schema_version": 1,
        "status": "monitoring-qualified",
        "project_version": __version__,
        "checks": checks,
        "limitations": [
            "qualification used synthetic health reports in an automatically removed local filesystem",
            "systemd syntax and package ownership are covered by separate package qualification",
            "no external collector, credential, network delivery, or long-duration soak was exercised",
        ],
    }


def _unsafe_state_check() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="meercata-monitor-invalid-") as root:
        paths = MeercataPaths.isolated(Path(root))
        paths.monitor_state_dir.mkdir(parents=True)
        paths.monitor_state_file.write_text("{}\n", encoding="utf-8")
        try:
            MonitorService(
                paths, _Reports((_report(HealthStatus.HEALTHY, "service", 6),))
            ).run()
        except MonitorError:
            return _passed("integrity.invalid-state-refused", {"refused": True})
    raise QualificationError("monitor accepted an invalid durable state")


def _retention_check() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="meercata-monitor-retention-") as root:
        paths = MeercataPaths.isolated(Path(root))
        paths.monitor_log_dir.mkdir(parents=True)
        with paths.monitor_events_file.open("wb") as handle:
            handle.truncate(MAX_MONITOR_LOG_BYTES + 1)
        try:
            MonitorService(
                paths, _Reports((_report(HealthStatus.HEALTHY, "service", 7),))
            ).events(1)
        except MonitorError:
            return _passed(
                "retention.oversize-refused",
                {"active_limit_bytes": MAX_MONITOR_LOG_BYTES, "refused": True},
            )
    raise QualificationError("monitor accepted an oversized transition log")


def _report(status: HealthStatus, check_id: str, second: int) -> HealthReport:
    return HealthReport(
        "ips",
        (
            HealthCheck(
                check_id,
                status,
                f"qualification {check_id} {status.value}",
                remediation=None if status == HealthStatus.HEALTHY else "qualification repair",
            ),
        ),
        generated_utc=f"2026-08-26T00:00:{second:02d}Z",
        generated_local=f"2026-08-26T08:00:{second:02d}+08:00",
    )


def _passed(check_id: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": details}


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="python3 -m meercata.monitor_qualifier",
        description="Qualify durable monitoring transitions in disposable local state",
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    build_parser().parse_args(argv)
    try:
        print(json.dumps(qualify(), sort_keys=True), file=stdout)
        return 0
    except (OSError, MonitorError, QualificationError) as exc:
        print(f"meercata-monitor-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
