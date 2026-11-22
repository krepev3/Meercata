from __future__ import annotations

import io
import json
from pathlib import Path
import stat

import pytest

from meercata.cli import main
from meercata.errors import LockHeldError, MonitorError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.locking import ControllerLock
from meercata.monitor import MonitorService
from meercata.paths import MeercataPaths


class Reports:
    def __init__(self, *reports: HealthReport) -> None:
        self.reports = reports
        self.index = 0

    def collect(self) -> HealthReport:
        report = self.reports[min(self.index, len(self.reports) - 1)]
        self.index += 1
        return report


class FailingReports:
    def collect(self) -> HealthReport:
        raise RuntimeError("injected collector failure")


def report(
    status: HealthStatus,
    *,
    check_id: str = "service",
    second: int = 0,
) -> HealthReport:
    return HealthReport(
        "ips",
        (
            HealthCheck(
                check_id,
                status,
                f"{check_id} is {status.value}",
                remediation=None if status == HealthStatus.HEALTHY else "restore service",
            ),
        ),
        generated_utc=f"2026-08-26T00:00:{second:02d}Z",
        generated_local=f"2026-08-26T08:00:{second:02d}+08:00",
    )


def test_monitor_emits_baseline_deduplicates_and_records_recovery(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(
        paths,
        Reports(
            report(HealthStatus.CRITICAL, second=1),
            report(HealthStatus.CRITICAL, second=2),
            report(HealthStatus.HEALTHY, second=3),
        ),
    )

    first = service.run()
    second = service.run()
    third = service.run()

    assert first["transition"]["reason"] == "baseline"
    assert first["transition"]["affected_checks"][0]["id"] == "service"
    assert second["transition_emitted"] is False
    assert second["state"]["consecutive_observations"] == 2
    assert third["transition"]["reason"] == "recovered"
    assert third["sequence"] == 2
    assert [event["reason"] for event in service.events(10)] == ["baseline", "recovered"]
    assert stat.S_IMODE(paths.monitor_state_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.monitor_events_file.stat().st_mode) == 0o600


def test_monitor_records_condition_change_at_same_severity(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(
        paths,
        Reports(
            report(HealthStatus.CRITICAL, check_id="service", second=1),
            report(HealthStatus.CRITICAL, check_id="disk", second=2),
        ),
    )

    service.run()
    changed = service.run()

    assert changed["transition"]["reason"] == "conditions-changed"
    assert changed["transition"]["previous"]["status"] == "critical"


def test_monitor_repairs_missing_state_from_durable_event_without_duplicate(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(paths, Reports(report(HealthStatus.DEGRADED, second=1)))
    service.run()
    paths.monitor_state_file.unlink()

    repaired = service.run()

    assert repaired["transition_emitted"] is False
    assert repaired["sequence"] == 1
    assert len(service.events(10)) == 1


def test_monitor_refuses_corrupt_state_and_symlink_log(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(paths, Reports(report(HealthStatus.HEALTHY)))
    paths.monitor_state_dir.mkdir(parents=True)
    paths.monitor_state_file.write_text("{}\n", encoding="utf-8")

    with pytest.raises(MonitorError, match="schema"):
        service.run()

    paths.monitor_state_file.unlink()
    paths.monitor_log_dir.mkdir(parents=True)
    target = tmp_path / "foreign-log"
    target.write_text("", encoding="utf-8")
    paths.monitor_events_file.symlink_to(target)
    with pytest.raises(MonitorError, match="read monitor transition log"):
        service.run()


def test_monitor_lock_rejects_concurrent_writer(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    lock = ControllerLock(paths.monitor_lock_file)
    lock.acquire("test-owner")
    try:
        with pytest.raises(LockHeldError):
            MonitorService(paths, Reports(report(HealthStatus.HEALTHY))).run()
    finally:
        lock.release()


def test_monitor_event_query_is_bounded(tmp_path: Path) -> None:
    service = MonitorService(
        MeercataPaths.isolated(tmp_path), Reports(report(HealthStatus.HEALTHY))
    )

    with pytest.raises(MonitorError, match="limit"):
        service.events(0)
    with pytest.raises(MonitorError, match="limit"):
        service.events(101)


def test_monitor_converts_unexpected_collection_failure_to_unknown(tmp_path: Path) -> None:
    value = MonitorService(MeercataPaths.isolated(tmp_path), FailingReports()).run()

    assert value["status"] == "unknown"
    assert value["exit_code"] == 3
    assert value["transition"]["affected_checks"][0]["id"] == "configuration"
    assert "RuntimeError" in value["health"]["checks"][0]["summary"]


def test_monitor_refuses_malformed_existing_transition(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.monitor_log_dir.mkdir(parents=True)
    paths.monitor_events_file.write_text(
        '{"event":"health-transition","state_after":{}}\n', encoding="utf-8"
    )

    with pytest.raises(MonitorError, match="schema"):
        MonitorService(paths, Reports(report(HealthStatus.HEALTHY))).events(1)


def test_monitor_cli_run_status_and_events(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(paths, Reports(report(HealthStatus.DEGRADED, second=1)))
    factory = lambda _paths: service
    stdout = io.StringIO()

    assert (
        main(
            ["monitor", "run", "--json"],
            paths=paths,
            stdout=stdout,
            monitor_factory=factory,
        )
        == 1
    )
    assert json.loads(stdout.getvalue())["transition_emitted"] is True

    stdout = io.StringIO()
    assert (
        main(
            ["monitor", "status", "--json"],
            paths=paths,
            stdout=stdout,
            monitor_factory=factory,
        )
        == 0
    )
    assert json.loads(stdout.getvalue())["status"] == "degraded"

    stdout = io.StringIO()
    assert (
        main(
            ["monitor", "events", "--json", "--limit", "1"],
            paths=paths,
            stdout=stdout,
            monitor_factory=factory,
        )
        == 0
    )
    assert json.loads(stdout.getvalue())[0]["reason"] == "baseline"


def test_monitor_status_is_unknown_before_first_observation(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(paths, Reports(report(HealthStatus.HEALTHY)))
    stdout = io.StringIO()

    result = main(
        ["monitor", "status", "--json"],
        paths=paths,
        stdout=stdout,
        monitor_factory=lambda _paths: service,
    )

    assert result == 3
    assert json.loads(stdout.getvalue())["status"] == "uninitialized"


def test_monitor_run_conforms_to_versioned_schema(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    source = Path(__file__).parents[1]
    schema = json.loads((source / "schemas/monitor-v1.schema.json").read_text())
    value = MonitorService(
        MeercataPaths.isolated(tmp_path), Reports(report(HealthStatus.HEALTHY))
    ).run()

    jsonschema.validate(value, schema)
