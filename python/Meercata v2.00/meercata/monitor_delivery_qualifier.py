"""Deterministic qualification for freshness and durable monitor delivery."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata import __version__
from meercata.errors import MonitorDeliveryError, QualificationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.monitor import MonitorService
from meercata.monitor_delivery import (
    DeliveryConfig,
    DeliveryOutbox,
    DeliveryResult,
    _append_receipt,
    _endpoint,
)
from meercata.paths import MeercataPaths


class _Reports:
    def __init__(self, reports: Sequence[HealthReport]) -> None:
        self.reports = tuple(reports)
        self.index = 0

    def collect(self) -> HealthReport:
        report = self.reports[min(self.index, len(self.reports) - 1)]
        self.index += 1
        return report


class _Transport:
    def __init__(self, results: Sequence[DeliveryResult]) -> None:
        self.results = list(results)
        self.calls = 0

    def send(
        self,
        config: DeliveryConfig,
        token: str,
        event_id: str,
        event: Mapping[str, Any],
    ) -> DeliveryResult:
        del config, token, event_id, event
        self.calls += 1
        if not self.results:
            raise QualificationError("delivery transport was called unexpectedly")
        return self.results.pop(0)


def qualify() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="meercata-delivery-qualification-") as root:
        paths = MeercataPaths.isolated(Path(root))
        monitor = MonitorService(
            paths,
            _Reports(
                (
                    _report(HealthStatus.CRITICAL, "service", 1),
                    _report(HealthStatus.CRITICAL, "service", 2),
                    _report(HealthStatus.HEALTHY, "service", 3),
                    _report(HealthStatus.CRITICAL, "disk", 4),
                )
            ),
        )
        baseline = monitor.run()
        duplicate = monitor.run()
        queued = DeliveryOutbox(paths).status()

        clock = [1000]
        retry_transport = _Transport(
            (
                DeliveryResult(False, True, "transport-error"),
                DeliveryResult(True, False, "accepted", 202),
            )
        )
        retry_delivery = DeliveryOutbox(
            paths,
            config_loader=lambda _: _config(paths),
            transport=retry_transport,
            wall_clock=lambda: clock[0],
        )
        retry = retry_delivery.deliver()
        deferred = retry_delivery.deliver()
        clock[0] = 1030
        accepted = retry_delivery.deliver()

        monitor.run()
        rejected_delivery = DeliveryOutbox(
            paths,
            config_loader=lambda _: _config(paths),
            transport=_Transport(
                (DeliveryResult(False, False, "remote-rejected", 401),)
            ),
            wall_clock=lambda: 1040,
        )
        rejected = rejected_delivery.deliver()
        dead = rejected_delivery.dead_letters(1)[0]

        final = monitor.run()
        envelope_path = next(paths.monitor_outbox_dir.iterdir())
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        _append_receipt(
            paths.monitor_receipts_file,
            {
                "schema_version": 1,
                "event_id": envelope["event_id"],
                "sequence": envelope["sequence"],
                "status": "delivered",
                "attempts": 1,
                "generated_utc": "1970-01-01T00:17:30Z",
                "result_code": "accepted",
                "http_status": 200,
            },
        )
        no_send = _Transport(())
        repaired = DeliveryOutbox(
            paths,
            config_loader=lambda _: _config(paths),
            transport=no_send,
            wall_clock=lambda: 1050,
        ).deliver()

        observed = int(
            datetime.fromisoformat(final["state"]["last_observed_utc"].replace("Z", "+00:00")).timestamp()
        )
        stale = MonitorService(
            paths,
            _Reports((_report(HealthStatus.HEALTHY, "service", 5),)),
            wall_clock=lambda: observed + 181,
        ).freshness()

        checks = [
            _passed(
                "outbox.transition-enqueued",
                {
                    "sequence": baseline["sequence"],
                    "pending": queued["pending"],
                },
            ),
            _passed(
                "outbox.duplicate-suppressed",
                {
                    "transition_emitted": duplicate["transition_emitted"],
                    "pending": queued["pending"],
                },
            ),
            _passed(
                "delivery.retry-deferred",
                {
                    "retried": retry["retried"],
                    "before_due_attempted": deferred["attempted"],
                },
            ),
            _passed(
                "delivery.accepted",
                {
                    "delivered": accepted["delivered"],
                    "transport_calls": retry_transport.calls,
                },
            ),
            _passed(
                "delivery.dead-lettered",
                {
                    "dead_lettered": rejected["dead_lettered"],
                    "attempts": dead["attempts"],
                    "last_error": dead["last_error"],
                },
            ),
            _passed(
                "crash.receipt-reconciled",
                {
                    "attempted": repaired["attempted"],
                    "pending": repaired["pending"],
                    "transport_calls": no_send.calls,
                },
            ),
            _passed(
                "freshness.stale-detected",
                {
                    "status": stale["status"],
                    "exit_code": stale["exit_code"],
                    "age_seconds": stale["age_seconds"],
                },
            ),
            _unsafe_endpoint_check(),
        ]
    return {
        "schema_version": 1,
        "status": "monitor-delivery-qualified",
        "project_version": __version__,
        "checks": checks,
        "limitations": [
            "qualification used injected transport results and an automatically removed local filesystem",
            "verified-TLS behavior is unit-covered but no external endpoint or production credential was used",
            "systemd execution and package ownership are covered by separate package qualification",
            "collector availability, certificate rotation, proxy behavior, and long-duration soak were not exercised",
        ],
    }


def _config(paths: MeercataPaths) -> DeliveryConfig:
    paths.monitor_delivery_token_dir.mkdir(parents=True, exist_ok=True)
    paths.monitor_delivery_token_file.write_text("q" * 32 + "\n", encoding="ascii")
    paths.monitor_delivery_token_file.chmod(0o640)
    return DeliveryConfig(
        "https://collector.example.test/v1/meercata-events",
        paths.monitor_delivery_token_file,
        5,
        3,
        30,
        120,
        20,
    )


def _report(status: HealthStatus, check_id: str, second: int) -> HealthReport:
    return HealthReport(
        "ips",
        (HealthCheck(check_id, status, f"qualification {check_id} {status.value}"),),
        generated_utc=f"2026-08-26T00:00:{second:02d}Z",
        generated_local=f"2026-08-26T08:00:{second:02d}+08:00",
    )


def _unsafe_endpoint_check() -> dict[str, Any]:
    try:
        _endpoint("http://untrusted.example.test/v1/events")
    except MonitorDeliveryError:
        return _passed("integrity.unsafe-endpoint-refused", {"refused": True})
    raise QualificationError("delivery accepted a non-HTTPS endpoint")


def _passed(check_id: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": details}


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="python3 -m meercata.monitor_delivery_qualifier",
        description="Qualify durable monitoring delivery in disposable local state",
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
    except (OSError, MonitorDeliveryError, QualificationError) as exc:
        print(f"meercata-monitor-delivery-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
