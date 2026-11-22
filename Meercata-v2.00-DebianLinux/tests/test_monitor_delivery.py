from __future__ import annotations

import io
import json
import stat
from datetime import datetime
from pathlib import Path

import pytest

from meercata.cli import main
from meercata.errors import MonitorDeliveryError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.monitor import MonitorService
from meercata.monitor_delivery import (
    DeliveryConfig,
    DeliveryOutbox,
    DeliveryResult,
    load_delivery_config,
    HttpsDeliveryTransport,
)
from meercata.paths import MeercataPaths


class Reports:
    def __init__(self, report: HealthReport) -> None:
        self.report = report

    def collect(self) -> HealthReport:
        return self.report


class Transport:
    def __init__(self, *results: DeliveryResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, str, str, dict[str, object]]] = []

    def send(
        self,
        config: DeliveryConfig,
        token: str,
        event_id: str,
        event: dict[str, object],
    ) -> DeliveryResult:
        self.calls.append((config.endpoint, token, event_id, event))
        return self.results.pop(0)


def _report(second: int = 1) -> HealthReport:
    return HealthReport(
        "ips",
        (HealthCheck("service", HealthStatus.CRITICAL, "service failed"),),
        generated_utc=f"2026-08-26T00:00:{second:02d}Z",
        generated_local=f"2026-08-26T08:00:{second:02d}+08:00",
    )


def _config(paths: MeercataPaths, **changes: object) -> DeliveryConfig:
    paths.monitor_delivery_token_dir.mkdir(parents=True, exist_ok=True)
    paths.monitor_delivery_token_file.write_text("a" * 32 + "\n", encoding="ascii")
    paths.monitor_delivery_token_file.chmod(0o640)
    values = {
        "endpoint": "https://collector.example.test/v1/meercata-events",
        "token_file": paths.monitor_delivery_token_file,
        "timeout_seconds": 5.0,
        "max_attempts": 3,
        "base_retry_seconds": 30,
        "max_retry_seconds": 120,
        "batch_size": 20,
    }
    values.update(changes)
    return DeliveryConfig(**values)


def _queued(paths: MeercataPaths) -> dict[str, object]:
    result = MonitorService(paths, Reports(_report())).run()
    assert result["transition_emitted"] is True
    return result


def test_monitor_transition_is_enqueued_once_with_private_files(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    service = MonitorService(paths, Reports(_report()))

    first = service.run()
    second = service.run()
    outbox = DeliveryOutbox(paths)

    assert first["sequence"] == second["sequence"] == 1
    assert outbox.status()["pending"] == 1
    envelope = next(paths.monitor_outbox_dir.iterdir())
    assert stat.S_IMODE(envelope.stat().st_mode) == 0o600
    assert len(json.loads(envelope.read_text())["event_id"]) == 64


def test_successful_delivery_writes_receipt_then_removes_envelope(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    transport = Transport(DeliveryResult(True, False, "accepted", 202))
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=transport,
        wall_clock=lambda: 1000,
    )

    report = delivery.deliver()

    assert report == {
        "schema_version": 1,
        "generated_utc": "1970-01-01T00:16:40Z",
        "status": "delivery-complete",
        "attempted": 1,
        "delivered": 1,
        "retried": 0,
        "dead_lettered": 0,
        "pending": 0,
    }
    assert transport.calls[0][1] == "a" * 32
    assert not list(paths.monitor_outbox_dir.iterdir())
    receipt = json.loads(paths.monitor_receipts_file.read_text())
    assert receipt["status"] == "delivered"
    assert receipt["http_status"] == 202
    assert "a" * 32 not in paths.monitor_receipts_file.read_text()


def test_retry_is_deferred_with_exponential_backoff_then_delivered(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    now = [1000]
    transport = Transport(
        DeliveryResult(False, True, "transport-error"),
        DeliveryResult(True, False, "accepted", 200),
    )
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=transport,
        wall_clock=lambda: now[0],
    )

    first = delivery.deliver()
    before_due = delivery.deliver()
    envelope = json.loads(next(paths.monitor_outbox_dir.iterdir()).read_text())
    now[0] = 1030
    final = delivery.deliver()

    assert first["retried"] == 1
    assert before_due["attempted"] == 0
    assert envelope["attempts"] == 1
    assert envelope["next_attempt_epoch"] == 1030
    assert final["delivered"] == 1
    assert len(transport.calls) == 2


def test_permanent_rejection_moves_envelope_to_bounded_dead_letter(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    transport = Transport(DeliveryResult(False, False, "remote-rejected", 401))
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=transport,
        wall_clock=lambda: 1000,
    )

    report = delivery.deliver()
    dead = delivery.dead_letters(1)[0]

    assert report["dead_lettered"] == 1
    assert report["pending"] == 0
    assert dead["attempts"] == 1
    assert dead["last_error"] == "remote-rejected"
    assert delivery.status()["dead_letters"] == 1


def test_delivery_reconciles_success_receipt_without_duplicate_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    transport = Transport(DeliveryResult(True, False, "accepted", 200))
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=transport,
        wall_clock=lambda: 1000,
    )
    original = __import__(
        "meercata.monitor_delivery", fromlist=["_unlink_synced"]
    )._unlink_synced
    monkeypatch.setattr(
        "meercata.monitor_delivery._unlink_synced",
        lambda _path: (_ for _ in ()).throw(OSError("injected crash")),
    )

    with pytest.raises(OSError, match="injected crash"):
        delivery.deliver()
    monkeypatch.setattr("meercata.monitor_delivery._unlink_synced", original)
    recovered = delivery.deliver()

    assert recovered["attempted"] == 0
    assert recovered["pending"] == 0
    assert len(transport.calls) == 1


def test_delivery_refuses_unsafe_endpoint_token_and_envelope(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        "schema_version=1\n[monitor_delivery]\n"
        'endpoint="http://collector.example.test/v1/events"\n',
        encoding="utf-8",
    )
    with pytest.raises(MonitorDeliveryError, match="HTTPS"):
        load_delivery_config(paths)

    _queued(paths)
    envelope = next(paths.monitor_outbox_dir.iterdir())
    envelope.write_text("{}\n", encoding="utf-8")
    with pytest.raises(MonitorDeliveryError, match="schema"):
        DeliveryOutbox(paths).status()

    envelope.unlink()
    MonitorService(paths, Reports(_report())).run()
    assert list(paths.monitor_outbox_dir.iterdir())
    config = _config(paths)
    paths.monitor_delivery_token_file.chmod(0o644)
    with pytest.raises(MonitorDeliveryError, match="permissions"):
        DeliveryOutbox(
            paths,
            config_loader=lambda _: config,
            transport=Transport(DeliveryResult(True, False, "accepted", 200)),
        ).deliver()


def test_delivery_config_is_strict_and_uses_fixed_credential_root(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        "schema_version=1\n"
        "[monitor_delivery]\n"
        'endpoint="https://collector.example.test/v1/events"\n'
        f'token_file="{paths.monitor_delivery_token_file}"\n'
        "timeout_seconds=5\nmax_attempts=4\nbase_retry_seconds=10\n"
        "max_retry_seconds=120\nbatch_size=5\n",
        encoding="utf-8",
    )

    config = load_delivery_config(paths)

    assert config.endpoint.startswith("https://")
    assert config.max_attempts == 4
    assert config.batch_size == 5


def test_monitor_freshness_detects_uninitialized_fresh_stale_and_future(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    observed = int(datetime.fromisoformat("2026-08-26T00:00:01+00:00").timestamp())
    empty = MonitorService(paths, Reports(_report()), wall_clock=lambda: observed)
    assert empty.freshness()["status"] == "uninitialized"
    empty.run()

    fresh = MonitorService(
        paths, Reports(_report()), wall_clock=lambda: observed + 180
    ).freshness()
    stale = MonitorService(
        paths, Reports(_report()), wall_clock=lambda: observed + 181
    ).freshness()
    future = MonitorService(
        paths, Reports(_report()), wall_clock=lambda: observed - 31
    ).freshness()

    assert (fresh["status"], fresh["exit_code"]) == ("fresh", 0)
    assert (stale["status"], stale["exit_code"]) == ("stale", 2)
    assert (future["status"], future["exit_code"]) == ("unknown", 3)


def test_delivery_and_freshness_cli_preserve_bounded_exit_contract(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=Transport(DeliveryResult(False, False, "remote-rejected", 400)),
        wall_clock=lambda: 1000,
    )
    stdout = io.StringIO()

    assert main(
        ["monitor", "deliver", "--json"],
        paths=paths,
        stdout=stdout,
        delivery_factory=lambda _: delivery,
    ) == 2
    assert json.loads(stdout.getvalue())["dead_lettered"] == 1

    stdout = io.StringIO()
    monitor = MonitorService(paths, Reports(_report()), wall_clock=lambda: 2_000_000_000)
    assert main(
        ["monitor", "freshness", "--json"],
        paths=paths,
        stdout=stdout,
        monitor_factory=lambda _: monitor,
    ) == 2
    assert json.loads(stdout.getvalue())["status"] == "stale"


def test_delivery_and_freshness_outputs_conform_to_versioned_schemas(
    tmp_path: Path,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    delivery_schema = json.loads(
        (root / "schemas/monitor-delivery-v1.schema.json").read_text()
    )
    freshness_schema = json.loads(
        (root / "schemas/monitor-freshness-v1.schema.json").read_text()
    )
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=Transport(DeliveryResult(False, False, "remote-rejected", 400)),
        wall_clock=lambda: 1000,
    )

    jsonschema.validate(delivery.deliver(), delivery_schema)
    jsonschema.validate(delivery.status(), delivery_schema)
    jsonschema.validate(delivery.dead_letters(100), delivery_schema)
    jsonschema.validate(delivery.health(), delivery_schema)
    freshness = MonitorService(
        paths, Reports(_report()), wall_clock=lambda: 2_000_000_000
    ).freshness()
    jsonschema.validate(freshness, freshness_schema)


@pytest.mark.parametrize(
    "status,delivered,retryable,code",
    [
        (202, True, False, "accepted"),
        (429, False, True, "remote-retryable"),
        (401, False, False, "remote-rejected"),
    ],
)
def test_https_transport_uses_verified_fixed_post_and_classifies_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    delivered: bool,
    retryable: bool,
    code: str,
) -> None:
    calls: dict[str, object] = {}

    class Response:
        def __init__(self) -> None:
            self.status = status

        def read(self, maximum: int) -> bytes:
            calls["read_maximum"] = maximum
            return b"ignored"

    class Connection:
        def __init__(self, host, port, timeout, context) -> None:
            calls.update(host=host, port=port, timeout=timeout, context=context)

        def request(self, method, path, body, headers) -> None:
            calls.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            calls["closed"] = True

    context = object()
    monkeypatch.setattr(
        "meercata.monitor_delivery.ssl.create_default_context",
        lambda **values: calls.update(context_values=values) or context,
    )
    monkeypatch.setattr("meercata.monitor_delivery.http.client.HTTPSConnection", Connection)
    paths = MeercataPaths.isolated(tmp_path)
    config = _config(paths)

    result = HttpsDeliveryTransport().send(
        config,
        "s" * 32,
        "f" * 64,
        {"sequence": 1},
    )

    assert (result.delivered, result.retryable, result.code) == (
        delivered,
        retryable,
        code,
    )
    assert calls["host"] == "collector.example.test"
    assert calls["method"] == "POST"
    assert calls["path"] == "/v1/meercata-events"
    assert calls["context"] is context
    assert calls["context_values"] == {"cafile": None}
    headers = calls["headers"]
    assert headers["Authorization"] == "Bearer " + "s" * 32
    assert headers["Idempotency-Key"] == "f" * 64
    assert calls["closed"] is True


def test_delivery_health_reports_age_retry_and_dead_letter_pressure(
    tmp_path: Path,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    created = int(datetime.fromisoformat("2026-08-26T00:00:01+00:00").timestamp())
    healthy = DeliveryOutbox(paths, wall_clock=lambda: created + 10).health()
    aged = DeliveryOutbox(paths, wall_clock=lambda: created + 301).health()
    transport = Transport(DeliveryResult(False, False, "remote-rejected", 401))
    delivery = DeliveryOutbox(
        paths,
        config_loader=lambda _: _config(paths),
        transport=transport,
        wall_clock=lambda: created + 302,
    )
    delivery.deliver()
    dead = delivery.health()

    assert (healthy["status"], healthy["exit_code"]) == ("healthy", 0)
    assert (aged["status"], aged["exit_code"]) == ("degraded", 1)
    assert aged["oldest_pending_age_seconds"] == 301
    assert (dead["status"], dead["exit_code"]) == ("critical", 2)
    assert dead["dead_letters"] == 1


def test_delivery_config_accepts_only_safe_private_ca_bundle(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    ca_file = paths.monitor_delivery_token_dir / "collector-ca.pem"
    paths.monitor_delivery_token_dir.mkdir()
    ca_file.write_text(
        "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    ca_file.chmod(0o644)
    paths.controller_config_file.write_text(
        "schema_version=1\n[monitor_delivery]\n"
        'endpoint="https://collector.example.test/v1/events"\n'
        f'ca_file="{ca_file}"\n',
        encoding="utf-8",
    )

    config = load_delivery_config(paths)

    assert config.ca_file == ca_file


@pytest.mark.parametrize(
    "age,status,exit_code",
    [(300, "healthy", 0), (301, "degraded", 1), (1800, "degraded", 1),
     (1801, "critical", 2), (-30, "healthy", 0), (-31, "unknown", 3)],
)
def test_delivery_health_cli_age_boundaries(tmp_path, age, status, exit_code) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    created = int(datetime.fromisoformat("2026-08-26T00:00:01+00:00").timestamp())
    delivery = DeliveryOutbox(paths, wall_clock=lambda: created + age)
    stdout = io.StringIO()
    assert main(
        ["monitor", "delivery-health", "--json"], paths=paths, stdout=stdout,
        delivery_factory=lambda _: delivery,
    ) == exit_code
    result = json.loads(stdout.getvalue())
    assert (result["status"], result["exit_code"]) == (status, exit_code)
    assert result["due_pending"] == 1
    assert result["oldest_pending_age_seconds"] == age


def test_delivery_health_reports_retry_then_recovers_without_requiring_secrets(tmp_path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    created = int(datetime.fromisoformat("2026-08-26T00:00:01+00:00").timestamp())
    clock = [created]
    delivery = DeliveryOutbox(
        paths, config_loader=lambda _: _config(paths),
        transport=Transport(DeliveryResult(False, True, "transport-error"),
                            DeliveryResult(True, False, "accepted", 202)),
        wall_clock=lambda: clock[0],
    )
    delivery.deliver()
    retry = delivery.health()
    assert (retry["status"], retry["retrying"], retry["due_pending"]) == ("degraded", 1, 0)
    clock[0] += 30
    delivery.deliver()
    paths.monitor_delivery_token_file.unlink()
    # The independent watchdog does not need the worker's credential or network.
    healthy = DeliveryOutbox(paths, wall_clock=lambda: clock[0]).health()
    assert (healthy["status"], healthy["pending"], healthy["retrying"]) == ("healthy", 0, 0)
    assert healthy["last_receipt"]["status"] == "delivered"


def test_delivery_health_refuses_corrupted_dead_letter(tmp_path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    delivery = DeliveryOutbox(
        paths, config_loader=lambda _: _config(paths),
        transport=Transport(DeliveryResult(False, False, "remote-rejected", 401)),
    )
    delivery.deliver()
    next(paths.monitor_dead_letter_dir.iterdir()).write_text("{}")
    with pytest.raises(MonitorDeliveryError, match="schema"):
        delivery.health()


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o744])
def test_delivery_refuses_unsafe_ca_before_transport(tmp_path, mode) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _queued(paths)
    ca = paths.monitor_delivery_token_dir / "collector-ca.pem"
    config = _config(paths, ca_file=ca)
    ca.write_text("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
    ca.chmod(mode)
    transport = Transport()
    delivery = DeliveryOutbox(paths, config_loader=lambda _: config, transport=transport)
    with pytest.raises(MonitorDeliveryError, match="permissions"):
        delivery.deliver()
    assert transport.calls == []


@pytest.mark.parametrize("kind", ["outside", "symlink"])
def test_delivery_config_refuses_ca_outside_credential_root(tmp_path, kind) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _config(paths)
    outside = tmp_path / "outside-ca.pem"
    outside.write_text("fixture")
    ca = outside
    if kind == "symlink":
        ca = paths.monitor_delivery_token_dir / "collector-ca.pem"
        ca.symlink_to(outside)
    paths.controller_config_file.write_text(
        'schema_version=1\n[monitor_delivery]\n'
        'endpoint="https://collector.example.test/v1/events"\n'
        f'ca_file="{ca}"\n'
    )
    with pytest.raises(MonitorDeliveryError, match="outside the credential directory"):
        load_delivery_config(paths)


def test_delivery_health_count_thresholds_use_actual_durable_envelopes(tmp_path) -> None:
    import copy

    paths = MeercataPaths.isolated(tmp_path)
    event = _queued(paths)["transition"]
    created = int(datetime.fromisoformat("2026-08-26T00:00:01+00:00").timestamp())
    delivery = DeliveryOutbox(paths, wall_clock=lambda: created)
    expected = {99: ("healthy", 0), 100: ("degraded", 1),
                499: ("degraded", 1), 500: ("critical", 2)}
    for sequence in range(2, 501):
        transition = copy.deepcopy(event)
        transition["sequence"] = sequence
        transition["state_after"]["sequence"] = sequence
        delivery.ensure(transition)
        if sequence in expected:
            health = delivery.health()
            assert health["pending"] == health["due_pending"] == sequence
            assert (health["status"], health["exit_code"]) == expected[sequence]


@pytest.mark.parametrize("timestamp", ["not-a-date", "2026-08-26T00:00:01"])
def test_delivery_health_rejects_ambiguous_event_times(tmp_path, timestamp) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    event = _queued(paths)["transition"]
    event["sequence"] = 2
    event["state_after"]["sequence"] = 2
    event["generated_utc"] = timestamp
    delivery = DeliveryOutbox(paths, wall_clock=lambda: 1787702401)
    delivery.ensure(event)
    assert (delivery.health()["status"], delivery.health()["exit_code"]) == ("unknown", 3)
