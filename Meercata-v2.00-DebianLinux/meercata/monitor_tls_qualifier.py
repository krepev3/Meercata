"""Disposable loopback-TLS qualification for monitor delivery operations."""

from __future__ import annotations

import argparse
import http.server
import json
import ssl
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import MonitorDeliveryError, QualificationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.monitor import MonitorService
from meercata.monitor_delivery import (
    DeliveryConfig,
    DeliveryOutbox,
    HttpsDeliveryTransport,
)
from meercata.paths import MeercataPaths

OPENSSL = "/usr/bin/openssl"
TOKEN_CURRENT = "dev24-current-token-000000000000"
TOKEN_RETIRED = "dev24-retired-token-000000000000"
MAX_COLLECTOR_BODY = 256 * 1024


@dataclass
class _CollectorState:
    token: str
    events: dict[str, dict[str, Any]] = field(default_factory=dict)
    requests: int = 0
    duplicates: int = 0
    unauthorized: int = 0


class _CollectorHandler(http.server.BaseHTTPRequestHandler):
    server: _CollectorServer

    def do_POST(self) -> None:
        state = self.server.collector_state
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if self.path != "/v1/meercata-events" or not 1 <= length <= MAX_COLLECTOR_BODY:
            self.send_error(400)
            return
        body = self.rfile.read(length)
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400)
            return
        event_id = self.headers.get("Idempotency-Key")
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or value.get("source") != "meercata"
            or value.get("event_id") != event_id
            or not isinstance(event_id, str)
            or len(event_id) != 64
            or not isinstance(value.get("event"), dict)
        ):
            self.send_error(400)
            return
        state.requests += 1
        if self.headers.get("Authorization") != f"Bearer {state.token}":
            state.unauthorized += 1
            self.send_response(401)
            self.end_headers()
            return
        if event_id in state.events:
            state.duplicates += 1
            self.send_response(200)
            self.end_headers()
            return
        state.events[event_id] = value["event"]
        self.send_response(202)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _CollectorServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        state: _CollectorState,
        certificate: Path,
        private_key: Path,
    ) -> None:
        self.collector_state = state
        self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls_context.load_cert_chain(certificate, private_key)
        super().__init__(address, _CollectorHandler)

    def get_request(self) -> tuple[ssl.SSLSocket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(2)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except (OSError, ssl.SSLError):
            connection.close()
            raise


class _Collector:
    def __init__(
        self,
        state: _CollectorState,
        certificate: Path,
        private_key: Path,
        *,
        port: int = 0,
    ) -> None:
        self.server = _CollectorServer(
            ("127.0.0.1", port), state, certificate, private_key
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="meercata-dev24-tls-collector",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def __enter__(self) -> _Collector:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise QualificationError("local TLS collector did not stop")


class _Reports:
    def collect(self) -> HealthReport:
        return HealthReport(
            "ids",
            (HealthCheck("service", HealthStatus.CRITICAL, "qualification event"),),
            generated_utc="2026-08-26T00:00:01Z",
            generated_local="2026-08-26T08:00:01+08:00",
        )


class _RecoveryReport:
    def collect(self) -> HealthReport:
        return HealthReport(
            "ids", (HealthCheck("service", HealthStatus.HEALTHY, "qualification recovery"),),
            generated_utc="2026-08-26T00:30:02Z",
            generated_local="2026-08-26T08:30:02+08:00",
        )


def qualify() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="meercata-monitor-tls-") as root_text:
        root = Path(root_text)
        pki1 = _generate_pki(root / "pki1", serial=1001, name="Dev24 CA 1")
        pki2 = _generate_pki(root / "pki2", serial=2001, name="Dev24 CA 2")
        state = _CollectorState(TOKEN_RETIRED)
        transport = HttpsDeliveryTransport()
        direct_event = {"qualification": "dev24", "sequence": 1}
        direct_id = "1" * 64
        paths = MeercataPaths.isolated(root / "meercata")
        MonitorService(paths, _Reports()).run()
        paths.monitor_delivery_token_dir.mkdir(parents=True, exist_ok=True)
        paths.monitor_delivery_token_file.write_text(TOKEN_CURRENT + "\n", encoding="ascii")
        paths.monitor_delivery_token_file.chmod(0o640)
        ca_path = paths.monitor_delivery_token_dir / "collector-ca.pem"
        ca_path.write_bytes(pki1["ca_cert"].read_bytes())
        ca_path.chmod(0o644)
        created = 1787702401  # 2026-08-26T00:00:01Z, matching the synthetic event.
        clock = [created]

        with _Collector(state, pki1["server_cert"], pki1["server_key"]) as collector:
            port = collector.port
            endpoint = f"https://localhost:{port}/v1/meercata-events"
            paths.controller_config_file.write_text(
                "schema_version=1\n[monitor_delivery]\n"
                f'endpoint="{endpoint}"\n'
                f'token_file="{paths.monitor_delivery_token_file}"\n'
                f'ca_file="{ca_path}"\n'
                "timeout_seconds=2\nmax_attempts=3\n"
                "base_retry_seconds=30\nmax_retry_seconds=120\n",
                encoding="utf-8",
            )
            # Use the ordinary config/token/CA loader for durable delivery.
            delivery = DeliveryOutbox(paths, wall_clock=lambda: clock[0])
            config1 = DeliveryConfig(
                endpoint, paths.monitor_delivery_token_file,
                timeout_seconds=2, ca_file=ca_path,
            )
            trusted = transport.send(config1, TOKEN_RETIRED, direct_id, direct_event)
            state.token = TOKEN_CURRENT
            retired = transport.send(
                config1, TOKEN_RETIRED, "2" * 64, {"qualification": "retired"}
            )
            retired_unauthorized = state.unauthorized
            rotated = transport.send(
                config1, TOKEN_CURRENT, "2" * 64, {"qualification": "rotated"}
            )
            duplicate = transport.send(config1, TOKEN_CURRENT, direct_id, direct_event)
            requests_before_mismatch = state.requests
            mismatch = transport.send(
                DeliveryConfig(
                    f"https://127.0.0.1:{port}/v1/meercata-events",
                    paths.monitor_delivery_token_file,
                    timeout_seconds=2, ca_file=ca_path,
                ),
                TOKEN_CURRENT, "3" * 64, {"qualification": "hostname-mismatch"},
            )
            mismatch_blocked_before_http = state.requests == requests_before_mismatch
            healthy = delivery.health()

        unavailable = delivery.deliver()
        retry_health = delivery.health()
        # Construct a new worker to prove retry state survives worker restart.
        delivery = DeliveryOutbox(paths, wall_clock=lambda: clock[0])
        before_due = delivery.deliver()
        clock[0] = created + 1801
        age_health = delivery.health()
        with _Collector(
            state, pki1["server_cert"], pki1["server_key"], port=port
        ):
            recovered = delivery.deliver()
            recovered_health = delivery.health()

        with _Collector(
            state, pki2["server_cert"], pki2["server_key"], port=port
        ):
            requests_before_rotation = state.requests
            old_ca = transport.send(
                config1, TOKEN_CURRENT, "4" * 64, {"qualification": "old-ca"}
            )
            rotation_blocked_before_http = state.requests == requests_before_rotation
            ca_path.write_bytes(pki2["ca_cert"].read_bytes())
            new_ca = transport.send(
                config1, TOKEN_CURRENT, "4" * 64, {"qualification": "new-ca"}
            )
            # A new condition with a retired on-disk token must dead-letter and
            # remain visible through the independently scheduled health query.
            MonitorService(paths, _RecoveryReport()).run()
            paths.monitor_delivery_token_file.write_text(TOKEN_RETIRED + "\n", encoding="ascii")
            rejected = delivery.deliver()
            dead_health = delivery.health()

        assertions = {
            "trusted": trusted.delivered and trusted.http_status == 202,
            "hostname": mismatch.code == "transport-error"
            and mismatch_blocked_before_http,
            "retired_token": retired.code == "remote-rejected"
            and retired.http_status == 401,
            "current_token": rotated.delivered and rotated.http_status == 202,
            "duplicate": duplicate.delivered
            and duplicate.http_status == 200
            and state.duplicates == 1,
            "outage": unavailable["retried"] == 1
            and unavailable["pending"] == 1
            and before_due["attempted"] == 0,
            "recovery": recovered["delivered"] == 1
            and recovered["pending"] == 0,
            "ca_rotation": old_ca.code == "transport-error"
            and new_ca.delivered
            and new_ca.http_status == 202 and rotation_blocked_before_http,
            "healthy": healthy["exit_code"] == 0 and healthy["pending"] == 1,
            "retry_health": retry_health["exit_code"] == 1 and retry_health["retrying"] == 1,
            "age_health": age_health["exit_code"] == 2
            and age_health["oldest_pending_age_seconds"] == 1801,
            "recovered_health": recovered_health["exit_code"] == 0,
            "dead_health": rejected["dead_lettered"] == 1
            and dead_health["exit_code"] == 2 and dead_health["dead_letters"] == 1,
        }
        failed = [name for name, passed in assertions.items() if not passed]
        if failed:
            raise QualificationError(
                "loopback TLS delivery assertions failed: " + ", ".join(failed)
            )

        checks = [
            _passed(
                "tls.trusted-ca",
                {"delivered": trusted.delivered, "http_status": trusted.http_status},
            ),
            _passed(
                "tls.hostname-refused",
                {
                    "result": mismatch.code,
                    "collector_requests_unchanged": mismatch_blocked_before_http,
                },
            ),
            _passed(
                "auth.retired-token-refused",
                {
                    "result": retired.code,
                    "http_status": retired.http_status,
                    "unauthorized": retired_unauthorized,
                },
            ),
            _passed(
                "auth.current-token-accepted",
                {"delivered": rotated.delivered, "http_status": rotated.http_status},
            ),
            _passed(
                "collector.duplicate-deduplicated",
                {
                    "delivered": duplicate.delivered,
                    "http_status": duplicate.http_status,
                    "duplicates": state.duplicates,
                },
            ),
            _passed(
                "outage.retry-persisted",
                {
                    "retried": unavailable["retried"],
                    "pending": unavailable["pending"],
                },
            ),
            _passed(
                "outage.delivery-recovered",
                {
                    "delivered": recovered["delivered"],
                    "pending": recovered["pending"],
                },
            ),
            _passed(
                "tls.ca-rotation",
                {
                    "old_ca_result": old_ca.code,
                    "new_ca_delivered": new_ca.delivered,
                    "new_ca_http_status": new_ca.http_status,
                    "old_ca_blocked_before_http": rotation_blocked_before_http,
                },
            ),
            _passed("health.pending-healthy", {
                "status": healthy["status"], "exit_code": healthy["exit_code"],
                "pending": healthy["pending"],
            }),
            _passed("health.retry-degraded", {
                "status": retry_health["status"], "exit_code": retry_health["exit_code"],
                "retrying": retry_health["retrying"], "before_due_attempted": before_due["attempted"],
            }),
            _passed("health.age-critical", {
                "status": age_health["status"], "exit_code": age_health["exit_code"],
                "oldest_pending_age_seconds": age_health["oldest_pending_age_seconds"],
                "recovered_exit_code": recovered_health["exit_code"],
            }),
            _passed("health.dead-letter-critical", {
                "status": dead_health["status"], "exit_code": dead_health["exit_code"],
                "dead_letters": dead_health["dead_letters"],
            }),
        ]
    return {
        "schema_version": 1,
        "status": "monitor-tls-qualified",
        "project_version": __version__,
        "checks": checks,
        "limitations": [
            "qualification used an automatically removed loopback collector and generated disposable keys",
            "no production endpoint, credential, certificate authority, DNS, proxy, or external network was used",
            "collector clustering, regional failover, rate limits, and long-duration availability were not exercised",
            "systemd PID 1 execution and production secret provisioning remain separate deployment gates",
        ],
    }


def _generate_pki(directory: Path, *, serial: int, name: str) -> dict[str, Path]:
    directory.mkdir(mode=0o700)
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.pem"
    server_key = directory / "server.key"
    request = directory / "server.csr"
    server_cert = directory / "server.pem"
    extensions = directory / "server.ext"
    extensions.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost\n",
        encoding="ascii",
    )
    commands = (
        (
            "ca",
            (
                OPENSSL,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-days",
                "3650",
                "-sha256",
                "-subj",
                f"/CN=Meercata {name}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            ),
        ),
        (
            "request",
            (
                OPENSSL,
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(server_key),
                "-out",
                str(request),
                "-sha256",
                "-subj",
                "/CN=localhost",
            ),
        ),
        (
            "sign",
            (
                OPENSSL,
                "x509",
                "-req",
                "-in",
                str(request),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                str(serial),
                "-out",
                str(server_cert),
                "-days",
                "3650",
                "-sha256",
                "-extfile",
                str(extensions),
            ),
        ),
    )
    for suffix, argv in commands:
        command_id = f"openssl.{serial}.{suffix}"
        result = CommandRunner(
            {command_id: CommandDefinition.fixed(argv, timeout_seconds=30)}
        ).run(command_id)
        if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
            raise QualificationError(f"{command_id} failed")
    return {
        "ca_cert": ca_cert,
        "server_cert": server_cert,
        "server_key": server_key,
    }


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    if any(value is False for value in details.values()):
        raise QualificationError(f"{check_id} did not satisfy its assertion")
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="python3 -m meercata.monitor_tls_qualifier",
        description="Qualify monitor delivery against a disposable loopback TLS collector",
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
        print(f"meercata-monitor-tls-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
