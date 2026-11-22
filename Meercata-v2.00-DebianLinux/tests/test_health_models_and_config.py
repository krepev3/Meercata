import json
from pathlib import Path

import pytest

from meercata.errors import HealthConfigurationError
from meercata.health_config import load_health_config
from meercata.health_models import (
    HealthCheck,
    HealthReport,
    HealthStatus,
    render_health_report,
)
from meercata.paths import MeercataPaths


def write_config(paths: MeercataPaths, body: str) -> None:
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(body, encoding="utf-8")


def valid_config(paths: MeercataPaths, extra: str = "") -> str:
    return f'''schema_version = 1

[health]
mode = "ids"
interface = "eth0"
queue = 0
eve_path = "{paths.suricata_log_dir / 'eve.json'}"
socket_path = "{paths.suricata_run_dir / 'suricata-command.socket'}"
{extra}
'''


def test_health_status_exit_codes_and_aggregation() -> None:
    assert HealthStatus.HEALTHY.exit_code == 0
    assert HealthStatus.DEGRADED.exit_code == 1
    assert HealthStatus.CRITICAL.exit_code == 2
    assert HealthStatus.UNKNOWN.exit_code == 3

    report = HealthReport(
        "ids",
        (
            HealthCheck("healthy", HealthStatus.HEALTHY, "ok"),
            HealthCheck("optional", HealthStatus.UNKNOWN, "not sampled", required=False),
            HealthCheck("degraded", HealthStatus.DEGRADED, "warning"),
        ),
    )
    assert report.status == HealthStatus.DEGRADED
    assert report.exit_code == 1

    critical = HealthReport(
        "ids",
        (
            HealthCheck("unknown", HealthStatus.UNKNOWN, "unknown"),
            HealthCheck("critical", HealthStatus.CRITICAL, "down"),
        ),
    )
    assert critical.status == HealthStatus.CRITICAL


def test_health_report_json_schema_and_human_output() -> None:
    report = HealthReport(
        "ids",
        (HealthCheck("service", HealthStatus.HEALTHY, "active"),),
    )

    value = report.to_dict()
    assert value["schema_version"] == 1
    assert value["status"] == "healthy"
    assert value["checks"][0]["id"] == "service"
    assert "Meercata health: HEALTHY" in render_health_report(report)


def test_health_json_schema_tracks_report_contract() -> None:
    schema_path = Path(__file__).parents[1] / "schemas" / "health-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    report_keys = set(
        HealthReport(
            "ids",
            (HealthCheck("service", HealthStatus.HEALTHY, "active"),),
        ).to_dict()
    )

    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["properties"]["schema_version"]["const"] == 1
    assert set(schema["required"]) == report_keys


def test_load_health_config_with_defaults(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config(paths))

    config = load_health_config(paths)

    assert config.mode == "ids"
    assert config.expected_capture_mode == "AF_PACKET"
    assert config.thresholds.watch_interval_seconds == 5


def test_health_config_accepts_known_rules_sibling_table(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config(paths) + '\n[rules]\nsource = "et/open"\n')

    config = load_health_config(paths)

    assert config.mode == "ids"


def test_load_health_config_accepts_ips_and_overrides(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    body = valid_config(paths).replace('mode = "ids"', 'mode = "ips"').replace(
        "queue = 0", "queue = 42"
    )
    body += "\npacket_stall_seconds = 45\n"
    write_config(paths, body)

    config = load_health_config(paths)

    assert config.expected_capture_mode == "NFQ"
    assert config.queue == 42
    assert config.thresholds.packet_stall_seconds == 45


@pytest.mark.parametrize(
    "body_fragment, expected",
    [
        ("unknown_key = 1", "unknown health"),
        ('mode = "bad"', "must be 'ids' or 'ips'"),
        ("queue = 70000", "integer from 0 to 65535"),
        ("watch_interval_seconds = 0.1", "between 0.5 and 300"),
        (
            "eve_stale_warning_seconds = 120\neve_stale_critical_seconds = 30",
            "warning thresholds",
        ),
    ],
)
def test_load_health_config_rejects_invalid_values(
    tmp_path: Path,
    body_fragment: str,
    expected: str,
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    body = valid_config(paths)
    if body_fragment.startswith("mode ="):
        body = body.replace('mode = "ids"', body_fragment)
    elif body_fragment.startswith("queue ="):
        body = body.replace("queue = 0", body_fragment)
    else:
        body += f"\n{body_fragment}\n"
    write_config(paths, body)

    with pytest.raises(HealthConfigurationError, match=expected):
        load_health_config(paths)


def test_load_health_config_rejects_path_outside_managed_root(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    body = valid_config(paths).replace(
        str(paths.suricata_log_dir / "eve.json"),
        "/tmp/unmanaged-eve.json",
    )
    write_config(paths, body)

    with pytest.raises(HealthConfigurationError, match="outside"):
        load_health_config(paths)


def test_load_health_config_rejects_symlink_file(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    target = tmp_path / "target.toml"
    target.write_text(valid_config(paths), encoding="utf-8")
    paths.controller_config_file.symlink_to(target)

    with pytest.raises(HealthConfigurationError, match="cannot read"):
        load_health_config(paths)


def test_health_thresholds_reject_nonfinite_number(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config(paths, "packet_stall_seconds = nan"))

    with pytest.raises(HealthConfigurationError):
        load_health_config(paths)
