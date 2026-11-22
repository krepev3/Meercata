import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from meercata.health import HealthCollector
from meercata.health_config import HealthConfig, HealthThresholds
from meercata.health_models import HealthStatus
from meercata.models import CommandResult
from meercata.paths import MeercataPaths


def command_result(stdout: str, return_code: int = 0) -> CommandResult:
    return CommandResult(
        command_id="fake",
        argv=("/fake",),
        return_code=return_code,
        stdout=stdout,
        stderr="",
        timed_out=False,
        stdout_truncated=False,
        stderr_truncated=False,
        started_utc="2026-08-10T00:00:00Z",
        duration_seconds=0.01,
    )


class FakeCommands:
    def __init__(
        self,
        nft_value: Mapping[str, Any] | None = None,
        nfqueue_status: str = "42 1234 0 2 65535 0 0 1\n",
    ) -> None:
        self.nft_value = nft_value or {"nftables": []}
        self.nfqueue_status = nfqueue_status

    def run(self, command_id: str) -> CommandResult:
        if command_id == "systemd.suricata.show":
            return command_result(
                "ActiveState=active\n"
                "SubState=running\n"
                "MainPID=123\n"
                "ExecMainStatus=0\n"
                "Result=success\n"
                "Type=notify\n"
            )
        if command_id == "nftables.meercata.list":
            return command_result(json.dumps(self.nft_value))
        if command_id == "nfqueue.listeners.read":
            return command_result(self.nfqueue_status)
        raise AssertionError(command_id)


class FakeSocket:
    def __init__(self, values: Mapping[str, Any]) -> None:
        self.values = dict(values)

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def request(self, command: str, arguments: Mapping[str, Any] | None = None) -> Any:
        return self.values[command]


class FailingSocket(FakeSocket):
    def __enter__(self) -> "FakeSocket":
        raise OSError("socket unavailable")


def socket_values(capture_mode: str = "AF_PACKET") -> dict[str, Any]:
    commands = [
        "version",
        "uptime",
        "running-mode",
        "capture-mode",
        "iface-list",
        "iface-stat",
        "dump-counters",
    ]
    return {
        "command-list": {"commands": commands},
        "version": "8.0.6 RELEASE",
        "uptime": 100,
        "running-mode": "workers",
        "capture-mode": capture_mode,
        "iface-list": {
            "count": 1,
            "ifaces": ["NFQ#42" if capture_mode == "NFQ" else "eth0"],
        },
        "iface-stat": {"pkts": 1000, "drop": 0, "invalid-checksums": 0},
        "dump-counters": {
            "uptime": 100,
            "decoder": {"pkts": 1000},
            "capture": {"kernel_packets": 1000, "kernel_drops": 0},
            "tcp": {
                "reassembly_gap": 0,
                "ssn_memcap_drop": 0,
                "segment_memcap_drop": 0,
            },
            "flow": {"emerg_mode_entered": 0, "emerg_mode_over": 0},
        },
    }


def setup_host(tmp_path: Path, *, mode: str = "ids", queue: int = 0):
    paths = MeercataPaths.isolated(tmp_path)
    proc_root = tmp_path / "fake-proc"
    sys_root = tmp_path / "fake-sys"
    process = proc_root / "123"
    process.mkdir(parents=True)
    (process / "comm").write_text("Suricata-Main\n", encoding="utf-8")
    (process / "cmdline").write_bytes(b"/usr/bin/suricata\0-c\0/etc/suricata/suricata.yaml\0")
    (process / "status").write_text("Name:\tsuricata\nVmRSS:\t102400 kB\n", encoding="utf-8")
    stat_fields = ["S", *("0" for _ in range(10)), "100", "50", "0", "0"]
    (process / "stat").write_text(
        f"123 (Suricata-Main) {' '.join(stat_fields)}\n",
        encoding="utf-8",
    )
    (proc_root / "meminfo").write_text(
        "MemTotal:       1048576 kB\nMemAvailable:    524288 kB\n",
        encoding="utf-8",
    )
    nfq_path = proc_root / "net" / "netfilter"
    nfq_path.mkdir(parents=True)
    (nfq_path / "nfnetlink_queue").write_text(
        f"{queue} 1234 0 2 65535 0 0 1\n",
        encoding="utf-8",
    )
    interface = sys_root / "class" / "net" / "eth0"
    interface.mkdir(parents=True)
    (interface / "operstate").write_text("up\n", encoding="utf-8")
    paths.suricata_log_dir.mkdir(parents=True)
    eve = paths.suricata_log_dir / "eve.json"
    eve.write_text('{"event_type":"stats"}\n', encoding="utf-8")
    os.utime(eve, (995, 995))
    config = HealthConfig(
        mode=mode,
        interface="eth0",
        queue=queue,
        eve_path=eve,
        socket_path=paths.suricata_run_dir / "suricata-command.socket",
        thresholds=HealthThresholds(packet_stall_seconds=10),
    )
    return paths, proc_root, sys_root, config


def nft_hooks(queue: int = 42, interface: str = "eth0", bypass: bool = True):
    flags = ["bypass"] if bypass else []
    return {
        "nftables": [
            {
                "rule": {
                    "family": "inet",
                    "table": "meercata",
                    "chain": "forward",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": interface,
                            }
                        },
                        {"counter": {"packets": 99, "bytes": 1000}},
                        {"queue": {"num": queue, "flags": flags}},
                    ],
                }
            }
        ]
    }


def collector(
    tmp_path: Path,
    *,
    mode: str = "ids",
    queue: int = 0,
    values: Mapping[str, Any] | None = None,
    commands: FakeCommands | None = None,
    clock: list[float] | None = None,
) -> tuple[HealthCollector, MeercataPaths, Path]:
    paths, proc_root, sys_root, config = setup_host(tmp_path, mode=mode, queue=queue)
    current = clock or [1000.0]
    socket_data = values or socket_values("NFQ" if mode == "ips" else "AF_PACKET")
    instance = HealthCollector(
        config,
        paths,
        commands=commands or FakeCommands(nft_hooks(queue)),
        socket_factory=lambda _path, _timeout: FakeSocket(socket_data),
        proc_root=proc_root,
        sys_root=sys_root,
        wall_clock=lambda: 1000,
        monotonic_clock=lambda: current[0],
    )
    return instance, paths, proc_root


def by_id(report, check_id: str):
    return next(check for check in report.checks if check.check_id == check_id)


def test_healthy_ids_report(tmp_path: Path) -> None:
    instance, _paths, _proc = collector(tmp_path)

    report = instance.collect()

    assert report.status == HealthStatus.HEALTHY
    assert report.exit_code == 0
    assert by_id(report, "capture_mode").status == HealthStatus.HEALTHY
    assert by_id(report, "packet_loss").status == HealthStatus.HEALTHY


def test_ips_health_targets_private_suricata_unit(tmp_path: Path) -> None:
    instance, _paths, _proc = collector(tmp_path, mode="ips", queue=42)

    assert instance.service_unit == "meercata-suricata-ips.service"
    report = instance.collect()
    assert by_id(report, "service").status == HealthStatus.HEALTHY
    assert by_id(report, "capture_interface").observed == ["NFQ#42"]


def test_suricata_8_af_packet_dev_alias_is_healthy(tmp_path: Path) -> None:
    instance, _paths, _proc = collector(
        tmp_path, values=socket_values("AF_PACKET_DEV")
    )

    assert by_id(instance.collect(), "capture_mode").status == HealthStatus.HEALTHY


def test_stopped_process_is_critical(tmp_path: Path) -> None:
    instance, _paths, proc_root = collector(tmp_path)
    (proc_root / "123" / "comm").write_text("python\n", encoding="utf-8")
    (proc_root / "123" / "cmdline").write_bytes(b"/usr/bin/python3\0")

    report = instance.collect()

    assert by_id(report, "process").status == HealthStatus.CRITICAL
    assert report.exit_code == 2


def test_stale_eve_is_critical(tmp_path: Path) -> None:
    instance, paths, _proc = collector(tmp_path)
    os.utime(paths.suricata_log_dir / "eve.json", (800, 800))

    report = instance.collect()

    assert by_id(report, "eve_freshness").status == HealthStatus.CRITICAL


def test_failed_socket_is_critical_and_dependent_checks_unknown(tmp_path: Path) -> None:
    paths, proc_root, sys_root, config = setup_host(tmp_path)
    instance = HealthCollector(
        config,
        paths,
        commands=FakeCommands(),
        socket_factory=lambda _path, _timeout: FailingSocket({}),
        proc_root=proc_root,
        sys_root=sys_root,
        wall_clock=lambda: 1000,
    )

    report = instance.collect()

    assert by_id(report, "suricata_socket").status == HealthStatus.CRITICAL
    assert by_id(report, "capture_mode").status == HealthStatus.UNKNOWN
    assert report.status == HealthStatus.CRITICAL


@pytest.mark.parametrize(
    "field,value,check_id",
    [
        ("capture-mode", "NFQ", "capture_mode"),
        ("iface-list", {"count": 1, "ifaces": ["eth1"]}, "capture_interface"),
    ],
)
def test_wrong_capture_mode_or_interface_is_critical(
    tmp_path: Path,
    field: str,
    value: Any,
    check_id: str,
) -> None:
    values = socket_values()
    values[field] = value
    instance, _paths, _proc = collector(tmp_path, values=values)

    assert by_id(instance.collect(), check_id).status == HealthStatus.CRITICAL


def test_packet_counter_stall_is_detected_across_watch_samples(tmp_path: Path) -> None:
    clock = [0.0]
    instance, _paths, _proc = collector(tmp_path, clock=clock)

    assert by_id(instance.collect(), "packet_progress").status == HealthStatus.HEALTHY
    clock[0] = 5.0
    assert by_id(instance.collect(), "packet_progress").status == HealthStatus.HEALTHY
    clock[0] = 11.0
    third = instance.collect()

    assert by_id(third, "packet_progress").status == HealthStatus.CRITICAL


def test_ips_packet_progress_prefers_nfqueue_interface_counter(tmp_path: Path) -> None:
    values = socket_values("NFQ")
    values["dump-counters"]["decoder"]["pkts"] = 0
    values["iface-stat"]["pkts"] = 1
    instance, _paths, _proc = collector(
        tmp_path,
        mode="ips",
        queue=42,
        values=values,
    )

    check = by_id(instance.collect(), "packet_progress")

    assert check.status == HealthStatus.HEALTHY
    assert check.observed["packets"] == 1


def test_packet_loss_and_stream_gap_thresholds(tmp_path: Path) -> None:
    values = socket_values()
    values["iface-stat"] = {"pkts": 900, "drop": 100}
    values["dump-counters"]["tcp"]["reassembly_gap"] = 10
    instance, _paths, _proc = collector(tmp_path, values=values)

    report = instance.collect()

    assert by_id(report, "packet_loss").status == HealthStatus.CRITICAL
    assert by_id(report, "stream_gaps").status == HealthStatus.CRITICAL


def test_memcap_emergency_is_critical(tmp_path: Path) -> None:
    values = socket_values()
    values["dump-counters"]["flow"]["emerg_mode_entered"] = 2
    values["dump-counters"]["flow"]["emerg_mode_over"] = 1
    instance, _paths, _proc = collector(tmp_path, values=values)

    assert by_id(instance.collect(), "suricata_memcap").status == HealthStatus.CRITICAL


def test_healthy_ips_hooks_and_listener(tmp_path: Path) -> None:
    instance, _paths, _proc = collector(tmp_path, mode="ips", queue=42)

    report = instance.collect()

    assert by_id(report, "nftables_hooks").status == HealthStatus.HEALTHY
    assert by_id(report, "nfqueue_listener").status == HealthStatus.HEALTHY
    assert report.status == HealthStatus.HEALTHY


def test_wrong_nft_queue_and_missing_listener_are_critical(tmp_path: Path) -> None:
    instance, _paths, proc_root = collector(
        tmp_path,
        mode="ips",
        queue=42,
        commands=FakeCommands(nft_hooks(queue=7), nfqueue_status=""),
    )
    (proc_root / "net" / "netfilter" / "nfnetlink_queue").write_text("", encoding="utf-8")

    report = instance.collect()

    assert by_id(report, "nftables_hooks").status == HealthStatus.CRITICAL
    assert by_id(report, "nfqueue_listener").status == HealthStatus.CRITICAL


def test_memory_and_disk_pressure_are_critical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance, _paths, proc_root = collector(tmp_path)
    (proc_root / "meminfo").write_text(
        "MemTotal:       1000000 kB\nMemAvailable:     10000 kB\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "meercata.health.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=1000, used=960, free=40),
    )

    report = instance.collect()

    assert by_id(report, "memory").status == HealthStatus.CRITICAL
    assert by_id(report, "disk").status == HealthStatus.CRITICAL


def test_process_rss_and_cpu_pressure_affect_overall_health(tmp_path: Path) -> None:
    clock = [0.0]
    instance, _paths, proc_root = collector(tmp_path, clock=clock)
    (proc_root / "123" / "status").write_text(
        "Name:\tsuricata\nVmRSS:\t524288 kB\n",
        encoding="utf-8",
    )
    first = instance.collect()
    assert by_id(first, "process_resources").status == HealthStatus.CRITICAL
    assert first.status == HealthStatus.CRITICAL

    stat_fields = ["S", *("0" for _ in range(10)), "300", "50", "0", "0"]
    (proc_root / "123" / "stat").write_text(
        f"123 (Suricata-Main) {' '.join(stat_fields)}\n",
        encoding="utf-8",
    )
    clock[0] = 1.0
    second = instance.collect()
    assert by_id(second, "process_resources").observed["cpu_percent"] >= 100
