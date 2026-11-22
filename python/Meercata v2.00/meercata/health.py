"""Read-only production health collection for Suricata and Meercata."""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.health_config import HealthConfig, load_health_config
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.models import CommandResult
from meercata.paths import MeercataPaths
from meercata.privileged_client import (
    PrivilegedHealthCommandExecutor,
    PrivilegedHealthSocketFactory,
)
from meercata.suricata_socket import SuricataSocketClient


class CommandExecutor(Protocol):
    def run(self, command_id: str) -> CommandResult: ...


class SocketClient(Protocol):
    def __enter__(self) -> SocketClient: ...
    def __exit__(self, kind: object, value: object, traceback: object) -> None: ...
    def request(self, command: str, arguments: Mapping[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class SocketSnapshot:
    version: str
    uptime_seconds: float
    running_mode: str
    capture_mode: str
    interfaces: tuple[str, ...]
    interface_stats: Mapping[str, Any]
    counters: Mapping[str, Any]


class HealthService:
    def __init__(self, collector: HealthCollector) -> None:
        self.collector = collector

    @classmethod
    def from_paths(cls, paths: MeercataPaths) -> HealthService:
        config = load_health_config(paths)
        socket_factory = (
            PrivilegedHealthSocketFactory(
                paths,
                config.socket_path,
                _socket_capture_name(config),
            )
            if paths == MeercataPaths.production()
            else SuricataSocketClient
        )
        service_unit = (
            "meercata-suricata-ips.service"
            if config.mode == "ips"
            else "suricata.service"
        )
        commands = (
            PrivilegedHealthCommandExecutor(paths, service_unit)
            if paths == MeercataPaths.production()
            else None
        )
        return cls(
            HealthCollector(
                config,
                paths,
                commands=commands,
                socket_factory=socket_factory,
            )
        )

    def collect(self) -> HealthReport:
        return self.collector.collect()


class HealthCollector:
    def __init__(
        self,
        config: HealthConfig,
        paths: MeercataPaths,
        *,
        commands: CommandExecutor | None = None,
        socket_factory: Callable[[Path, float], SocketClient] = SuricataSocketClient,
        proc_root: Path = Path("/proc"),
        sys_root: Path = Path("/sys"),
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.paths = paths
        self.service_unit = (
            "meercata-suricata-ips.service"
            if config.mode == "ips"
            else "suricata.service"
        )
        self.commands = commands or _live_commands(self.service_unit)
        self.socket_factory = socket_factory
        self.proc_root = proc_root
        self.sys_root = sys_root
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self._previous_packets: tuple[int, float] | None = None
        self._previous_cpu: tuple[tuple[int, ...], int, float] | None = None

    def collect(self) -> HealthReport:
        checks: list[HealthCheck] = [
            HealthCheck(
                "configuration",
                HealthStatus.HEALTHY,
                "health configuration loaded and validated",
                observed={
                    "mode": self.config.mode,
                    "interface": self.config.interface,
                    "queue": self.config.queue,
                },
            )
        ]
        checks.append(self._service_check())
        process_check, processes = self._process_check()
        checks.append(process_check)
        checks.append(self._interface_check())
        socket_checks, snapshot = self._socket_checks()
        checks.extend(socket_checks)
        checks.append(self._eve_check())
        checks.append(self._packet_progress_check(snapshot))
        checks.append(self._packet_loss_check(snapshot))
        checks.append(self._stream_health_check(snapshot))
        checks.append(self._memcap_check(snapshot))
        if self.config.mode == "ips":
            checks.append(self._nftables_check())
            checks.append(self._nfqueue_listener_check())
        checks.append(self._disk_check())
        checks.append(self._memory_check())
        checks.append(self._process_resource_check(processes))
        return HealthReport(self.config.mode, tuple(checks))

    def _service_check(self) -> HealthCheck:
        try:
            result = self.commands.run("systemd.suricata.show")
        except Exception as exc:
            return _unknown("service", "cannot query systemd", exc)
        if not result.succeeded:
            return HealthCheck(
                "service",
                HealthStatus.UNKNOWN,
                f"systemd did not return {self.service_unit} state",
                observed={"return_code": result.return_code, "timed_out": result.timed_out},
                expected={"ActiveState": "active", "SubState": "running", "Type": "notify"},
                remediation=f"Verify systemd is running and {self.service_unit} is installed.",
            )
        properties = _parse_properties(result.stdout)
        active = properties.get("ActiveState")
        substate = properties.get("SubState")
        unit_type = properties.get("Type")
        metrics = {
            "main_pid": _safe_int(properties.get("MainPID")),
            "exec_main_status": _safe_int(properties.get("ExecMainStatus")),
            "result": properties.get("Result"),
        }
        if active != "active" or substate not in {"running", "exited"}:
            return HealthCheck(
                "service",
                HealthStatus.CRITICAL,
                f"{self.service_unit} is {active or 'unknown'}/{substate or 'unknown'}",
                observed=properties,
                expected={"ActiveState": "active", "SubState": "running", "Type": "notify"},
                metrics=metrics,
                remediation=f"Inspect journalctl -u {self.service_unit} and restore service readiness.",
            )
        if unit_type != "notify":
            return HealthCheck(
                "service",
                HealthStatus.DEGRADED,
                "Suricata is active but systemd readiness notification is not enforced",
                observed=properties,
                expected={"Type": "notify"},
                metrics=metrics,
                remediation="Install the qualified Type=notify Suricata unit.",
            )
        return HealthCheck(
            "service",
            HealthStatus.HEALTHY,
            "Suricata systemd unit is active and readiness-aware",
            observed=properties,
            expected={"ActiveState": "active", "SubState": "running", "Type": "notify"},
            metrics=metrics,
        )

    def _process_check(self) -> tuple[HealthCheck, tuple[int, ...]]:
        try:
            processes = _suricata_processes(self.proc_root)
        except OSError as exc:
            return _unknown("process", "cannot inspect process table", exc), ()
        pids = tuple(sorted(processes))
        if not pids:
            return (
                HealthCheck(
                    "process",
                    HealthStatus.CRITICAL,
                    "no Suricata process is running",
                    observed={"pids": []},
                    expected="one supervised Suricata process",
                    remediation=f"Start the qualified {self.service_unit} after correcting its failure.",
                ),
                (),
            )
        status = HealthStatus.HEALTHY if len(pids) == 1 else HealthStatus.DEGRADED
        summary = (
            "one Suricata process is running"
            if len(pids) == 1
            else f"multiple Suricata processes are running ({len(pids)})"
        )
        return (
            HealthCheck(
                "process",
                status,
                summary,
                observed={"pids": list(pids)},
                expected="one supervised Suricata process",
                remediation=(
                    None
                    if len(pids) == 1
                    else "Stop unintended Suricata instances and retain the supervised service."
                ),
            ),
            pids,
        )

    def _interface_check(self) -> HealthCheck:
        interface_dir = self.sys_root / "class" / "net" / self.config.interface
        if not interface_dir.exists():
            return HealthCheck(
                "interface",
                HealthStatus.CRITICAL,
                f"configured interface {self.config.interface} is missing",
                observed="missing",
                expected=self.config.interface,
                remediation="Correct health.interface or restore the network interface.",
            )
        try:
            state = (interface_dir / "operstate").read_text(encoding="utf-8").strip()
        except OSError as exc:
            return _unknown("interface", "cannot read interface operating state", exc)
        if state == "down":
            status = HealthStatus.CRITICAL
        elif state not in {"up", "unknown"}:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        return HealthCheck(
            "interface",
            status,
            f"{self.config.interface} operstate is {state}",
            observed=state,
            expected="up",
            remediation=(
                None if status == HealthStatus.HEALTHY else "Restore the configured capture interface."
            ),
        )

    def _socket_checks(self) -> tuple[list[HealthCheck], SocketSnapshot | None]:
        try:
            with self.socket_factory(
                self.config.socket_path,
                self.config.thresholds.socket_timeout_seconds,
            ) as client:
                command_list = client.request("command-list")
                available = _socket_command_names(command_list)
                required = {
                    "version",
                    "uptime",
                    "running-mode",
                    "capture-mode",
                    "iface-list",
                    "iface-stat",
                    "dump-counters",
                }
                missing = sorted(required - available)
                if missing:
                    raise ValueError(f"required read-only commands unavailable: {', '.join(missing)}")
                version = str(client.request("version"))
                uptime = float(client.request("uptime"))
                running_mode = str(client.request("running-mode"))
                capture_mode = str(client.request("capture-mode"))
                interfaces = _socket_interfaces(client.request("iface-list"))
                interface_stats = client.request(
                    "iface-stat", {"iface": _socket_capture_name(self.config)}
                )
                counters = client.request("dump-counters")
                if not isinstance(interface_stats, dict) or not isinstance(counters, dict):
                    raise ValueError("socket statistics have an invalid shape")
        except Exception as exc:
            socket_check = _critical(
                "suricata_socket",
                "Suricata read-only command socket is unavailable or invalid",
                exc,
                remediation="Restore the running Suricata Unix command socket and its group access.",
            )
            return (
                [
                    socket_check,
                    HealthCheck(
                        "capture_mode",
                        HealthStatus.UNKNOWN,
                        "capture mode cannot be verified without the Suricata socket",
                        expected=self.config.expected_capture_mode,
                    ),
                    HealthCheck(
                        "capture_interface",
                        HealthStatus.UNKNOWN,
                        "capture interface cannot be verified without the Suricata socket",
                        expected=self.config.interface,
                    ),
                ],
                None,
            )
        snapshot = SocketSnapshot(
            version,
            uptime,
            running_mode,
            capture_mode,
            interfaces,
            interface_stats,
            counters,
        )
        checks = [
            HealthCheck(
                "suricata_socket",
                HealthStatus.HEALTHY,
                "Suricata read-only command socket responded",
                observed={"version": version, "uptime_seconds": uptime, "running_mode": running_mode},
            )
        ]
        normalized_capture = _canonical_capture_mode(capture_mode)
        expected_capture = _canonical_capture_mode(self.config.expected_capture_mode)
        checks.append(
            HealthCheck(
                "capture_mode",
                HealthStatus.HEALTHY if normalized_capture == expected_capture else HealthStatus.CRITICAL,
                (
                    f"capture mode is {capture_mode}"
                    if normalized_capture == expected_capture
                    else f"capture mode {capture_mode} does not match {self.config.mode} policy"
                ),
                observed=capture_mode,
                expected=self.config.expected_capture_mode,
                remediation=(
                    None
                    if normalized_capture == expected_capture
                    else "Restart through the qualified Meercata lifecycle for the configured mode."
                ),
            )
        )
        socket_capture_name = _socket_capture_name(self.config)
        checks.append(
            HealthCheck(
                "capture_interface",
                HealthStatus.HEALTHY if socket_capture_name in interfaces else HealthStatus.CRITICAL,
                (
                    f"Suricata is capturing on {socket_capture_name}"
                    if socket_capture_name in interfaces
                    else f"Suricata is not capturing on {socket_capture_name}"
                ),
                observed=list(interfaces),
                expected=socket_capture_name,
                remediation=(
                    None
                    if self.config.interface in interfaces
                    else "Correct the capture configuration and restart through a transaction."
                ),
            )
        )
        return checks, snapshot

    def _eve_check(self) -> HealthCheck:
        try:
            metadata = self.config.eve_path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("EVE path is not a regular file")
            if not os.access(self.config.eve_path, os.R_OK):
                raise OSError("EVE file is not readable")
        except OSError as exc:
            return _critical(
                "eve_freshness",
                "EVE output is missing or unreadable",
                exc,
                remediation="Restore readable Suricata EVE JSON output.",
            )
        age = self.wall_clock() - metadata.st_mtime
        thresholds = self.config.thresholds
        if age < -5:
            status = HealthStatus.DEGRADED
            summary = "EVE modification time is in the future"
        elif age >= thresholds.eve_stale_critical_seconds:
            status = HealthStatus.CRITICAL
            summary = f"EVE output is stale ({age:.1f}s old)"
        elif age >= thresholds.eve_stale_warning_seconds:
            status = HealthStatus.DEGRADED
            summary = f"EVE output is aging ({age:.1f}s old)"
        else:
            status = HealthStatus.HEALTHY
            summary = f"EVE output is fresh ({max(age, 0):.1f}s old)"
        return HealthCheck(
            "eve_freshness",
            status,
            summary,
            observed={"path": str(self.config.eve_path), "age_seconds": round(age, 3), "size_bytes": metadata.st_size},
            expected={
                "warning_before_seconds": thresholds.eve_stale_warning_seconds,
                "critical_before_seconds": thresholds.eve_stale_critical_seconds,
            },
            remediation=(None if status == HealthStatus.HEALTHY else "Check EVE logging and packet flow."),
        )

    def _packet_progress_check(self, snapshot: SocketSnapshot | None) -> HealthCheck:
        if snapshot is None:
            return HealthCheck(
                "packet_progress",
                HealthStatus.UNKNOWN,
                "packet progress cannot be measured without socket counters",
                expected="decoder.pkts increasing",
            )
        if self.config.mode == "ips":
            # Suricata's NFQ iface-stat is the authoritative receive counter;
            # decoder.pkts can remain zero even after queue verdicts are issued.
            packets = _safe_int(snapshot.interface_stats.get("pkts"))
            if packets is None:
                packets = _counter(snapshot.counters, "decoder.pkts")
        else:
            packets = _counter(snapshot.counters, "decoder.pkts")
            if packets is None:
                packets = _safe_int(snapshot.interface_stats.get("pkts"))
        if packets is None:
            return HealthCheck(
                "packet_progress",
                HealthStatus.UNKNOWN,
                "Suricata did not expose a packet counter",
                expected="decoder.pkts increasing",
            )
        now = self.monotonic_clock()
        previous = self._previous_packets
        stalled_for = 0.0
        status = HealthStatus.HEALTHY
        summary = f"packet counter is {packets}"
        if packets == 0 and snapshot.uptime_seconds >= self.config.thresholds.packet_stall_seconds:
            status = HealthStatus.CRITICAL
            stalled_for = snapshot.uptime_seconds
            summary = "Suricata has been running without processing packets"
            self._previous_packets = (packets, now)
        elif previous is None:
            summary = f"packet counter baseline is {packets}"
            self._previous_packets = (packets, now)
        elif previous is not None and packets == previous[0]:
            stalled_for = now - previous[1]
            if stalled_for >= self.config.thresholds.packet_stall_seconds:
                status = HealthStatus.CRITICAL
                summary = f"packet counter has stalled for {stalled_for:.1f}s"
            else:
                summary = "packet counter is awaiting the configured stall window"
        elif previous is not None and packets > previous[0]:
            summary = f"packet counter advanced by {packets - previous[0]}"
            self._previous_packets = (packets, now)
        else:
            summary = "packet counter restarted; a new progress baseline was recorded"
            self._previous_packets = (packets, now)
        return HealthCheck(
            "packet_progress",
            status,
            summary,
            observed={"packets": packets, "stalled_seconds": round(stalled_for, 3)},
            expected={"maximum_stall_seconds": self.config.thresholds.packet_stall_seconds},
            remediation=(None if status == HealthStatus.HEALTHY else "Verify interface traffic, capture mode, and Suricata receive threads."),
        )

    def _packet_loss_check(self, snapshot: SocketSnapshot | None) -> HealthCheck:
        if snapshot is None:
            return HealthCheck(
                "packet_loss",
                HealthStatus.UNKNOWN,
                "packet loss cannot be measured without socket counters",
                expected="drop rate below warning threshold",
            )
        packets = _safe_int(snapshot.interface_stats.get("pkts"))
        drops = _safe_int(snapshot.interface_stats.get("drop"))
        source = "iface-stat"
        if packets is None or drops is None:
            packets = _counter(snapshot.counters, "capture.kernel_packets")
            drops = _counter(snapshot.counters, "capture.kernel_drops")
            source = "dump-counters"
        if packets is None or drops is None:
            return HealthCheck(
                "packet_loss",
                HealthStatus.UNKNOWN,
                "capture packet/drop counters are unavailable",
                expected="capture.kernel_drops available",
            )
        denominator = packets + drops
        percent = (drops / denominator * 100) if denominator else 0.0
        status = _high_is_bad(
            percent,
            self.config.thresholds.packet_drop_warning_percent,
            self.config.thresholds.packet_drop_critical_percent,
        )
        return HealthCheck(
            "packet_loss",
            status,
            f"capture drop rate is {percent:.4f}%",
            observed={"packets": packets, "drops": drops, "percent": round(percent, 6), "source": source},
            expected={
                "warning_below_percent": self.config.thresholds.packet_drop_warning_percent,
                "critical_below_percent": self.config.thresholds.packet_drop_critical_percent,
            },
            remediation=(None if status == HealthStatus.HEALTHY else "Investigate kernel/NIC pressure and tune capture capacity."),
        )

    def _stream_health_check(self, snapshot: SocketSnapshot | None) -> HealthCheck:
        if snapshot is None:
            return HealthCheck("stream_gaps", HealthStatus.UNKNOWN, "TCP stream gaps are unavailable")
        gaps = _counter(snapshot.counters, "tcp.reassembly_gap")
        packets = _counter(snapshot.counters, "decoder.pkts")
        if gaps is None or packets is None:
            return HealthCheck("stream_gaps", HealthStatus.UNKNOWN, "TCP reassembly gap counters are unavailable")
        percent = (gaps / packets * 100) if packets else 0.0
        status = _high_is_bad(
            percent,
            self.config.thresholds.reassembly_gap_warning_percent,
            self.config.thresholds.reassembly_gap_critical_percent,
        )
        return HealthCheck(
            "stream_gaps",
            status,
            f"TCP reassembly gap rate is {percent:.6f}%",
            observed={"gaps": gaps, "packets": packets, "percent": round(percent, 8)},
            remediation=(None if status == HealthStatus.HEALTHY else "Investigate packet loss, checksums, and stream memory pressure."),
        )

    def _memcap_check(self, snapshot: SocketSnapshot | None) -> HealthCheck:
        if snapshot is None:
            return HealthCheck("suricata_memcap", HealthStatus.UNKNOWN, "Suricata memcap counters are unavailable")
        names = (
            "tcp.ssn_memcap_drop",
            "tcp.segment_memcap_drop",
            "flow.emerg_mode_entered",
            "flow.emerg_mode_over",
        )
        values = {name: _counter(snapshot.counters, name) for name in names}
        known = {name: value for name, value in values.items() if value is not None}
        if not known:
            return HealthCheck("suricata_memcap", HealthStatus.UNKNOWN, "Suricata memcap counters are unavailable")
        entered = known.get("flow.emerg_mode_entered", 0)
        exited = known.get("flow.emerg_mode_over", 0)
        drops = known.get("tcp.ssn_memcap_drop", 0) + known.get("tcp.segment_memcap_drop", 0)
        if entered > exited:
            status = HealthStatus.CRITICAL
            summary = "Suricata flow engine is in emergency mode"
        elif entered > 0 or drops > 0:
            status = HealthStatus.DEGRADED
            summary = "Suricata has recorded memcap pressure"
        else:
            status = HealthStatus.HEALTHY
            summary = "no Suricata memcap pressure is recorded"
        return HealthCheck(
            "suricata_memcap",
            status,
            summary,
            observed=known,
            remediation=(None if status == HealthStatus.HEALTHY else "Review flow/TCP memcaps and host memory capacity."),
        )

    def _nftables_check(self) -> HealthCheck:
        try:
            result = self.commands.run("nftables.meercata.list")
        except Exception as exc:
            return _unknown("nftables_hooks", "cannot inspect Meercata nftables table", exc)
        if not result.succeeded:
            return HealthCheck(
                "nftables_hooks",
                HealthStatus.CRITICAL,
                "Meercata nftables table is missing or unreadable",
                observed={"return_code": result.return_code},
                expected={"family": "inet", "table": "meercata", "queue": self.config.queue},
                remediation="Restore the last-known-good Meercata-owned nftables transaction.",
            )
        try:
            value = json.loads(result.stdout)
            hooks = _nft_queue_hooks(value)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return _unknown("nftables_hooks", "nftables returned invalid JSON", exc)
        matching = [hook for hook in hooks if hook["queue"] == self.config.queue]
        interfaces = sorted({iface for hook in matching for iface in hook["interfaces"]})
        bypass_ok = bool(matching) and all(hook["bypass"] for hook in matching)
        interface_ok = self.config.interface in interfaces
        if not matching or not interface_ok or not bypass_ok:
            return HealthCheck(
                "nftables_hooks",
                HealthStatus.CRITICAL,
                "NFQUEUE hooks do not match queue, interface, and fail-open policy",
                observed={"hooks": hooks},
                expected={"queue": self.config.queue, "interface": self.config.interface, "bypass": True},
                remediation="Recover the Meercata-owned nftables table from a verified transaction.",
            )
        packets = sum(hook["packets"] for hook in matching)
        return HealthCheck(
            "nftables_hooks",
            HealthStatus.HEALTHY,
            "Meercata NFQUEUE hooks match the configured fail-open policy",
            observed={"matching_rules": len(matching), "interfaces": interfaces, "packets": packets},
            expected={"queue": self.config.queue, "interface": self.config.interface, "bypass": True},
        )

    def _nfqueue_listener_check(self) -> HealthCheck:
        try:
            result = self.commands.run("nfqueue.listeners.read")
            if not result.succeeded or result.stdout_truncated:
                raise ValueError("NFQUEUE status command failed")
            queues = _parse_nfqueue_proc(result.stdout)
        except (OSError, ValueError) as exc:
            return _unknown("nfqueue_listener", "cannot inspect kernel NFQUEUE listeners", exc)
        queue = queues.get(self.config.queue)
        if queue is None:
            return HealthCheck(
                "nfqueue_listener",
                HealthStatus.CRITICAL,
                f"no userspace listener is attached to NFQUEUE {self.config.queue}",
                observed={"queues": sorted(queues)},
                expected=self.config.queue,
                remediation="Restore Suricata NFQ capture; fail-open bypass should preserve connectivity.",
            )
        drops = queue["queue_dropped"] + queue["user_dropped"]
        status = HealthStatus.DEGRADED if drops else HealthStatus.HEALTHY
        return HealthCheck(
            "nfqueue_listener",
            status,
            f"NFQUEUE {self.config.queue} listener is attached" + (f" with {drops} recorded drops" if drops else ""),
            observed=queue,
            expected={"queue": self.config.queue, "drops": 0},
            remediation=(None if not drops else "Investigate NFQUEUE capacity, latency, and userspace scheduling."),
        )

    def _disk_check(self) -> HealthCheck:
        try:
            usage = shutil.disk_usage(self.config.eve_path.parent)
        except OSError as exc:
            return _unknown("disk", "cannot inspect EVE filesystem capacity", exc)
        percent_free = usage.free / usage.total * 100 if usage.total else 0.0
        thresholds = self.config.thresholds
        if percent_free <= thresholds.disk_critical_percent_free:
            status = HealthStatus.CRITICAL
        elif percent_free <= thresholds.disk_warning_percent_free:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        return HealthCheck(
            "disk",
            status,
            f"EVE filesystem has {percent_free:.1f}% free",
            observed={"free_bytes": usage.free, "total_bytes": usage.total, "percent_free": round(percent_free, 3)},
            expected={"warning_above_percent": thresholds.disk_warning_percent_free, "critical_above_percent": thresholds.disk_critical_percent_free},
            remediation=(None if status == HealthStatus.HEALTHY else "Free space or expand the Suricata log filesystem before data loss."),
        )

    def _memory_check(self) -> HealthCheck:
        try:
            memory = _parse_meminfo((self.proc_root / "meminfo").read_text(encoding="utf-8"))
            total = memory["MemTotal"] * 1024
            available = memory["MemAvailable"] * 1024
        except (OSError, KeyError, ValueError) as exc:
            return _unknown("memory", "cannot inspect host memory", exc)
        percent_used = (total - available) / total * 100 if total else 100.0
        status = _high_is_bad(
            percent_used,
            self.config.thresholds.memory_warning_percent_used,
            self.config.thresholds.memory_critical_percent_used,
        )
        return HealthCheck(
            "memory",
            status,
            f"host memory usage is {percent_used:.1f}%",
            observed={"total_bytes": total, "available_bytes": available, "percent_used": round(percent_used, 3)},
            remediation=(None if status == HealthStatus.HEALTHY else "Reduce memory pressure or increase qualified capacity."),
        )

    def _process_resource_check(self, pids: tuple[int, ...]) -> HealthCheck:
        if not pids:
            return HealthCheck(
                "process_resources",
                HealthStatus.UNKNOWN,
                "Suricata process resource usage is unavailable",
            )
        try:
            rss_bytes = sum(_process_rss_bytes(self.proc_root, pid) for pid in pids)
            memory = _parse_meminfo((self.proc_root / "meminfo").read_text(encoding="utf-8"))
            total_memory = memory["MemTotal"] * 1024
            cpu_ticks = sum(_process_cpu_ticks(self.proc_root, pid) for pid in pids)
        except (OSError, KeyError, ValueError) as exc:
            return _unknown("process_resources", "cannot read Suricata process resources", exc)
        rss_percent = rss_bytes / total_memory * 100 if total_memory else 100.0
        now = self.monotonic_clock()
        cpu_percent: float | None = None
        previous = self._previous_cpu
        if previous is not None and previous[0] == pids and now > previous[2]:
            tick_delta = max(cpu_ticks - previous[1], 0)
            cpu_percent = tick_delta / os.sysconf("SC_CLK_TCK") / (now - previous[2]) * 100
        self._previous_cpu = (pids, cpu_ticks, now)
        rss_status = _high_is_bad(
            rss_percent,
            self.config.thresholds.process_rss_warning_percent,
            self.config.thresholds.process_rss_critical_percent,
        )
        cpu_status = HealthStatus.HEALTHY
        if cpu_percent is not None:
            cpu_status = _high_is_bad(
                cpu_percent,
                self.config.thresholds.process_cpu_warning_percent,
                self.config.thresholds.process_cpu_critical_percent,
            )
        status = _worst(rss_status, cpu_status)
        cpu_summary = "awaiting second sample" if cpu_percent is None else f"{cpu_percent:.1f}% CPU"
        return HealthCheck(
            "process_resources",
            status,
            f"Suricata uses {rss_percent:.2f}% RAM; {cpu_summary}",
            observed={"rss_bytes": rss_bytes, "rss_percent": round(rss_percent, 4), "cpu_percent": None if cpu_percent is None else round(cpu_percent, 4)},
            remediation=(None if status == HealthStatus.HEALTHY else "Profile Suricata load and tune or increase qualified resources."),
        )


def _live_commands(service_unit: str = "suricata.service") -> CommandRunner:
    if service_unit not in {"suricata.service", "meercata-suricata-ips.service"}:
        raise ValueError("Suricata systemd unit is not allowlisted")
    return CommandRunner(
        {
            "systemd.suricata.show": CommandDefinition.fixed(
                (
                    "/usr/bin/systemctl",
                    "show",
                    service_unit,
                    "--property=ActiveState,SubState,MainPID,ExecMainStatus,Result,Type",
                    "--no-pager",
                ),
                timeout_seconds=5,
            ),
            "nftables.meercata.list": CommandDefinition.fixed(
                ("/usr/sbin/nft", "-j", "list", "table", "inet", "meercata"),
                timeout_seconds=5,
            ),
            "nfqueue.listeners.read": CommandDefinition.fixed(
                ("/usr/bin/cat", "/proc/net/netfilter/nfnetlink_queue"),
                timeout_seconds=5,
            ),
        },
        max_output_bytes=2 * 1024 * 1024,
    )


def _parse_properties(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            result[key] = value
    return result


def _suricata_processes(proc_root: Path) -> set[int]:
    result: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if comm in {"suricata", "Suricata-Main"}:
            result.add(int(entry.name))
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()[:65536].split(b"\0", 1)[0]
        except OSError:
            continue
        executable = Path(os.fsdecode(cmdline)).name if cmdline else ""
        if executable == "suricata":
            result.add(int(entry.name))
    return result


def _socket_command_names(value: Any) -> set[str]:
    if isinstance(value, dict):
        value = value.get("commands")
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _socket_interfaces(value: Any) -> tuple[str, ...]:
    if isinstance(value, dict):
        value = value.get("ifaces")
    if not isinstance(value, list):
        raise ValueError("iface-list response is invalid")
    return tuple(str(item) for item in value)


def _socket_capture_name(config: HealthConfig) -> str:
    return f"NFQ#{config.queue}" if config.mode == "ips" else config.interface


def _canonical_capture_mode(value: str) -> str:
    normalized = value.upper().replace("-", "_")
    # Suricata 8 reports the --af-packet backend as AF_PACKET_DEV through
    # its Unix command socket.
    if normalized == "AF_PACKET_DEV":
        return "AF_PACKET"
    return normalized


def _counter(counters: Mapping[str, Any], dotted_name: str) -> int | None:
    value: Any = counters
    for component in dotted_name.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return _safe_int(value)


def _safe_int(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _high_is_bad(value: float, warning: float, critical: float) -> HealthStatus:
    if value >= critical:
        return HealthStatus.CRITICAL
    if value >= warning:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


def _worst(*statuses: HealthStatus) -> HealthStatus:
    order = {
        HealthStatus.HEALTHY: 0,
        HealthStatus.DEGRADED: 1,
        HealthStatus.UNKNOWN: 2,
        HealthStatus.CRITICAL: 3,
    }
    return max(statuses, key=order.__getitem__)


def _unknown(
    check_id: str,
    summary: str,
    error: BaseException,
    *,
    required: bool = True,
) -> HealthCheck:
    return HealthCheck(
        check_id,
        HealthStatus.UNKNOWN,
        summary,
        required=required,
        observed={"error_type": type(error).__name__},
    )


def _critical(
    check_id: str,
    summary: str,
    error: BaseException,
    *,
    remediation: str,
) -> HealthCheck:
    return HealthCheck(
        check_id,
        HealthStatus.CRITICAL,
        summary,
        observed={"error_type": type(error).__name__},
        remediation=remediation,
    )


def _parse_meminfo(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator:
            continue
        tokens = raw.strip().split()
        if not tokens:
            continue
        token = tokens[0]
        values[name] = int(token)
    return values


def _process_rss_bytes(proc_root: Path, pid: int) -> int:
    for line in (proc_root / str(pid) / "status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise ValueError(f"VmRSS unavailable for process {pid}")


def _process_cpu_ticks(proc_root: Path, pid: int) -> int:
    text = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
    closing = text.rfind(")")
    if closing < 0:
        raise ValueError("invalid process stat")
    fields = text[closing + 2 :].split()
    return int(fields[11]) + int(fields[12])


def _parse_nfqueue_proc(text: str) -> dict[int, dict[str, int]]:
    queues: dict[int, dict[str, int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        values = [int(field, 0) for field in fields[:8]]
        queues[values[0]] = {
            "queue": values[0],
            "peer_portid": values[1],
            "queue_total": values[2],
            "copy_mode": values[3],
            "copy_range": values[4],
            "queue_dropped": values[5],
            "user_dropped": values[6],
            "id_sequence": values[7],
        }
    return queues


def _nft_queue_hooks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("nftables"), list):
        raise ValueError("nft JSON root is invalid")
    hooks: list[dict[str, Any]] = []
    for item in value["nftables"]:
        if not isinstance(item, dict) or not isinstance(item.get("rule"), dict):
            continue
        rule = item["rule"]
        expressions = rule.get("expr", [])
        if not isinstance(expressions, list):
            continue
        interfaces: set[str] = set()
        packets = 0
        queue_entries: list[tuple[int, bool]] = []
        for expression in expressions:
            if not isinstance(expression, dict):
                continue
            match = expression.get("match")
            if isinstance(match, dict):
                left = match.get("left")
                right = match.get("right")
                if (
                    isinstance(left, dict)
                    and isinstance(left.get("meta"), dict)
                    and left["meta"].get("key") in {"iifname", "oifname"}
                    and isinstance(right, str)
                ):
                    interfaces.add(right)
            counter = expression.get("counter")
            if isinstance(counter, dict):
                packets += _safe_int(counter.get("packets")) or 0
            queue = expression.get("queue")
            if isinstance(queue, dict):
                number = _safe_int(queue.get("num"))
                flags = queue.get("flags", [])
                if isinstance(flags, str):
                    flags = [flags]
                if number is not None:
                    queue_entries.append((number, isinstance(flags, list) and "bypass" in flags))
        for number, bypass in queue_entries:
            hooks.append(
                {
                    "chain": rule.get("chain"),
                    "queue": number,
                    "bypass": bypass,
                    "interfaces": sorted(interfaces),
                    "packets": packets,
                }
            )
    return hooks
