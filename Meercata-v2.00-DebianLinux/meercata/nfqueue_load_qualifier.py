"""Bounded NFQUEUE load, pressure, and failure qualification."""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.audit import AuditLogger
from meercata.errors import QualificationError
from meercata.ips_config import IpsConfig
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.nfqueue_functional_qualifier import (
    ACCEPT_PORT,
    CLIENT_NAMESPACE,
    DROP_PORT,
    DROP_SID,
    IP,
    PAYLOAD_BYTES,
    PYTHON,
    QUEUE,
    SERVER_ADDRESS,
    SURICATA,
    SURICATA_CONFIG,
    _cleanup_topology,
    _configure_topology,
    _probe_http,
    _queue_counters,
    _read_listeners,
    _run_checked,
    _start_http_servers,
    _stop_process,
    _suricata_capability,
    _total_packets,
    _wait_for_http,
    _wait_for_listener,
    _wait_for_listener_loss,
    _write_payload,
    _write_rules,
)
from meercata.nftables_namespace_qualifier import (
    _best_effort_delete,
    _list_table,
    _passed,
    _require_disposable_network_namespace,
    _table_exists,
)
from meercata.nftables_policy import inspect_owned_table
from meercata.nftables_transaction_qualifier import _DirectActivator
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine

CONFIRMATION = "I_UNDERSTAND_THIS_RUNS_BOUNDED_NFQUEUE_LOAD_IN_DISPOSABLE_NAMESPACES"
NORMAL_SECONDS = 6.0
NORMAL_ACCEPT_WORKERS = 8
NORMAL_DROP_WORKERS = 4
LISTENER_LOSS_SECONDS = 6.0
LISTENER_LOSS_WORKERS = 8
LISTENER_LOSS_SUCCESS_FLOOR = 0.90
NORMAL_MAX_PENDING = 256
OVERLOAD_MAX_PENDING = 16
OVERLOAD_CONNECTIONS = 128
OVERLOAD_WORKERS = 64
MAX_RSS_BYTES = 768 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024

_MIXED_LOAD_CODE = """\
import concurrent.futures,hashlib,json,sys,time,urllib.request
accept_url,drop_url=sys.argv[1],sys.argv[2]
duration=float(sys.argv[3]); accept_workers=int(sys.argv[4]); drop_workers=int(sys.argv[5])
limit=int(sys.argv[6]); expected=sys.argv[7]
deadline=time.monotonic()+duration
def accept_worker(_):
    ok=failed=corrupt=total_bytes=0; durations=[]
    while time.monotonic()<deadline:
        started=time.monotonic()
        try:
            with urllib.request.urlopen(accept_url,timeout=2.0) as response:
                body=response.read(limit+1)
            elapsed=(time.monotonic()-started)*1000
            if len(body)==limit and hashlib.sha256(body).hexdigest()==expected:
                ok+=1; total_bytes+=len(body); durations.append(elapsed)
            else: corrupt+=1
        except Exception: failed+=1
    return {'accept_ok':ok,'accept_failed':failed,'accept_corrupt':corrupt,'bytes':total_bytes,'latencies_ms':durations}
def drop_worker(_):
    blocked=unexpected=0
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen(drop_url,timeout=0.35) as response: response.read(1)
            unexpected+=1
        except Exception: blocked+=1
    return {'drop_blocked':blocked,'drop_unexpected':unexpected}
tasks=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=accept_workers+drop_workers) as pool:
    tasks += [pool.submit(accept_worker,index) for index in range(accept_workers)]
    tasks += [pool.submit(drop_worker,index) for index in range(drop_workers)]
    values=[task.result() for task in tasks]
result={'accept_ok':0,'accept_failed':0,'accept_corrupt':0,'bytes':0,'drop_blocked':0,'drop_unexpected':0,'latencies_ms':[]}
for value in values:
    for key in ('accept_ok','accept_failed','accept_corrupt','bytes','drop_blocked','drop_unexpected'): result[key]+=value.get(key,0)
    result['latencies_ms']+=value.get('latencies_ms',[])
print(json.dumps(result,separators=(',',':'),sort_keys=True))
"""

_BURST_CODE = """\
import concurrent.futures,json,socket,sys,time
host=sys.argv[1]; port=int(sys.argv[2]); attempts=int(sys.argv[3]); workers=int(sys.argv[4]); timeout=float(sys.argv[5])
def connect(_):
    started=time.monotonic()
    try:
        with socket.create_connection((host,port),timeout=timeout): return ('connected',(time.monotonic()-started)*1000)
    except Exception: return ('failed',(time.monotonic()-started)*1000)
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool: values=list(pool.map(connect,range(attempts)))
print(json.dumps({'attempts':attempts,'connected':sum(1 for state,_ in values if state=='connected'),'failed':sum(1 for state,_ in values if state=='failed'),'duration_max_ms':round(max(value for _,value in values),3)},separators=(',',':'),sort_keys=True))
"""


class NfqueueLoadQualifier:
    """Exercise bounded mixed load, crash transition, and queue saturation."""

    def __init__(self, *, confirmation: str, image_digest: str) -> None:
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_network_namespace(
            self.confirmation,
            self.image_digest,
            expected_confirmation=CONFIRMATION,
        )
        platform.update(_require_load_runtime())
        checks: list[dict[str, Any]] = [_passed("platform.bounded", platform)]
        processes: list[subprocess.Popen[bytes]] = []
        forwarding_before: str | None = None

        with tempfile.TemporaryDirectory(prefix="meercata-nfq-load-") as temporary:
            root = Path(temporary)
            paths = MeercataPaths.isolated(root / "state")
            server_root = root / "server"
            server_root.mkdir(mode=0o700)
            payload = _write_payload(server_root / "payload.bin")
            rules = _write_rules(root / "qualification.rules")
            service: PrivilegedNftablesService | None = None
            suricata: subprocess.Popen[bytes] | None = None
            try:
                forwarding_before = _configure_topology()
                processes.extend(_start_http_servers(server_root))
                baseline = _wait_for_http(ACCEPT_PORT, PAYLOAD_BYTES, 10.0)
                if baseline["sha256"] != payload["sha256"]:
                    raise QualificationError("routed load baseline payload is invalid")
                checks.append(
                    _passed(
                        "topology.routed",
                        {
                            "baseline_bytes": baseline["bytes"],
                            "baseline_sha256": baseline["sha256"],
                            "client_namespace": CLIENT_NAMESPACE,
                            "server_address": SERVER_ADDRESS,
                        },
                    )
                )

                normal_log = root / "suricata-normal"
                normal_log.mkdir(mode=0o700)
                capability = _suricata_capability(rules, normal_log)
                checks.append(_passed("suricata.nfq-capability", capability))

                service, transaction = _activate_policy(paths)
                checks.append(_passed("policy.transaction-commit", transaction))

                suricata = _start_suricata_load(
                    rules,
                    normal_log,
                    max_pending=NORMAL_MAX_PENDING,
                )
                processes.append(suricata)
                listener_before = _wait_for_listener(QUEUE, 20.0, process=suricata)
                counters_before = _queue_counters(_list_table("meercata"))

                normal = _run_profile(
                    _MIXED_LOAD_CODE,
                    (
                        f"http://{SERVER_ADDRESS}:{ACCEPT_PORT}/payload.bin",
                        f"http://{SERVER_ADDRESS}:{DROP_PORT}/payload.bin",
                        str(NORMAL_SECONDS),
                        str(NORMAL_ACCEPT_WORKERS),
                        str(NORMAL_DROP_WORKERS),
                        str(PAYLOAD_BYTES),
                        payload["sha256"],
                    ),
                    suricata=suricata,
                    timeout=NORMAL_SECONDS + 12.0,
                )
                _require_mixed_correctness(normal["result"])
                counters_after = _queue_counters(_list_table("meercata"))
                if _total_packets(counters_after) <= _total_packets(counters_before):
                    raise QualificationError("normal-load nftables counters did not progress")
                checks.append(
                    _passed(
                        "load.mixed-correctness",
                        _mixed_details(normal["result"], normal["elapsed_seconds"]),
                    )
                )

                queue_details = _normal_queue_details(
                    listener_before,
                    normal["listener_samples"],
                    counters_before,
                    counters_after,
                )
                checks.append(_passed("load.queue-integrity", queue_details))

                resources = normal["resources"]
                if resources["rss_max_bytes"] > MAX_RSS_BYTES:
                    raise QualificationError("Suricata exceeded the bounded RSS ceiling")
                checks.append(_passed("load.resources", resources))

                stats = _wait_for_stats(normal_log / "eve.json", 5.0)
                _require_normal_stats(stats)
                checks.append(_passed("load.suricata-stats", stats))

                loss_profile = _start_profile(
                    _MIXED_LOAD_CODE,
                    (
                        f"http://{SERVER_ADDRESS}:{ACCEPT_PORT}/payload.bin",
                        f"http://{SERVER_ADDRESS}:{DROP_PORT}/payload.bin",
                        str(LISTENER_LOSS_SECONDS),
                        str(LISTENER_LOSS_WORKERS),
                        "0",
                        str(PAYLOAD_BYTES),
                        payload["sha256"],
                    ),
                )
                time.sleep(1.0)
                _kill_process(suricata)
                processes.remove(suricata)
                suricata = None
                _wait_for_listener_loss(QUEUE, 10.0)
                loss = _finish_profile(loss_profile, LISTENER_LOSS_SECONDS + 10.0)
                loss_details = _listener_loss_details(loss, payload)
                recovery = _wait_for_http(DROP_PORT, PAYLOAD_BYTES, 10.0)
                if recovery["sha256"] != payload["sha256"]:
                    raise QualificationError("listener-loss recovery payload is invalid")
                loss_details.update(
                    {
                        "listener_present": False,
                        "recovery_port": DROP_PORT,
                        "recovery_duration_ms": recovery["duration_ms"],
                    }
                )
                checks.append(_passed("failure.listener-loss-under-load", loss_details))

                overload_log = root / "suricata-overload"
                overload_log.mkdir(mode=0o700)
                suricata = _start_suricata_load(
                    rules,
                    overload_log,
                    max_pending=OVERLOAD_MAX_PENDING,
                )
                processes.append(suricata)
                overload_listener = _wait_for_listener(QUEUE, 20.0, process=suricata)
                blocked = _probe_http(DROP_PORT, PAYLOAD_BYTES, 1.0)
                if blocked["ok"] is not False:
                    raise QualificationError("drop verdict did not recover before overload injection")

                os.killpg(suricata.pid, signal.SIGSTOP)
                burst = _start_profile(
                    _BURST_CODE,
                    (
                        SERVER_ADDRESS,
                        str(ACCEPT_PORT),
                        str(OVERLOAD_CONNECTIONS),
                        str(OVERLOAD_WORKERS),
                        "1.0",
                    ),
                )
                pressure = _wait_for_queue_pressure(overload_listener, 4.0)
                bypass = service.emergency_bypass(
                    "queue-overload", "INC-DEV20-QUALIFICATION"
                )
                if bypass.get("removed") is not True or _table_exists("meercata"):
                    raise QualificationError("queue-overload emergency bypass did not remove policy")
                os.killpg(suricata.pid, signal.SIGCONT)
                burst_result = _finish_profile(burst, 8.0)
                restored = _wait_for_http(ACCEPT_PORT, PAYLOAD_BYTES, 10.0)
                if restored["sha256"] != payload["sha256"]:
                    raise QualificationError("overload bypass recovery payload is invalid")
                checks.append(
                    _passed(
                        "overload.detected-and-bypassed",
                        {
                            "max_pending_packets": OVERLOAD_MAX_PENDING,
                            "burst_attempts": burst_result["attempts"],
                            "burst_connected": burst_result["connected"],
                            "burst_failed": burst_result["failed"],
                            "queue_total_peak": pressure["queue_total"],
                            "queue_dropped_delta": pressure["queue_dropped_delta"],
                            "user_dropped_delta": pressure["user_dropped_delta"],
                            "incident_id": bypass["incident_id"],
                            "bypass_removed_policy": bypass["removed"],
                            "recovery_bytes": restored["bytes"],
                            "recovery_sha256": restored["sha256"],
                        },
                    )
                )
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
                    _stop_process(process)
                if service is not None and _table_exists("meercata"):
                    try:
                        service.emergency_bypass(
                            "queue-overload", "INC-DEV20-CLEANUP"
                        )
                    except Exception:
                        _best_effort_delete(root, "meercata")
                else:
                    _best_effort_delete(root, "meercata")
                _cleanup_topology(forwarding_before)

        if len(checks) != 10:
            raise QualificationError("NFQUEUE load qualification check count is invalid")
        return {
            "schema_version": 1,
            "status": "nfqueue-load-qualified",
            "project_version": __version__,
            "profile": {
                "normal_seconds": NORMAL_SECONDS,
                "normal_accept_workers": NORMAL_ACCEPT_WORKERS,
                "normal_drop_workers": NORMAL_DROP_WORKERS,
                "normal_max_pending_packets": NORMAL_MAX_PENDING,
                "listener_loss_seconds": LISTENER_LOSS_SECONDS,
                "listener_loss_success_floor": LISTENER_LOSS_SUCCESS_FLOOR,
                "overload_max_pending_packets": OVERLOAD_MAX_PENDING,
                "overload_connections": OVERLOAD_CONNECTIONS,
                "overload_workers": OVERLOAD_WORKERS,
            },
            "checks": checks,
            "limitations": [
                "results describe one bounded disposable-container run, not deployable production capacity",
                "synthetic HTTP traffic does not represent a deployment protocol, packet-size, or rule-mix distribution",
                "intentional queue saturation validates detection and emergency bypass, not lossless overload handling",
                "multi-queue scaling, NIC behavior, 24-72 hour soak, installed IPS systemd recovery, and reboot remain unqualified",
            ],
        }


def _require_load_runtime() -> dict[str, Any]:
    from meercata.nfqueue_functional_qualifier import _require_runtime

    runtime = _require_runtime()
    memory = _read_cgroup_integer(Path("/sys/fs/cgroup/memory.max"), "memory")
    pids = _read_cgroup_integer(Path("/sys/fs/cgroup/pids.max"), "pids")
    try:
        cpu_fields = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        quota = int(cpu_fields[0])
        period = int(cpu_fields[1])
    except (OSError, ValueError, IndexError) as exc:
        raise QualificationError("bounded CPU cgroup limit is unavailable") from exc
    cpu_limit = quota / period
    if not 512 * 1024 * 1024 <= memory <= 2 * 1024 * 1024 * 1024:
        raise QualificationError("qualification memory limit must be between 512 MiB and 2 GiB")
    if not 128 <= pids <= 1024:
        raise QualificationError("qualification PID limit must be between 128 and 1024")
    if not 1.0 <= cpu_limit <= 4.0:
        raise QualificationError("qualification CPU limit must be between 1 and 4 CPUs")
    runtime["cgroup_limits"] = {
        "memory_bytes": memory,
        "pids": pids,
        "cpu_cores": round(cpu_limit, 3),
    }
    return runtime


def _read_cgroup_integer(path: Path, label: str) -> int:
    try:
        value = path.read_text().strip()
        parsed = int(value)
    except (OSError, ValueError) as exc:
        raise QualificationError(f"bounded {label} cgroup limit is unavailable") from exc
    if parsed <= 0:
        raise QualificationError(f"bounded {label} cgroup limit is invalid")
    return parsed


def _activate_policy(
    paths: MeercataPaths,
) -> tuple[PrivilegedNftablesService, dict[str, Any]]:
    config = IpsConfig("lan0", QUEUE)
    service = PrivilegedNftablesService(paths, config, require_root=False)
    store = StateStore(paths)
    transaction = IpsNftablesWorkflow(
        config,
        TransactionEngine(
            store=store,
            audit=AuditLogger(paths.audit_file),
            lock=ControllerLock(paths.controller_lock_file),
        ),
        _DirectActivator(service),
    ).activate_policy()
    observed = inspect_owned_table(_list_table("meercata"))
    if (
        transaction.state != TransactionState.COMMITTED
        or observed.transaction_id != transaction.transaction_id
        or observed.interface != "lan0"
        or observed.queue != QUEUE
        or observed.fail_open is not True
    ):
        raise QualificationError("load policy transaction did not commit exactly")
    return service, {
        "transaction_id": transaction.transaction_id,
        "semantic_sha256": observed.semantic_sha256,
        "interface": observed.interface,
        "queue": observed.queue,
        "fail_open": observed.fail_open,
    }


def _start_suricata_load(
    rules: Path,
    log_root: Path,
    *,
    max_pending: int,
) -> subprocess.Popen[bytes]:
    if max_pending not in {NORMAL_MAX_PENDING, OVERLOAD_MAX_PENDING}:
        raise QualificationError("Suricata pending-packet profile is invalid")
    _run_checked(
        (
            str(SURICATA), "-T", "-c", str(SURICATA_CONFIG), "-S", str(rules),
            "-l", str(log_root), "--set", f"max-pending-packets={max_pending}",
            "--set", "stats.interval=1", "--set", "unix-command.enabled=no",
            "--init-errors-fatal",
        ),
        "Suricata load configuration test",
        timeout=30,
    )
    return subprocess.Popen(
        (
            str(SURICATA), "-c", str(SURICATA_CONFIG), "-S", str(rules),
            "-q", str(QUEUE), "-l", str(log_root),
            "--pidfile", str(log_root / "suricata.pid"),
            "--set", f"max-pending-packets={max_pending}",
            "--set", "stats.interval=1", "--set", "unix-command.enabled=no",
            "--init-errors-fatal",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _profile_argv(code: str, arguments: tuple[str, ...]) -> tuple[str, ...]:
    if code not in {_MIXED_LOAD_CODE, _BURST_CODE}:
        raise QualificationError("load profile code is not allowlisted")
    return (
        str(IP), "netns", "exec", CLIENT_NAMESPACE,
        str(PYTHON), "-c", code, *arguments,
    )


def _start_profile(code: str, arguments: tuple[str, ...]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        _profile_argv(code, arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _finish_profile(process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _stop_process(process)
        raise QualificationError("bounded load profile timed out") from exc
    if (
        process.returncode != 0
        or len(stdout) > MAX_REPORT_BYTES
        or len(stderr) > MAX_REPORT_BYTES
    ):
        raise QualificationError("bounded load profile failed")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise QualificationError("bounded load profile returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise QualificationError("bounded load profile result is not an object")
    return value


def _run_profile(
    code: str,
    arguments: tuple[str, ...],
    *,
    suricata: subprocess.Popen[bytes],
    timeout: float,
) -> dict[str, Any]:
    process = _start_profile(code, arguments)
    started = time.monotonic()
    listeners: list[dict[str, int]] = []
    resources: list[dict[str, int]] = []
    try:
        while process.poll() is None:
            if suricata.poll() is not None:
                raise QualificationError("Suricata exited during bounded normal load")
            listener = next(
                (item for item in _read_listeners() if item["queue"] == QUEUE),
                None,
            )
            if listener is None:
                raise QualificationError("NFQUEUE listener disappeared during normal load")
            listeners.append(listener)
            resources.append(_process_resources(suricata.pid))
            if time.monotonic() - started > timeout:
                raise QualificationError("bounded normal load exceeded its deadline")
            time.sleep(0.1)
        result = _finish_profile(process, 1.0)
    except Exception:
        _stop_process(process)
        raise
    if len(listeners) < 2 or len(resources) < 2:
        raise QualificationError("bounded load produced insufficient samples")
    elapsed = time.monotonic() - started
    return {
        "result": result,
        "listener_samples": listeners,
        "resources": _resource_summary(resources, elapsed),
        "elapsed_seconds": elapsed,
    }


def _process_resources(pid: int) -> dict[str, int]:
    if pid <= 1:
        raise QualificationError("Suricata PID is invalid for resource sampling")
    try:
        status = Path(f"/proc/{pid}/status").read_text().splitlines()
        stat_fields = Path(f"/proc/{pid}/stat").read_text().split()
        rss_line = next(line for line in status if line.startswith("VmRSS:"))
        rss_bytes = int(rss_line.split()[1]) * 1024
        cpu_ticks = int(stat_fields[13]) + int(stat_fields[14])
        threads_line = next(line for line in status if line.startswith("Threads:"))
        threads = int(threads_line.split()[1])
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        raise QualificationError("cannot sample Suricata process resources") from exc
    if rss_bytes <= 0 or cpu_ticks < 0 or threads <= 0:
        raise QualificationError("Suricata process resource sample is invalid")
    return {"rss_bytes": rss_bytes, "cpu_ticks": cpu_ticks, "threads": threads}


def _resource_summary(samples: list[dict[str, int]], elapsed: float) -> dict[str, Any]:
    if elapsed <= 0:
        raise QualificationError("resource sample duration is invalid")
    try:
        clock_ticks = int(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError) as exc:
        raise QualificationError("system clock tick rate is unavailable") from exc
    cpu_delta = samples[-1]["cpu_ticks"] - samples[0]["cpu_ticks"]
    cpu_percent_one_core = cpu_delta / clock_ticks / elapsed * 100
    if cpu_delta < 0 or not math.isfinite(cpu_percent_one_core):
        raise QualificationError("Suricata CPU sample is invalid")
    return {
        "sample_count": len(samples),
        "duration_seconds": round(elapsed, 3),
        "rss_min_bytes": min(item["rss_bytes"] for item in samples),
        "rss_max_bytes": max(item["rss_bytes"] for item in samples),
        "rss_ceiling_bytes": MAX_RSS_BYTES,
        "threads_max": max(item["threads"] for item in samples),
        "cpu_percent_one_core": round(cpu_percent_one_core, 3),
    }


def _require_mixed_correctness(value: Mapping[str, Any]) -> None:
    integers = (
        "accept_ok", "accept_failed", "accept_corrupt", "bytes",
        "drop_blocked", "drop_unexpected",
    )
    if any(type(value.get(key)) is not int or value[key] < 0 for key in integers):
        raise QualificationError("mixed-load counters are invalid")
    latencies = value.get("latencies_ms")
    if (
        not isinstance(latencies, list)
        or len(latencies) != value["accept_ok"]
        or any(not isinstance(item, (int, float)) or item < 0 for item in latencies)
    ):
        raise QualificationError("mixed-load latency samples are invalid")
    if (
        value["accept_ok"] <= 0
        or value["drop_blocked"] <= 0
        or value["accept_failed"] != 0
        or value["accept_corrupt"] != 0
        or value["drop_unexpected"] != 0
        or value["bytes"] != value["accept_ok"] * PAYLOAD_BYTES
    ):
        raise QualificationError("mixed-load accept/drop correctness failed")


def _mixed_details(value: Mapping[str, Any], duration: float) -> dict[str, Any]:
    if duration <= 0 or not math.isfinite(duration):
        raise QualificationError("mixed-load duration is invalid")
    latencies = [float(item) for item in value["latencies_ms"]]
    throughput = value["bytes"] * 8 / duration / 1_000_000
    return {
        "duration_seconds": round(duration, 3),
        "accept_successes": value["accept_ok"],
        "accept_failures": value["accept_failed"],
        "accept_corrupt": value["accept_corrupt"],
        "accepted_bytes": value["bytes"],
        "drop_blocked": value["drop_blocked"],
        "drop_unexpected_accepts": value["drop_unexpected"],
        "latency_median_ms": round(statistics.median(latencies), 3),
        "latency_p95_ms": round(_percentile(latencies, 0.95), 3),
        "goodput_mbps": round(throughput, 3),
        "classification": "bounded-synthetic-load-not-capacity",
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values or not 0 < fraction <= 1:
        raise QualificationError("percentile input is invalid")
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def _normal_queue_details(
    initial: Mapping[str, int],
    samples: list[Mapping[str, int]],
    counters_before: Mapping[str, Mapping[str, int]],
    counters_after: Mapping[str, Mapping[str, int]],
) -> dict[str, Any]:
    queue_drop_delta = max(item["queue_dropped"] for item in samples) - initial["queue_dropped"]
    user_drop_delta = max(item["user_dropped"] for item in samples) - initial["user_dropped"]
    if queue_drop_delta != 0 or user_drop_delta != 0:
        raise QualificationError("normal bounded load caused an NFQUEUE transport drop")
    return {
        "samples": len(samples),
        "queue_total_peak": max(item["queue_total"] for item in samples),
        "queue_dropped_delta": queue_drop_delta,
        "user_dropped_delta": user_drop_delta,
        "nft_packets_before": _total_packets(dict(counters_before)),
        "nft_packets_after": _total_packets(dict(counters_after)),
    }


def _wait_for_stats(path: Path, wait_seconds: float) -> dict[str, int]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        events = _read_complete_json_lines(path)
        stats_events = [item["stats"] for item in events if isinstance(item.get("stats"), dict)]
        if stats_events:
            latest = stats_events[-1]
            return {
                "ips_accepted": _nested_counter(latest, "ips", "accepted"),
                "ips_blocked": _nested_counter(latest, "ips", "blocked"),
                "ips_nfq_error": _nested_counter(latest, "ips", "drop_reason", "nfq_error"),
                "memcap_pressure_max": _nested_counter(latest, "memcap", "pressure_max"),
                "flow_emergency_entered": _nested_counter(latest, "flow", "emerg_mode_entered"),
                "tcp_reassembly_gap": _nested_counter(latest, "tcp", "reassembly_gap"),
                "tcp_session_memcap_drop": _nested_counter(latest, "tcp", "ssn_memcap_drop"),
                "tcp_segment_memcap_drop": _nested_counter(latest, "tcp", "segment_memcap_drop"),
                "alert_queue_overflow": _nested_counter(latest, "detect", "alert_queue_overflow"),
            }
        time.sleep(0.1)
    raise QualificationError("Suricata EVE stats did not become available")


def _read_complete_json_lines(path: Path) -> list[dict[str, Any]]:
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise QualificationError("cannot read Suricata EVE load output") from exc
    lines = content.splitlines()
    if content and not content.endswith("\n"):
        lines = lines[:-1]
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise QualificationError("Suricata EVE load output contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise QualificationError("Suricata EVE load record is not an object")
        events.append(value)
    return events


def _nested_counter(value: Mapping[str, Any], *path: str) -> int:
    current: Any = value
    for name in path:
        if not isinstance(current, Mapping):
            return 0
        current = current.get(name, 0)
    if type(current) is not int or current < 0:
        raise QualificationError("Suricata EVE stats counter is invalid")
    return current


def _require_normal_stats(stats: Mapping[str, int]) -> None:
    if stats["ips_accepted"] <= 0 or stats["ips_blocked"] <= 0:
        raise QualificationError("Suricata IPS stats did not record accept and block verdicts")
    zero_required = (
        "ips_nfq_error",
        "flow_emergency_entered",
        "tcp_reassembly_gap",
        "tcp_session_memcap_drop",
        "tcp_segment_memcap_drop",
        "alert_queue_overflow",
    )
    if any(stats[name] != 0 for name in zero_required):
        raise QualificationError("Suricata reported a forbidden normal-load degradation counter")


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        raise QualificationError("Suricata exited before listener-loss injection")
    try:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired) as exc:
        raise QualificationError("could not inject bounded Suricata listener loss") from exc


def _listener_loss_details(value: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    integers = ("accept_ok", "accept_failed", "accept_corrupt", "bytes")
    if any(type(value.get(key)) is not int or value[key] < 0 for key in integers):
        raise QualificationError("listener-loss load counters are invalid")
    total = value["accept_ok"] + value["accept_failed"] + value["accept_corrupt"]
    ratio = value["accept_ok"] / total if total else 0.0
    if (
        value["accept_ok"] <= 0
        or value["accept_corrupt"] != 0
        or value["bytes"] != value["accept_ok"] * payload["bytes"]
        or ratio < LISTENER_LOSS_SUCCESS_FLOOR
    ):
        raise QualificationError("listener-loss-under-load exceeded its bounded disruption floor")
    return {
        "injection": "SIGKILL",
        "attempts": total,
        "successes": value["accept_ok"],
        "failures": value["accept_failed"],
        "corrupt": value["accept_corrupt"],
        "success_ratio": round(ratio, 6),
        "required_success_floor": LISTENER_LOSS_SUCCESS_FLOOR,
        "accepted_bytes": value["bytes"],
    }


def _wait_for_queue_pressure(
    initial: Mapping[str, int], wait_seconds: float
) -> dict[str, int]:
    deadline = time.monotonic() + wait_seconds
    peak_total = initial["queue_total"]
    while time.monotonic() < deadline:
        current = next(
            (item for item in _read_listeners() if item["queue"] == QUEUE),
            None,
        )
        if current is None:
            raise QualificationError("NFQUEUE listener disappeared during overload injection")
        peak_total = max(peak_total, current["queue_total"])
        queue_delta = current["queue_dropped"] - initial["queue_dropped"]
        user_delta = current["user_dropped"] - initial["user_dropped"]
        if queue_delta > 0 or user_delta > 0:
            return {
                "queue_total": peak_total,
                "queue_dropped_delta": queue_delta,
                "user_dropped_delta": user_delta,
            }
        time.sleep(0.02)
    raise QualificationError("bounded overload did not produce observable NFQUEUE pressure")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m meercata.nfqueue_load_qualifier",
        description="Qualify bounded NFQUEUE load, pressure, and fail-open recovery",
    )
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        report = NfqueueLoadQualifier(
            confirmation=arguments.confirm,
            image_digest=arguments.image_digest,
        ).qualify()
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if arguments.output is not None:
            arguments.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="", file=stdout)
        return 0
    except QualificationError as exc:
        print(f"meercata-nfqueue-load-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
