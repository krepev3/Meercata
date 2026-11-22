"""Live NFQUEUE packet-verdict qualification in disposable network namespaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence, TextIO

from meercata import __version__
from meercata.audit import AuditLogger
from meercata.container_qualifier import DEBIAN_13_IMAGE_DIGEST
from meercata.errors import QualificationError
from meercata.ips_config import IpsConfig
from meercata.ips_lifecycle import IpsNftablesWorkflow
from meercata.locking import ControllerLock
from meercata.models import TransactionState
from meercata.nftables_namespace_qualifier import (
    _best_effort_delete,
    _list_table,
    _passed,
    _require_disposable_network_namespace,
)
from meercata.nftables_policy import inspect_owned_table
from meercata.nftables_transaction_qualifier import _DirectActivator
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import PrivilegedNftablesService
from meercata.state_store import StateStore
from meercata.transaction import TransactionEngine

CONFIRMATION = "I_UNDERSTAND_THIS_RUNS_LIVE_NFQUEUE_IN_DISPOSABLE_NETWORK_NAMESPACES"
IP = Path("/usr/bin/ip")
NFT = Path("/usr/sbin/nft")
PYTHON = Path("/usr/bin/python3")
SURICATA = Path("/usr/bin/suricata")
SURICATA_CONFIG = Path("/etc/suricata/suricata.yaml")
NFQUEUE_STATUS = Path("/proc/net/netfilter/nfnetlink_queue")
QUEUE = 42
DROP_SID = 9_900_019
CLIENT_NAMESPACE = "meercata-client"
SERVER_NAMESPACE = "meercata-server"
CLIENT_ADDRESS = "10.77.0.2"
SERVER_ADDRESS = "10.88.0.2"
ACCEPT_PORT = 8080
DROP_PORT = 9090
PAYLOAD_BYTES = 1024 * 1024
LATENCY_SAMPLES = 5

_PROBE_CODE = """\
import hashlib,json,sys,time,urllib.request
started=time.monotonic()
try:
    with urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2])) as response:
        body=response.read(int(sys.argv[3])+1)
    if len(body)>int(sys.argv[3]):
        raise RuntimeError('response-too-large')
    print(json.dumps({'ok':True,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'duration_ms':round((time.monotonic()-started)*1000,3)},sort_keys=True))
except Exception as exc:
    print(json.dumps({'ok':False,'error_type':type(exc).__name__,'duration_ms':round((time.monotonic()-started)*1000,3)},sort_keys=True))
    raise SystemExit(7)
"""


class NfqueueFunctionalQualifier:
    """Exercise the real dev18 policy, Suricata NFQ, and routed packets."""

    def __init__(self, *, confirmation: str, image_digest: str) -> None:
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_network_namespace(
            self.confirmation,
            self.image_digest,
            expected_confirmation=CONFIRMATION,
        )
        platform.update(_require_runtime())
        checks: list[dict[str, Any]] = [_passed("platform.namespace", platform)]
        processes: list[subprocess.Popen[bytes]] = []
        forwarding_before: str | None = None

        with tempfile.TemporaryDirectory(prefix="meercata-nfq-functional-") as temporary:
            root = Path(temporary)
            paths = MeercataPaths.isolated(root / "state")
            server_root = root / "server"
            log_root = root / "suricata"
            server_root.mkdir(mode=0o700)
            log_root.mkdir(mode=0o700)
            payload = _write_payload(server_root / "payload.bin")
            rules = _write_rules(root / "qualification.rules")
            service: PrivilegedNftablesService | None = None
            suricata: subprocess.Popen[bytes] | None = None
            try:
                forwarding_before = _configure_topology()
                processes.extend(_start_http_servers(server_root))
                baseline = _wait_for_http(ACCEPT_PORT, PAYLOAD_BYTES, 10.0)
                checks.append(
                    _passed(
                        "topology.routed",
                        {
                            "client": f"{CLIENT_ADDRESS}/24",
                            "gateway_interfaces": ["lan0", "wan0"],
                            "server": f"{SERVER_ADDRESS}/24",
                            "baseline_bytes": baseline["bytes"],
                            "baseline_sha256": baseline["sha256"],
                        },
                    )
                )

                capability = _suricata_capability(rules, log_root)
                checks.append(_passed("suricata.nfq-capability", capability))

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
                    raise QualificationError("live NFQUEUE policy transaction did not commit exactly")
                checks.append(
                    _passed(
                        "policy.transaction-commit",
                        {
                            "transaction_id": transaction.transaction_id,
                            "semantic_sha256": observed.semantic_sha256,
                            "interface": observed.interface,
                            "queue": observed.queue,
                            "fail_open": observed.fail_open,
                        },
                    )
                )

                counters_before = _queue_counters(_list_table("meercata"))
                suricata = _start_suricata(rules, log_root)
                processes.append(suricata)
                listener = _wait_for_listener(QUEUE, 20.0, process=suricata)
                checks.append(_passed("nfqueue.listener", listener))

                accepted = _wait_for_http(ACCEPT_PORT, PAYLOAD_BYTES, 10.0)
                if accepted["sha256"] != payload["sha256"]:
                    raise QualificationError("accepted NFQUEUE payload digest is incorrect")
                counters_after_accept = _wait_for_counter_progress(counters_before, 5.0)
                checks.append(
                    _passed(
                        "verdict.accept",
                        {
                            "port": ACCEPT_PORT,
                            "bytes": accepted["bytes"],
                            "sha256": accepted["sha256"],
                            "duration_ms": accepted["duration_ms"],
                            "queued_packets_before": _total_packets(counters_before),
                            "queued_packets_after": _total_packets(counters_after_accept),
                        },
                    )
                )

                blocked = _probe_http(DROP_PORT, PAYLOAD_BYTES, 2.0)
                if blocked["ok"] is not False:
                    raise QualificationError("Suricata drop rule did not block the qualification flow")
                alert = _wait_for_drop_alert(log_root / "eve.json", DROP_SID, 10.0)
                counters_after_drop = _wait_for_counter_progress(counters_after_accept, 5.0)
                checks.append(
                    _passed(
                        "verdict.drop",
                        {
                            "port": DROP_PORT,
                            "sid": DROP_SID,
                            "alert_action": alert["action"],
                            "probe_error_type": blocked["error_type"],
                            "probe_duration_ms": blocked["duration_ms"],
                            "queued_packets_before": _total_packets(counters_after_accept),
                            "queued_packets_after": _total_packets(counters_after_drop),
                        },
                    )
                )

                sample = _bounded_sample(payload)
                checks.append(_passed("performance.bounded-sample", sample))

                _stop_process(suricata)
                processes.remove(suricata)
                suricata = None
                _wait_for_listener_loss(QUEUE, 10.0)
                fail_open = _wait_for_http(DROP_PORT, PAYLOAD_BYTES, 10.0)
                if fail_open["sha256"] != payload["sha256"]:
                    raise QualificationError("fail-open payload digest is incorrect")
                counters_after_loss = _wait_for_counter_progress(counters_after_drop, 5.0)
                checks.append(
                    _passed(
                        "fail-open.listener-loss",
                        {
                            "listener_present": False,
                            "formerly_blocked_port": DROP_PORT,
                            "bytes": fail_open["bytes"],
                            "sha256": fail_open["sha256"],
                            "duration_ms": fail_open["duration_ms"],
                            "queued_packets_before": _total_packets(counters_after_drop),
                            "queued_packets_after": _total_packets(counters_after_loss),
                        },
                    )
                )
            finally:
                for process in reversed(processes):
                    _stop_process(process)
                if service is not None:
                    try:
                        service.emergency_bypass("listener-loss", "INC-DEV19-QUALIFICATION")
                    except Exception:
                        _best_effort_delete(root, "meercata")
                else:
                    _best_effort_delete(root, "meercata")
                _cleanup_topology(forwarding_before)

        if len(checks) != 9:
            raise QualificationError("NFQUEUE functional qualification check count is invalid")
        return {
            "schema_version": 1,
            "status": "nfqueue-functional-qualified",
            "project_version": __version__,
            "platform": platform,
            "topology": {
                "traffic_path": "client -> Meercata gateway -> server",
                "client_namespace": CLIENT_NAMESPACE,
                "server_namespace": SERVER_NAMESPACE,
                "gateway_interface": "lan0",
                "queue": QUEUE,
                "fail_policy": "open",
            },
            "checks": checks,
            "limitations": [
                "the run mutated networking and nftables only inside a disposable container",
                "the bounded transfer and latency sample is functional evidence, not a production capacity benchmark",
                "NFQUEUE overload, sustained soak, packet loss under load, multi-queue scaling, and resource ceilings remain unqualified",
                "public IPS CLI activation, systemd lifecycle, crash, reboot, and physical inline deployment remain gated",
            ],
        }


def _require_runtime() -> dict[str, Any]:
    for path in (IP, NFT, PYTHON, SURICATA, SURICATA_CONFIG):
        if not path.is_file() or (path != SURICATA_CONFIG and not os.access(path, os.X_OK)):
            raise QualificationError(f"required qualification runtime is unavailable: {path}")
    capabilities = _effective_capabilities(Path("/proc/self/status"))
    if not {"CAP_NET_ADMIN", "CAP_SYS_ADMIN"} <= set(capabilities):
        raise QualificationError("qualification requires CAP_NET_ADMIN and CAP_SYS_ADMIN")
    if not NFQUEUE_STATUS.is_file():
        raise QualificationError(
            "kernel nfnetlink_queue backend must be active before qualification"
        )
    return {
        "capabilities": capabilities,
        "kernel_nfqueue_backend": "available-before-run",
        "isolation_profile": "network-none with IPv4 forwarding, NET_ADMIN, SYS_ADMIN, seccomp-unconfined, apparmor-unconfined",
    }


def _effective_capabilities(path: Path) -> list[str]:
    try:
        line = next(line for line in path.read_text().splitlines() if line.startswith("CapEff:"))
        value = int(line.split(":", 1)[1].strip(), 16)
    except (OSError, StopIteration, ValueError) as exc:
        raise QualificationError("cannot read effective Linux capabilities") from exc
    known = ((12, "CAP_NET_ADMIN"), (21, "CAP_SYS_ADMIN"))
    return [name for bit, name in known if value & (1 << bit)]


def _configure_topology() -> str:
    forwarding = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        previous = forwarding.read_text().strip()
        if previous != "1":
            forwarding.write_text("1\n")
    except OSError as exc:
        raise QualificationError("cannot enable forwarding in disposable namespace") from exc
    commands = (
        (str(IP), "netns", "add", CLIENT_NAMESPACE),
        (str(IP), "netns", "add", SERVER_NAMESPACE),
        (str(IP), "link", "add", "lan0", "type", "veth", "peer", "name", "client0"),
        (str(IP), "link", "set", "client0", "netns", CLIENT_NAMESPACE),
        (str(IP), "link", "add", "wan0", "type", "veth", "peer", "name", "server0"),
        (str(IP), "link", "set", "server0", "netns", SERVER_NAMESPACE),
        (str(IP), "address", "add", "10.77.0.1/24", "dev", "lan0"),
        (str(IP), "address", "add", "10.88.0.1/24", "dev", "wan0"),
        (str(IP), "link", "set", "lan0", "up"),
        (str(IP), "link", "set", "wan0", "up"),
        _ns_ip(CLIENT_NAMESPACE, "link", "set", "lo", "up"),
        _ns_ip(CLIENT_NAMESPACE, "address", "add", f"{CLIENT_ADDRESS}/24", "dev", "client0"),
        _ns_ip(CLIENT_NAMESPACE, "link", "set", "client0", "up"),
        _ns_ip(CLIENT_NAMESPACE, "route", "add", "default", "via", "10.77.0.1"),
        _ns_ip(SERVER_NAMESPACE, "link", "set", "lo", "up"),
        _ns_ip(SERVER_NAMESPACE, "address", "add", f"{SERVER_ADDRESS}/24", "dev", "server0"),
        _ns_ip(SERVER_NAMESPACE, "link", "set", "server0", "up"),
        _ns_ip(SERVER_NAMESPACE, "route", "add", "default", "via", "10.88.0.1"),
    )
    try:
        for index, argv in enumerate(commands):
            _run_checked(argv, f"topology step {index + 1}")
    except Exception:
        _cleanup_topology(previous)
        raise
    return previous


def _ns_ip(namespace: str, *arguments: str) -> tuple[str, ...]:
    return (str(IP), "netns", "exec", namespace, str(IP), *arguments)


def _cleanup_topology(forwarding_before: str | None) -> None:
    for namespace in (CLIENT_NAMESPACE, SERVER_NAMESPACE):
        subprocess.run(
            (str(IP), "netns", "del", namespace),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    if forwarding_before in {"0", "1"}:
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(forwarding_before + "\n")
        except OSError:
            pass


def _write_payload(path: Path) -> dict[str, Any]:
    block = hashlib.sha256(b"meercata-dev19-nfqueue-functional").digest()
    data = (block * ((PAYLOAD_BYTES + len(block) - 1) // len(block)))[:PAYLOAD_BYTES]
    path.write_bytes(data)
    path.chmod(0o600)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _write_rules(path: Path) -> Path:
    rule = (
        f'drop tcp {CLIENT_ADDRESS} any -> {SERVER_ADDRESS} {DROP_PORT} '
        f'(msg:"Meercata dev19 NFQ drop qualification"; flow:to_server; sid:{DROP_SID}; rev:1;)\n'
    )
    path.write_text(rule, encoding="utf-8")
    path.chmod(0o600)
    return path


def _start_http_servers(root: Path) -> list[subprocess.Popen[bytes]]:
    processes: list[subprocess.Popen[bytes]] = []
    for port in (ACCEPT_PORT, DROP_PORT):
        processes.append(
            subprocess.Popen(
                (
                    str(IP), "netns", "exec", SERVER_NAMESPACE,
                    str(PYTHON), "-m", "http.server", str(port),
                    "--bind", SERVER_ADDRESS, "--directory", str(root),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        )
    return processes


def _suricata_capability(rules: Path, log_root: Path) -> dict[str, Any]:
    build = _run_checked((str(SURICATA), "--build-info"), "Suricata build-info", timeout=15)
    if "NFQueue support:" not in build.stdout or "yes" not in build.stdout.split("NFQueue support:", 1)[1][:40]:
        raise QualificationError("Suricata build does not report NFQueue support")
    version_line = next((line for line in build.stdout.splitlines() if line.startswith("This is Suricata version ")), "")
    if not version_line or len(version_line) > 128:
        raise QualificationError("Suricata version output is invalid")
    _run_checked(
        (
            str(SURICATA), "-T", "-c", str(SURICATA_CONFIG), "-S", str(rules),
            "-l", str(log_root), "--init-errors-fatal",
        ),
        "Suricata NFQ configuration test",
        timeout=30,
    )
    return {"version": version_line.removeprefix("This is "), "nfqueue_support": True, "exclusive_rule_sid": DROP_SID}


def _start_suricata(rules: Path, log_root: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        (
            str(SURICATA), "-c", str(SURICATA_CONFIG), "-S", str(rules),
            "-q", str(QUEUE), "-l", str(log_root),
            "--pidfile", str(log_root / "suricata.pid"), "--init-errors-fatal",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _run_checked(
    argv: tuple[str, ...], label: str, *, timeout: float = 10.0
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QualificationError(f"{label} could not complete") from exc
    if result.returncode != 0 or len(result.stdout) > 128 * 1024 or len(result.stderr) > 128 * 1024:
        detail = result.stderr.strip().splitlines()[-1:] or result.stdout.strip().splitlines()[-1:]
        suffix = f": {detail[0][:200]}" if detail else ""
        raise QualificationError(f"{label} failed{suffix}")
    return result


def _probe_http(port: int, maximum_bytes: int, timeout: float) -> dict[str, Any]:
    if port not in {ACCEPT_PORT, DROP_PORT} or maximum_bytes != PAYLOAD_BYTES or not 0.5 <= timeout <= 10.0:
        raise QualificationError("HTTP qualification probe parameters are invalid")
    argv = (
        str(IP), "netns", "exec", CLIENT_NAMESPACE, str(PYTHON), "-c", _PROBE_CODE,
        f"http://{SERVER_ADDRESS}:{port}/payload.bin", str(timeout), str(maximum_bytes),
    )
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 3.0,
            check=False,
        )
        value = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise QualificationError("HTTP qualification probe did not return bounded JSON") from exc
    if result.returncode not in {0, 7} or not isinstance(value, dict) or value.get("ok") != (result.returncode == 0):
        raise QualificationError("HTTP qualification probe result is invalid")
    return value


def _wait_for_http(port: int, maximum_bytes: int, wait_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = _probe_http(port, maximum_bytes, 1.0)
        if last["ok"] is True:
            return last
        time.sleep(0.1)
    raise QualificationError(f"HTTP qualification endpoint on port {port} did not become ready: {last}")


def _read_listeners(path: Path = NFQUEUE_STATUS) -> list[dict[str, int]]:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise QualificationError("cannot read kernel NFQUEUE listener status") from exc
    listeners: list[dict[str, int]] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 9:
            raise QualificationError("kernel NFQUEUE listener status is malformed")
        try:
            listeners.append(
                {
                    "queue": int(fields[0]),
                    "port_id": int(fields[1]),
                    "queue_total": int(fields[2]),
                    "copy_mode": int(fields[3]),
                    "copy_range": int(fields[4]),
                    "queue_dropped": int(fields[5]),
                    "user_dropped": int(fields[6]),
                }
            )
        except ValueError as exc:
            raise QualificationError("kernel NFQUEUE listener status contains a non-integer") from exc
    return listeners


def _wait_for_listener(
    queue: int,
    wait_seconds: float,
    *,
    process: subprocess.Popen[bytes] | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise QualificationError(
                f"Suricata exited before attaching to NFQUEUE (status {process.returncode})"
            )
        match = next((item for item in _read_listeners() if item["queue"] == queue), None)
        if match is not None:
            return match
        time.sleep(0.1)
    if not NFQUEUE_STATUS.exists():
        raise QualificationError(
            "kernel NFQUEUE status is unavailable; nfnetlink_queue is not active"
        )
    raise QualificationError("Suricata did not attach to the approved NFQUEUE")


def _wait_for_listener_loss(queue: int, wait_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if all(item["queue"] != queue for item in _read_listeners()):
            return
        time.sleep(0.1)
    raise QualificationError("NFQUEUE listener remained after Suricata stopped")


def _queue_counters(value: Any) -> dict[str, dict[str, int]]:
    try:
        items = value["nftables"]
    except (KeyError, TypeError) as exc:
        raise QualificationError("nftables counter JSON root is invalid") from exc
    counters: dict[str, dict[str, int]] = {}
    for item in items:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not isinstance(rule, dict):
            continue
        comment = rule.get("comment")
        if comment not in {"meercata-managed:v1:in", "meercata-managed:v1:out"}:
            continue
        expression = next((entry["counter"] for entry in rule.get("expr", []) if isinstance(entry, dict) and isinstance(entry.get("counter"), dict)), None)
        if not isinstance(expression, dict) or any(type(expression.get(key)) is not int or expression[key] < 0 for key in ("packets", "bytes")):
            raise QualificationError("nftables rule counter is invalid")
        counters[comment.rsplit(":", 1)[1]] = {"packets": expression["packets"], "bytes": expression["bytes"]}
    if set(counters) != {"in", "out"}:
        raise QualificationError("nftables queue counters are incomplete")
    return counters


def _total_packets(counters: dict[str, dict[str, int]]) -> int:
    return sum(item["packets"] for item in counters.values())


def _wait_for_counter_progress(previous: dict[str, dict[str, int]], wait_seconds: float) -> dict[str, dict[str, int]]:
    deadline = time.monotonic() + wait_seconds
    before = _total_packets(previous)
    while time.monotonic() < deadline:
        current = _queue_counters(_list_table("meercata"))
        if _total_packets(current) > before:
            return current
        time.sleep(0.1)
    raise QualificationError("nftables queue counters did not progress")


def _wait_for_drop_alert(path: Path, sid: int, wait_seconds: float) -> dict[str, str]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            content = ""
        except OSError as exc:
            raise QualificationError("cannot read Suricata EVE output") from exc
        lines = content.splitlines()
        if content and not content.endswith("\n"):
            lines = lines[:-1]
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise QualificationError("Suricata EVE output contains invalid JSON") from exc
            alert = event.get("alert") if isinstance(event, dict) else None
            if isinstance(alert, dict) and alert.get("signature_id") == sid:
                action = alert.get("action")
                if action not in {"blocked", "drop"}:
                    raise QualificationError("Suricata drop alert does not report a blocking action")
                return {"action": action, "signature": str(alert.get("signature", ""))[:256]}
        time.sleep(0.1)
    raise QualificationError("Suricata EVE output did not contain the qualification drop alert")


def _bounded_sample(payload: dict[str, Any]) -> dict[str, Any]:
    durations: list[float] = []
    for _ in range(LATENCY_SAMPLES):
        observed = _wait_for_http(ACCEPT_PORT, PAYLOAD_BYTES, 5.0)
        if observed["sha256"] != payload["sha256"]:
            raise QualificationError("bounded sample payload digest is incorrect")
        durations.append(float(observed["duration_ms"]))
    total_seconds = sum(durations) / 1000
    throughput_mbps = (PAYLOAD_BYTES * LATENCY_SAMPLES * 8) / total_seconds / 1_000_000
    return {
        "samples": LATENCY_SAMPLES,
        "bytes_per_sample": PAYLOAD_BYTES,
        "latency_min_ms": round(min(durations), 3),
        "latency_median_ms": round(statistics.median(durations), 3),
        "latency_max_ms": round(max(durations), 3),
        "aggregate_throughput_mbps": round(throughput_mbps, 3),
        "classification": "bounded-functional-sample-not-capacity",
    }


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m meercata.nfqueue_functional_qualifier",
        description="Qualify live Suricata NFQUEUE verdicts in disposable routed namespaces",
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
        report = NfqueueFunctionalQualifier(
            confirmation=arguments.confirm,
            image_digest=arguments.image_digest,
        ).qualify()
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if arguments.output is not None:
            arguments.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="", file=stdout)
        return 0
    except QualificationError as exc:
        print(f"meercata-nfqueue-functional-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
