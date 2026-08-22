#!/usr/bin/env python3
"""Cross-platform Suricata control helpers."""

import csv
import os
import re
import shutil
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import List
from utils import run
from hooks import flush_xt, flush_nft, install_nft, install_xt, show_counters
from platform_support import (
    IS_WINDOWS,
    suricata_command,
    suricata_env,
    suricata_working_directory,
)


SURICATA_PROCESS_PATTERN = r"(^|/)suricata([[:space:]]|$)"
MANAGED_SERVICE_UNITS = ("suricata.service", "suricata-inline.service")
WINDOWS_SERVICE_NAME = "Suricata"


def pick_backend(preference: str) -> str:
    if IS_WINDOWS:
        return "windivert"
    pref = preference.lower()
    if pref in {"xt", "nft"}:
        return pref
    if shutil.which("nft"):
        return "nft"
    return "xt"


def suricata_test(apply: bool, cfg: str) -> bool:
    executable = suricata_command()
    return run(
        [executable, "-T", "-c", cfg],
        apply,
        env=suricata_env(executable),
        cwd=suricata_working_directory(executable),
        timeout=30,
    )


def service_status(unit: str = "suricata.service") -> str:
    """Return a normalized systemd or Windows service state."""
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["sc.exe", "query", WINDOWS_SERVICE_NAME],
                text=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"unavailable: {exc}"
        output = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", output, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        if result.returncode != 0 and "1060" in output:
            return "not installed"
        return "not installed" if result.returncode != 0 else "unknown"
    try:
        result = subprocess.run(["systemctl", "is-active", unit], text=True, capture_output=True)
    except OSError as exc:
        return f"unavailable: {exc}"
    state = result.stdout.strip()
    if state:
        return state
    if result.returncode == 0:
        return "active"
    return f"error: {result.stderr.strip() or 'unknown'}"


def active_managed_services() -> List[str]:
    """Return Meercata-related services that are active before a foreground run."""
    if IS_WINDOWS:
        return [WINDOWS_SERVICE_NAME] if service_status() == "running" else []
    active: List[str] = []
    for unit in MANAGED_SERVICE_UNITS:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", unit],
                text=True,
                capture_output=True,
            )
        except OSError:
            continue
        if result.returncode == 0:
            active.append(unit)
    return active


def suricata_stop(apply: bool) -> bool:
    if IS_WINDOWS:
        run(["sc.exe", "stop", WINDOWS_SERVICE_NAME], apply, ignore_errors=True)
        run(["taskkill.exe", "/IM", "suricata.exe", "/T", "/F"], apply, ignore_errors=True)
        return True
    for unit in MANAGED_SERVICE_UNITS:
        run(["systemctl", "stop", unit], apply, ignore_errors=True)
    # Suricata changes its process name to Suricata-Main after startup, so
    # match the original executable command line rather than the comm name.
    run(["pkill", "-f", SURICATA_PROCESS_PATTERN], apply, ignore_errors=True)
    return True


def restore_pre_run_state(
    apply: bool,
    queue: int,
    iface: str,
    previously_active_services: List[str],
) -> bool:
    """Remove Meercata runtime state and restore services active before launch."""
    if not apply:
        action = "restore the pre-run service state"
        if not IS_WINDOWS:
            action = "remove Meercata runtime hooks and " + action
        print(f"[DRY] would {action}")
        return True

    print("[INFO] Restoring pre-run runtime state")
    # Stop both service variants and any remaining engine before removing all
    # Meercata-owned hooks. This also covers partial startup failures.
    suricata_stop(True)
    if IS_WINDOWS:
        ok = True
    else:
        ok_xt = flush_xt(True, queue, iface)
        ok_nft = flush_nft(True)
        ok = bool(ok_xt and ok_nft)
    for unit in previously_active_services:
        command = ["sc.exe", "start", unit] if IS_WINDOWS else ["systemctl", "start", unit]
        ok = run(command, True) and ok
    if ok:
        restored = ", ".join(previously_active_services) or "services remained stopped"
        print(f"[OK] Pre-run runtime state restored ({restored})")
    else:
        print("[WARN] Pre-run runtime-state restoration reported errors")
    return ok


def suricata_ids(apply: bool, iface: str, cfg: str, queue: int) -> bool:
    previously_active_services = active_managed_services() if apply else []
    suricata_stop(apply)
    try:
        if not IS_WINDOWS:
            if not flush_xt(apply, queue, iface):
                print("[WARN] iptables/ip6tables flush reported errors")
            if not flush_nft(apply):
                print("[WARN] nft flush reported errors")
        if not suricata_test(apply, cfg):
            print("[ERR] suricata -T failed; aborting start")
            return False
        executable = suricata_command()
        return run(
            [executable, "-c", cfg, "-i", iface],
            apply,
            env=suricata_env(executable),
            cwd=suricata_working_directory(executable),
        )
    finally:
        restore_pre_run_state(apply, queue, iface, previously_active_services)


def suricata_ips(
    apply: bool,
    iface: str,
    cfg: str,
    backend_pref: str,
    queue: int,
    fail_open: bool = True,
    windivert_filter: str = "true",
    forward: bool = False,
) -> bool:
    backend = pick_backend(backend_pref)
    previously_active_services = active_managed_services() if apply else []
    suricata_stop(apply)
    try:
        if IS_WINDOWS:
            if not windivert_filter.strip():
                print("[ERR] WinDivert filter cannot be empty")
                return False
            if not suricata_test(apply, cfg):
                print("[ERR] suricata -T failed; aborting start")
                return False
            executable = suricata_command()
            mode = "--windivert-forward" if forward else "--windivert"
            return run(
                [executable, "-c", cfg, mode, windivert_filter],
                apply,
                env=suricata_env(executable),
                cwd=suricata_working_directory(executable),
            )
        if not flush_xt(apply, queue, iface):
            print("[WARN] iptables/ip6tables flush reported errors")
        if not flush_nft(apply):
            print("[WARN] nft flush reported errors")
        if not suricata_test(apply, cfg):
            print("[ERR] suricata -T failed; aborting start")
            return False
        install_ok = (
            install_nft(apply, queue, iface, fail_open)
            if backend == "nft"
            else install_xt(apply, queue, iface, fail_open)
        )
        if install_ok is False:
            print(f"[ERR] failed to install {backend} hooks; aborting start")
            return False
        executable = suricata_command()
        return run([executable, "-c", cfg, "-q", str(queue)], apply)
    finally:
        restore_pre_run_state(apply, queue, iface, previously_active_services)


def status() -> None:
    svc = service_status()
    print(f"[Suricata service] {svc}")

    # Process list
    processes = suricata_processes()
    if processes:
        print("[Processes]")
        print("\n".join(processes))
    else:
        print("[Processes] none")

    if IS_WINDOWS:
        print("[Capture] Npcap/pcap (Windows); Linux NFQUEUE counters do not apply")
        return

    # iptables/ip6tables counters (table view)
    show_counters(True)

    # nft table
    print("\n[nft inet meercata]")
    if not shutil.which("nft"):
        print("(nft not installed)")
    else:
        try:
            nft_out = subprocess.check_output(["nft", "list", "table", "inet", "meercata"], text=True, stderr=subprocess.STDOUT)
            print(nft_out.strip())
        except subprocess.CalledProcessError as exc:
            print(f"(missing or empty) {exc}")


def suricata_processes() -> List[str]:
    """Return foreground or service Suricata processes by executable command line."""
    if IS_WINDOWS:
        try:
            output = subprocess.check_output(
                ["tasklist.exe", "/FI", "IMAGENAME eq suricata.exe", "/FO", "CSV", "/NH"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            return []
        processes: List[str] = []
        for row in csv.reader(output.splitlines()):
            if len(row) >= 2 and row[0].lower() == "suricata.exe":
                processes.append(f"{row[1]} {row[0]}")
        return processes
    try:
        output = subprocess.check_output(["pgrep", "-af", SURICATA_PROCESS_PATTERN], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return []
    return [line for line in output.splitlines() if line.strip()]


def live_monitor(
    log_path: str,
    suricatamon_bin: str,
    show_sid: str = "1",
    wide: str = "1",
    trigger_log_path: str = "",
) -> None:
    def _run_builtin() -> None:
        monitor_script = Path(__file__).resolve().with_name("suricatamon.py")
        command = [
            sys.executable,
            str(monitor_script),
            "--log",
            log_path,
            "--show-sid",
            show_sid,
            "--wide",
            wide,
        ]
        if trigger_log_path:
            command.extend(["--trigger-log", trigger_log_path])
        run(command, apply=True, force=True)

    if suricatamon_bin == "builtin" or trigger_log_path:
        if suricatamon_bin != "builtin" and trigger_log_path:
            print("[INFO] using builtin monitor so alert/drop evidence logging is available")
        _run_builtin()
        return

    # Accept either full path or PATH-resolvable binary.
    resolved = suricatamon_bin
    if not (os.path.isfile(resolved) and os.access(resolved, os.X_OK)):
        found = shutil.which(suricatamon_bin)
        if found and os.access(found, os.X_OK):
            resolved = found
        elif os.path.sep in suricatamon_bin:
            # If an absolute path was provided but missing, try basename on PATH.
            fallback = shutil.which(os.path.basename(suricatamon_bin))
            if fallback and os.access(fallback, os.X_OK):
                resolved = fallback
    if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
        print(f"[OK] launching suricatamon ({resolved}) (Ctrl-C to exit)…")
        run([resolved], apply=True, force=True)
        return

    print(f"[WARN] suricatamon not found/executable ({suricatamon_bin}); using builtin monitor.")
    _run_builtin()


def follow_evidence_log(log_path: str, lines: int = 100) -> bool:
    """Show recent threat evidence and follow appended records until Ctrl+C."""
    if not 1 <= lines <= 100000:
        print("[ERR] evidence tail line count must be between 1 and 100000")
        return False
    path = os.path.abspath(log_path)
    try:
        open(path, "a", encoding="utf-8").close()
    except OSError as exc:
        print(f"[ERR] cannot open evidence log {path}: {exc}", file=sys.stderr)
        return False
    print(f"[INFO] Following the last {lines} lines of {path}")
    print("[INFO] New evidence will appear automatically; press Ctrl+C to return to Meercata.")
    try:
        if IS_WINDOWS or not shutil.which("tail"):
            _follow_file_python(path, lines)
        else:
            subprocess.run(["tail", "-n", str(lines), "-F", "--", path], check=False)
    except KeyboardInterrupt:
        print("\n[INFO] Threat Monitoring stopped; evidence collection was not modified.")
    except OSError as exc:
        print(f"[ERR] cannot follow evidence log {path}: {exc}", file=sys.stderr)
        return False
    return True


def _follow_file_python(path: str, lines: int) -> None:
    """Small cross-platform equivalent of ``tail -n N -F``."""
    filename = Path(path)
    stream = filename.open("r", encoding="utf-8", errors="replace")
    try:
        recent = deque(stream, maxlen=lines)
        for line in recent:
            print(line, end="", flush=True)
        position = stream.tell()
        identity = _file_identity(filename)
        while True:
            line = stream.readline()
            if line:
                position = stream.tell()
                print(line, end="", flush=True)
                continue
            time.sleep(0.25)
            try:
                new_identity = _file_identity(filename)
                size = filename.stat().st_size
            except OSError:
                continue
            if new_identity != identity or size < position:
                stream.close()
                stream = filename.open("r", encoding="utf-8", errors="replace")
                identity = new_identity
                position = 0
    finally:
        stream.close()


def _file_identity(path: Path) -> tuple[int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino
