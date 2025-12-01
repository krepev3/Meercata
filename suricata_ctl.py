#!/usr/bin/env python3
"""Suricata control helpers."""

import os
import shutil
import subprocess
from utils import run
from hooks import flush_xt, flush_nft, install_nft, install_xt, show_counters


def pick_backend(preference: str) -> str:
    pref = preference.lower()
    if pref in {"xt", "nft"}:
        return pref
    if shutil.which("nft"):
        return "nft"
    return "xt"


def suricata_test(apply: bool, cfg: str) -> bool:
    return run(["suricata", "-T", "-c", cfg], apply)


def suricata_stop(apply: bool) -> bool:
    ok_svc = run(["systemctl", "stop", "suricata"], apply, ignore_errors=True)
    ok_proc = run(["pkill", "-x", "suricata"], apply, ignore_errors=True)
    return bool(ok_svc and ok_proc)


def suricata_ids(apply: bool, iface: str, cfg: str, queue: int) -> None:
    suricata_stop(apply)
    if not flush_xt(apply, queue, iface):
        print("[WARN] iptables flush reported errors")
    if not flush_nft(apply):
        print("[WARN] nft flush reported errors")
    if not suricata_test(apply, cfg):
        print("[ERR] suricata -T failed; aborting start")
        return
    run(["suricata", "-c", cfg, "-i", iface], apply)


def suricata_ips(apply: bool, iface: str, cfg: str, backend_pref: str, queue: int) -> None:
    backend = pick_backend(backend_pref)
    suricata_stop(apply)
    if not flush_xt(apply, queue, iface):
        print("[WARN] iptables flush reported errors")
    if not flush_nft(apply):
        print("[WARN] nft flush reported errors")
    if not suricata_test(apply, cfg):
        print("[ERR] suricata -T failed; aborting start")
        return
    install_ok = install_nft(apply, queue, iface) if backend == "nft" else install_xt(apply, queue, iface)
    if install_ok is False:
        print(f"[ERR] failed to install {backend} hooks; aborting start")
        return
    run(["suricata", "-c", cfg, "-q", str(queue)], apply)


def status() -> None:
    # Service status
    svc_res = subprocess.run(["systemctl", "is-active", "suricata"], text=True, capture_output=True)
    if svc_res.returncode == 0:
        svc = svc_res.stdout.strip() or "active"
    elif svc_res.returncode == 3:
        svc = svc_res.stdout.strip() or "inactive"
    else:
        svc = f"error: {svc_res.stderr.strip() or svc_res.stdout.strip() or 'unknown'}"
    print(f"[Suricata service] {svc}")

    # Process list
    try:
        pids = subprocess.check_output(["pgrep", "-ax", "suricata"], text=True).strip()
        if pids:
            print("[Processes]")
            print(pids)
        else:
            print("[Processes] none")
    except subprocess.CalledProcessError:
        print("[Processes] none")

    # iptables/ip6tables counters (table view)
    show_counters(True)

    # nft table
    print("\n[nft inet suri]")
    try:
        nft_out = subprocess.check_output(["nft", "list", "table", "inet", "suri"], text=True, stderr=subprocess.STDOUT)
        print(nft_out.strip())
    except subprocess.CalledProcessError as exc:
        print(f"(missing or empty) {exc}")


def live_monitor(log_path: str, suricatamon_bin: str, show_sid: str = "1", wide: str = "1") -> None:
    if os.path.isfile(suricatamon_bin) and os.access(suricatamon_bin, os.X_OK):
        print("[OK] launching suricatamon (Ctrl-C to exit)…")
        run(
            [suricatamon_bin],
            apply=True,
            force=True,
        )
    else:
        if not os.path.isfile(log_path):
            print(f"[ERR] cannot read {log_path}")
            return
        print(f"[WARN] suricatamon not found at {suricatamon_bin}. Falling back to tail.")
        run(["tail", "-n", "200", log_path], apply=True, force=True)
