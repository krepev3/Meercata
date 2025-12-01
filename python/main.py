#!/usr/bin/env python3
"""Meercata Python port (modular).

Default: dry-run (prints commands). Use --apply to execute.
Requires root for --apply when touching firewall/system services.
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from hooks import (
    allowlist_insert,
    backup_rules,
    existing_hooks,
    firewall_capabilities,
    flush_all,
    restore_rules,
    show_counters,
    show_firewall_rules,
)
from suricata_ctl import live_monitor, status, suricata_ids, suricata_ips
from systemd_unit import systemd_install, systemd_remove
from utils import ensure_binaries
from yaml_tools import (
    _render_table,
    yaml_af_packet_entries,
    yaml_default_rule_path,
    yaml_rulefiles,
    yaml_rules_insight,
    yaml_set_af_packet_state,
    yaml_add_rulefile,
    yaml_set_nfq_kv,
    yaml_set_rule_state,
    yaml_set_runmode,
    yaml_summary,
)

DEFAULT_CFG = os.environ.get("SURICATA_CFG", "/etc/suricata/suricata.yaml")
DEFAULT_QUEUE = int(os.environ.get("QUEUE", "0"))
DEFAULT_BACKEND = os.environ.get("BACKEND", "auto")  # auto|xt|nft
DEFAULT_IFACE = os.environ.get("IFACE", "")
SURICATAMON_BIN = os.environ.get("SURICATAMON_BIN", "/usr/local/bin/suricatamon")
DEFAULT_STORE = Path.home() / ".meercata_defaults.json"

# ANSI orange (approx.) for banner; fallback-safe.
COLOR_ORANGE = "\033[38;5;208m"
COLOR_RESET = "\033[0m"
BANNER = r"""
  |  \/  |  ___   ___  _ __  ___  __ _ | |_  __ _
  | |\/| | / _ \ / _ \| '__|/ __|/ _` || __|/ _` |
  | |  | ||  __/|  __/| |  | (__| (_| || |_| (_| |
  |_|  |_| \___| \___||_|   \___|\__,_| \__|\__,_|
  developer: Kreczlyxt  contact: analyxt@lyxt.xyz
  === Meercata (interactive) ===
"""
BANNER_COLORED = f"{COLOR_ORANGE}{BANNER}{COLOR_RESET}"


def _print_banner() -> None:
    for line in BANNER.strip("\n").splitlines():
        print(f"{COLOR_ORANGE}{line.rstrip()}{COLOR_RESET}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Meercata Python port (modular)")
    p.add_argument("--config", default=DEFAULT_CFG, help="suricata.yaml path")
    p.add_argument("--iface", default=DEFAULT_IFACE, help="interface (required for ids/ips)")
    p.add_argument("--queue", type=int, default=DEFAULT_QUEUE, help="NFQUEUE number")
    p.add_argument("--backend", default=DEFAULT_BACKEND, choices=["auto", "xt", "nft"], help="backend preference")
    p.add_argument("--apply", action="store_true", help="execute commands (otherwise dry-run)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ids", help="start Suricata in IDS mode")
    sub.add_parser("ips", help="start Suricata in IPS-ALL mode")
    sub.add_parser("flush", help="flush NFQUEUE hooks")
    sub.add_parser("status", help="show Suricata/NFQUEUE status")
    sub.add_parser("rules", help="show rule-files enabled/disabled")
    rp = sub.add_parser("rule-set", help="enable/disable a rule-file in suricata.yaml")
    rp.add_argument("--file", required=True, help="rule-file name as listed in YAML")
    rp.add_argument("--state", required=True, choices=["enabled", "disabled"], help="desired state")
    sub.add_parser("rule-menu", help="interactive rule enable/disable from suricata.yaml")
    sub.add_parser("yaml-summary", help="summarize HOME_NET/EXTERNAL_NET/capture/nfq")
    sub.add_parser("runmode-set", help="set runmode to workers/autofp").add_argument("--mode", required=True, choices=["workers", "autofp"])
    nfq_bc = sub.add_parser("nfq-batchcount", help="set nfq.batchcount")
    nfq_bc.add_argument("--value", required=True, help="integer batchcount")
    nfq_fo = sub.add_parser("nfq-failopen", help="set nfq.fail-open yes/no")
    nfq_fo.add_argument("--value", required=True, choices=["yes", "no"])
    sub.add_parser("nfq-queue", help="write nfq.queue = current queue")
    unit = sub.add_parser("unit-install", help="install systemd unit for inline mode")
    unit.add_argument("--iface", required=True, help="interface")
    unit.add_argument("--queue", type=int, required=True, help="NFQUEUE number")
    unit.add_argument("--backend", choices=["auto", "xt", "nft"], default=DEFAULT_BACKEND, help="backend preference")
    sub.add_parser("unit-remove", help="remove systemd unit")
    allow = sub.add_parser("allowlist", help="insert allowlist rule before NFQUEUE")
    allow.add_argument("--direction", choices=["in", "out", "forward"], default="in")
    allow.add_argument("--proto", choices=["tcp", "udp", "all"], default="all")
    allow.add_argument("--addr", default="", help="IP/CIDR to allow")
    allow.add_argument("--port", default="", help="destination port (optional)")
    sub.add_parser("backup", help="backup iptables/ip6tables rules")
    sub.add_parser("restore", help="restore iptables/ip6tables rules")
    sub.add_parser("counters", help="show iptables/ip6tables counters")
    monitor = sub.add_parser("monitor", help="launch suricatamon or tail eve.json")
    monitor.add_argument("--log", default=os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
    sub.add_parser("diag", help="show combined status (suricata + NFQUEUE hooks + firewall tools)")
    return p.parse_args()


def rule_menu(cfg: str) -> None:
    entries = yaml_rulefiles(cfg)
    if not entries:
        print(f"[ERR] no rule-files found in {cfg}")
        return
    while True:
        _clear_screen()
        _print_banner()
        print()
        print(f"Rule-files in {cfg}:")
        print()
        rows = []
        for idx, (state, name) in enumerate(entries, 1):
            rows.append((str(idx), state, name))
        print(_render_table(["#", "State", "Name"], rows))
        print()
        choice = input("Select number to change (Enter to quit): ").strip()
        if not choice:
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(entries)):
            print("[ERR] invalid selection")
            continue
        target_state, target_name = entries[int(choice) - 1]
        suggested = "enabled" if target_state == "disabled" else "disabled"
        desired = input(f"Set state to [enabled/disabled] (default {suggested}): ").strip().lower()
        if desired not in {"enabled", "disabled"}:
            desired = suggested
        changed = yaml_set_rule_state(cfg, target_name, desired)
        print(f"[OK] {target_name} -> {desired}" if changed else "[OK] no change needed")
        # refresh list after change
        entries = yaml_rulefiles(cfg)


def _prompt(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{msg}{suffix}: ").strip()
    return val if val else default


def _prompt_bool(msg: str, default: bool = False) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    val = input(f"{msg}{suffix}: ").strip().lower()
    if not val:
        return default
    return val in {"y", "yes"}


def _pause() -> None:
    input("\nPress Enter to continue...")


def _clear_screen() -> None:
    os.system("clear")


def _cfg_status(cfg: str) -> str:
    p = Path(cfg)
    return "ok" if p.exists() else "missing"


def _iface_ips() -> dict:
    """Return mapping of iface -> list of IPv4/IPv6 addresses."""
    res: Dict[str, List[str]] = {}
    for fam in ("-4", "-6"):
        try:
            out = subprocess.check_output(["ip", "-o", fam, "addr", "show"], text=True)
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                ip = parts[3].split("/")[0]
                res.setdefault(iface, []).append(ip)
    return res


def _iface_ok(iface: str) -> bool:
    return bool(iface) and Path(f"/sys/class/net/{iface}").exists()


def _iface_ok_with_ip(iface: str, ipmap: dict) -> bool:
    return _iface_ok(iface) and iface in ipmap


def _require_cfg(cfg: str) -> None:
    if not Path(cfg).exists():
        print(f"[ERR] Suricata config not found: {cfg}", file=sys.stderr)
        sys.exit(1)


def _queue_ok(queue: int) -> bool:
    return queue >= 0


def _parse_queue_input(raw: str, fallback: int) -> Tuple[int, bool]:
    """Parse queue input from user, returning (value, valid)."""
    stripped = raw.strip()
    if stripped.isdigit():
        val = int(stripped)
        if _queue_ok(val):
            return val, True
    return fallback, False


def diag_status(cfg: str, iface: str, queue: int) -> None:
    print("[Diag] Suricata service:", _service_status())
    print("[Diag] Firewall tools:", ", ".join(firewall_capabilities()) or "none detected")
    hooks_present = existing_hooks(queue, iface)
    if hooks_present:
        print("[Diag] NFQUEUE hooks:")
        for h in hooks_present:
            print(f"  - {h}")
    else:
        print("[Diag] NFQUEUE hooks: none for current iface/queue")
    if Path(cfg).exists():
        print(f"[Diag] Suricata config: {cfg} (exists)")
    else:
        print(f"[Diag] Suricata config: {cfg} (missing)")


def _load_defaults() -> tuple[str, str, int, str]:
    if DEFAULT_STORE.exists():
        try:
            data = json.loads(DEFAULT_STORE.read_text())
            return (
                data.get("config", DEFAULT_CFG),
                data.get("iface", DEFAULT_IFACE),
                int(data.get("queue", DEFAULT_QUEUE)),
                data.get("backend", DEFAULT_BACKEND),
            )
        except Exception:
            return DEFAULT_CFG, DEFAULT_IFACE, DEFAULT_QUEUE, DEFAULT_BACKEND
    return DEFAULT_CFG, DEFAULT_IFACE, DEFAULT_QUEUE, DEFAULT_BACKEND


def _save_defaults(cfg: str, iface: str, queue: int, backend: str) -> None:
    try:
        DEFAULT_STORE.write_text(json.dumps({"config": cfg, "iface": iface, "queue": queue, "backend": backend}))
    except Exception:
        pass


def _service_status() -> str:
    res = subprocess.run(["systemctl", "is-active", "suricata"], text=True, capture_output=True)
    if res.returncode == 0:
        return res.stdout.strip() or "active"
    # Exit code 3 is the normal "inactive" state for systemctl is-active.
    if res.returncode == 3:
        return res.stdout.strip() or "inactive"
    return f"error: {res.stderr.strip() or res.stdout.strip() or 'unknown'}"


def menu_suricata(cfg: str, iface: str, queue: int, backend: str) -> tuple[str, str, int, str]:
    while True:
        _clear_screen()
        _print_banner()
        print()
        print("-- Suricata control --")
        print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
        ipmap = _iface_ips()
        iface_state = "ok" if _iface_ok_with_ip(iface, ipmap) else ("missing" if iface else "blank")
        print(f"iface={iface or '<none>'} ({iface_state}) queue={queue} backend={backend}")
        print(f"service={_service_status()}")
        print()
        print("1) IDS (sniff-only)")
        print("2) IPS (NFQUEUE inline)")
        print("3) Status")
        print("4) Monitor (tail or suricatamon)")
        print("0) Back")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            return cfg, iface, queue, backend
        try:
            if choice == "1":
                ipmap = _iface_ips()
                if not _iface_ok_with_ip(iface, ipmap):
                    iface = _prompt("Interface (required)", iface)
                apply = _prompt_bool("Apply (execute commands)?", False)
                suricata_ids(apply, iface, cfg, queue)
            elif choice == "2":
                ipmap = _iface_ips()
                if not _iface_ok_with_ip(iface, ipmap):
                    iface = _prompt("Interface (required)", iface)
                apply = _prompt_bool("Apply (execute commands)?", False)
                suricata_ips(apply, iface, cfg, backend, queue)
            elif choice == "3":
                status()
            elif choice == "4":
                log = _prompt("Log path for tail", os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
                live_monitor(log, SURICATAMON_BIN)
            else:
                print("[ERR] invalid selection")
        except KeyboardInterrupt:
            print("\n[WARN] interrupted")
        except Exception as exc:
            print(f"[ERR] {exc}")
        _pause()
    return cfg, iface, queue, backend


def menu_rules(cfg: str, queue: int) -> None:
    while True:
        _clear_screen()
        _print_banner()
        print()
        print("-- Rules / YAML --")
        print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
        print(f"queue={queue}")
        print()
        print("1) Rule files (view/toggle/set)")
        print("2) Add rule-file (create file + add to YAML)")
        print("3) YAML/NFQ settings")
        print("0) Back")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            return
        if choice == "1":
            # Rule file management submenu
            while True:
                _clear_screen()
                _print_banner()
                print()
                print("-- Rule files --")
                print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
                print()
                print("1) Show rule-files (table)")
                print("2) Rule menu (toggle enable/disable)")
                print("3) Rule set (manual)")
                print("0) Back")
                print()
                sub = input("Select option: ").strip()
                if sub in {"0", ""}:
                    break
                try:
                    if sub == "1":
                        yaml_rules_insight(cfg)
                    elif sub == "2":
                        rule_menu(cfg)
                    elif sub == "3":
                        file = _prompt("Rule-file name", "")
                        if not file:
                            print("[ERR] rule file required")
                        else:
                            desired = _prompt("State (enabled/disabled)", "enabled").lower()
                            if desired not in {"enabled", "disabled"}:
                                desired = "enabled"
                            changed = yaml_set_rule_state(cfg, file, desired)
                            print(f"[OK] {file} -> {desired}" if changed else "[OK] no change needed")
                    else:
                        print("[ERR] invalid selection")
                except KeyboardInterrupt:
                    print("\n[WARN] interrupted")
                except Exception as exc:
                    print(f"[ERR] {exc}")
                _pause()
        elif choice == "2":
            # Add a new rule file interactively
            base = yaml_default_rule_path(cfg)
            print(f"Default rule path: {base}")
            name = _prompt("Rule-file name (e.g., custom.rules)", "custom.rules")
            if not name.endswith(".rules"):
                print("[ERR] rule-file name must end with .rules")
                _pause()
                continue
            content_lines: List[str] = []
            print("Enter rule lines (empty line to finish):")
            while True:
                line = input()
                if line == "":
                    break
                content_lines.append(line)
            if not content_lines:
                print("[WARN] no content entered; aborting")
                _pause()
                continue
            target_path = Path(base) / name
            if target_path.exists():
                if not _prompt_bool(f"{target_path} exists, overwrite?", False):
                    print("[INFO] aborting; file not overwritten")
                    _pause()
                    continue
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text("\n".join(content_lines) + "\n", encoding="utf-8")
            added = yaml_add_rulefile(cfg, name)
            if added:
                print(f"[OK] wrote {target_path} and added to rule-files")
            else:
                print(f"[OK] wrote {target_path}; already present in rule-files")
            print("\n[rule-files status]")
            yaml_rules_insight(cfg)
            _pause()
        elif choice == "3":
            # YAML / NFQ submenu
            while True:
                _clear_screen()
                _print_banner()
                print()
                print("-- YAML / NFQ --")
                print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
                print(f"queue={queue}")
                print()
                print("1) YAML summary (table) + af-packet toggle")
                print("2) Runmode set")
                print("3) NFQ batchcount")
                print("4) NFQ fail-open")
                print("5) NFQ queue = current queue")
                print("0) Back")
                print()
                sub = input("Select option: ").strip()
                if sub in {"0", ""}:
                    break
                try:
                    if sub == "1":
                        yaml_summary(cfg)
                        entries = yaml_af_packet_entries(cfg)
                        if entries:
                            rows = [(str(idx + 1), state, iface) for idx, (state, iface, _) in enumerate(entries)]
                            print("\n[af-packet]")
                            print(_render_table(["#", "State", "Interface"], rows))
                            print()
                            sel = input("Select interface number to toggle (Enter to back): ").strip()
                            if sel:
                                if sel.isdigit() and 1 <= int(sel) <= len(entries):
                                    state, iface_name, _ = entries[int(sel) - 1]
                                    desired = "disabled" if state == "enabled" else "enabled"
                                    ans = _prompt(f"Set state to [enabled/disabled] (default {desired})", desired).lower()
                                    if ans not in {"enabled", "disabled"}:
                                        ans = desired
                                    changed = yaml_set_af_packet_state(cfg, iface_name, ans)
                                    print(f"[OK] {iface_name} -> {ans}" if changed else "[OK] no change needed")
                                    print()
                                    yaml_summary(cfg)
                                else:
                                    print("[ERR] invalid selection")
                        else:
                            print("\n[af-packet] (none)")
                    elif sub == "2":
                        mode = _prompt("Mode (workers/autofp)", "workers")
                        yaml_set_runmode(cfg, mode)
                    elif sub == "3":
                        val = _prompt("nfq.batchcount value", "64")
                        yaml_set_nfq_kv(cfg, "batchcount", val)
                        print()
                        yaml_summary(cfg)
                    elif sub == "4":
                        val = _prompt("nfq.fail-open (yes/no)", "no")
                        yaml_set_nfq_kv(cfg, "fail-open", val)
                        print()
                        yaml_summary(cfg)
                    elif sub == "5":
                        yaml_set_nfq_kv(cfg, "queue", str(queue))
                        print()
                        yaml_summary(cfg)
                    else:
                        print("[ERR] invalid selection")
                except KeyboardInterrupt:
                    print("\n[WARN] interrupted")
                except Exception as exc:
                    print(f"[ERR] {exc}")
                _pause()
        else:
            print("[ERR] invalid selection")


def menu_hooks(cfg: str, iface: str, queue: int, backend: str) -> tuple[str, str, int, str]:
    while True:
        _clear_screen()
        _print_banner()
        print()
        print("-- Hooks / firewall --")
        print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
        print(f"iface={iface or '<none>'} queue={queue} backend={backend}")
        caps = firewall_capabilities()
        detected = ", ".join(caps) if caps else "none detected"
        print(f"firewall tools: {detected}")
        print()
        print("1) Flush NFQUEUE hooks")
        print("2) Allowlist insert")
        print("3) Counters")
        print("4) Backup rules")
        print("5) Restore rules")
        print("6) Show firewall rules")
        print("0) Back")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            return cfg, iface, queue, backend
        try:
            if choice == "1":
                hooks_present = existing_hooks(queue, iface)
                if hooks_present:
                    print("[INFO] Existing NFQUEUE hooks found:")
                    for h in hooks_present:
                        print(f"  - {h}")
                else:
                    print("[INFO] No NFQUEUE hooks detected for queue/iface.")
                apply = _prompt_bool("Apply (execute flush)?", False)
                if apply and hooks_present:
                    if not _prompt_bool("Confirm flush of the above hooks?", False):
                        print("[INFO] Flush cancelled")
                        _pause()
                        continue
                flush_all(apply, queue, iface)
                if apply:
                    if hooks_present:
                        print("[OK] Flushed NFQUEUE hooks:")
                        for h in hooks_present:
                            print(f"  - {h}")
                    else:
                        print("[OK] No NFQUEUE hooks were present; nothing to flush.")
            elif choice == "2":
                direction = _prompt("Direction (in/out/forward)", "in")
                proto = _prompt("Proto (tcp/udp/all)", "all")
                addr = _prompt("IP/CIDR (optional)", "")
                port = _prompt("Dest port (optional)", "")
                apply = _prompt_bool("Apply (insert now)?", False)
                allowlist_insert(apply, direction, proto, addr, port)
            elif choice == "3":
                show_counters(True)
            elif choice == "4":
                apply = _prompt_bool("Apply (save rules)?", False)
                backup_rules(apply)
            elif choice == "5":
                apply = _prompt_bool("Apply (restore rules)?", False)
                restore_rules(apply)
            elif choice == "6":
                show_firewall_rules()
            else:
                print("[ERR] invalid selection")
        except KeyboardInterrupt:
            print("\n[WARN] interrupted")
        except Exception as exc:
            print(f"[ERR] {exc}")
        _pause()
    return cfg, iface, queue, backend


def menu_systemd(cfg: str, iface: str, queue: int, backend: str) -> tuple[str, str, int, str]:
    while True:
        _clear_screen()
        _print_banner()
        print()
        print("-- Systemd unit --")
        print(f"config={cfg} dir={Path(cfg).parent} [{_cfg_status(cfg)}]")
        print(f"iface={iface or '<none>'} queue={queue} backend={backend}")
        print("[WARN] Experimental: enabling this unit can break boot if misconfigured. Use with caution.")
        print()
        print("1) Install inline unit")
        print("2) Remove inline unit")
        print("0) Back")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            return cfg, iface, queue, backend
        try:
            if choice == "1":
                iface = iface or _prompt("Interface (required)", iface)
                apply = _prompt_bool("Apply (write unit)?", False)
                systemd_install(apply, iface, queue, backend, cfg)
            elif choice == "2":
                apply = _prompt_bool("Apply (remove unit)?", False)
                systemd_remove(apply)
            else:
                print("[ERR] invalid selection")
        except KeyboardInterrupt:
            print("\n[WARN] interrupted")
        except Exception as exc:
            print(f"[ERR] {exc}")
        _pause()
    return cfg, iface, queue, backend


def interactive_menu() -> None:
    cfg, iface, queue, backend = _load_defaults()
    # Ensure suricata binary is present up front for interactive use.
    ensure_binaries(["suricata"])
    try:
        raw = subprocess.check_output(["suricata", "-V"], text=True).strip()
        cleaned = raw.replace("This is ", "")
        version = f"Suricata detected: {cleaned}. Applied."
    except Exception:
        version = "suricata -V failed"
    while True:
        _clear_screen()
        _print_banner()
        print()
        print(f"{version}")
        ipmap = _iface_ips()
        iface_state = "ok" if _iface_ok_with_ip(iface, ipmap) else ("missing" if iface else "blank")
        print(f"Suricata conf : {cfg} ({_cfg_status(cfg)})")
        print(f"Meercata conf : iface={iface or '<none>'} ({iface_state}) queue={queue} backend={backend}")
        print(f"service state : {_service_status()}")
        print()
        print("1) Suricata control")
        print("2) Rules / YAML")
        print("3) Hooks / firewall")
        print("4) Systemd unit")
        print("5) Set defaults (config/iface/queue/backend)")
        print("0) Quit")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            print("Bye.")
            return
        if choice == "1":
            cfg, iface, queue, backend = menu_suricata(cfg, iface, queue, backend)
        elif choice == "2":
            menu_rules(cfg, queue)
        elif choice == "3":
            cfg, iface, queue, backend = menu_hooks(cfg, iface, queue, backend)
        elif choice == "4":
            cfg, iface, queue, backend = menu_systemd(cfg, iface, queue, backend)
        elif choice == "5":
            _clear_screen()
            _print_banner()
            print()
            iface_map = _iface_ips()
            if iface_map:
                rows_if = [(name, ", ".join(ips)) for name, ips in iface_map.items()]
                print("[Interfaces with IP]")
                print(_render_table(["Interface", "IP"], rows_if))
                print()
            rows = [
                ("Suricata config", cfg, _cfg_status(cfg)),
                ("Interface", iface or "<none>", "ok" if _iface_ok_with_ip(iface, iface_map) else ("missing" if iface else "blank")),
                ("Queue", str(queue), ""),
                ("Backend", backend, backend if backend in {"auto", "xt", "nft"} else "invalid"),
            ]
            print(_render_table(["Field", "Value", "Status"], rows))
            print()
            new_cfg = _prompt("Suricata config", cfg)
            new_iface = _prompt("Interface (blank allowed)", iface)
            q_in = _prompt("Queue number", str(queue))
            new_backend = _prompt("Backend (auto/xt/nft)", backend).lower()
            # Validate inputs; keep previous on invalid.
            if Path(new_cfg).exists():
                cfg = new_cfg
            else:
                print(f"[WARN] Suricata config not found, keeping previous: {cfg}")
            if new_iface:
                if Path(f"/sys/class/net/{new_iface}").exists() and new_iface in iface_map:
                    iface = new_iface
                else:
                    print(f"[WARN] Interface {new_iface} not found or has no IP address, keeping previous: {iface or '<none>'}")
            else:
                iface = ""
            queue_parsed, q_valid = _parse_queue_input(q_in, queue)
            if q_valid:
                queue = queue_parsed
            else:
                print(f"[WARN] Invalid queue '{q_in}', keeping previous: {queue}")
            if new_backend in {"auto", "xt", "nft"}:
                backend = new_backend
            else:
                print(f"[WARN] Invalid backend '{new_backend}', keeping previous: {backend}")
            print()
            _clear_screen()
            _print_banner()
            print()
            iface_map = _iface_ips()
            rows = [
                ("Suricata config", cfg, _cfg_status(cfg)),
                ("Interface", iface or "<none>", "ok" if _iface_ok_with_ip(iface, iface_map) else ("missing" if iface else "blank")),
                ("Queue", str(queue), ""),
                ("Backend", backend, backend if backend in {"auto", "xt", "nft"} else "invalid"),
            ]
            print("[Updated defaults]")
            print(_render_table(["Field", "Value", "Status"], rows))
            cfg_state = _cfg_status(cfg)
            if cfg_state != "ok":
                print(f"[WARN] Suricata config not found: {cfg}")
            else:
                print("[OK] Defaults recorded; Suricata config path exists.")
            if not iface:
                print("[WARN] Interface is blank; IDS/IPS and systemd unit require --iface.")
            _save_defaults(cfg, iface, queue, backend)
            _pause()
        else:
            print("[ERR] unknown option")


def main() -> None:
    if len(sys.argv) == 1:
        # Interactive experience by default when no args are provided.
        interactive_menu()
        return

    args = parse_args()
    ensure_binaries(["suricata"])
    if not _queue_ok(args.queue):
        print(f"[ERR] invalid queue '{args.queue}'; must be >= 0", file=sys.stderr)
        sys.exit(1)
    if args.apply:
        if args.backend == "xt":
            ensure_binaries(["iptables"])
        elif args.backend == "nft":
            ensure_binaries(["nft"])
        else:
            ensure_binaries(["iptables"])
    if args.cmd in {"ids", "ips"} and not args.iface:
        print("[ERR] --iface is required for ids/ips", file=sys.stderr)
        sys.exit(1)
    if args.cmd in {
        "ids",
        "ips",
        "rules",
        "rule-set",
        "rule-menu",
        "yaml-summary",
        "runmode-set",
        "nfq-batchcount",
        "nfq-failopen",
        "nfq-queue",
        "unit-install",
    }:
        _require_cfg(args.config)

    if args.cmd == "ids":
        suricata_ids(args.apply, args.iface, args.config, args.queue)
    elif args.cmd == "ips":
        suricata_ips(args.apply, args.iface, args.config, args.backend, args.queue)
    elif args.cmd == "flush":
        flush_all(args.apply, args.queue, args.iface)
    elif args.cmd == "status":
        status()
    elif args.cmd == "rules":
        yaml_rules_insight(args.config)
    elif args.cmd == "rule-set":
        changed = yaml_set_rule_state(args.config, args.file, args.state)
        if changed:
            print(f"[OK] {args.file} -> {args.state}")
        else:
            print("[OK] no change needed")
    elif args.cmd == "rule-menu":
        rule_menu(args.config)
    elif args.cmd == "yaml-summary":
        yaml_summary(args.config)
    elif args.cmd == "runmode-set":
        yaml_set_runmode(args.config, args.mode)
    elif args.cmd == "nfq-batchcount":
        yaml_set_nfq_kv(args.config, "batchcount", args.value)
    elif args.cmd == "nfq-failopen":
        yaml_set_nfq_kv(args.config, "fail-open", args.value)
    elif args.cmd == "nfq-queue":
        yaml_set_nfq_kv(args.config, "queue", str(args.queue))
    elif args.cmd == "unit-install":
        print("[WARN] Experimental: enabling this unit can break boot if misconfigured. Use with caution.")
        systemd_install(args.apply, args.iface or DEFAULT_IFACE, args.queue, args.backend, args.config)
    elif args.cmd == "unit-remove":
        systemd_remove(args.apply)
    elif args.cmd == "allowlist":
        allowlist_insert(args.apply, args.direction, args.proto, args.addr, args.port)
    elif args.cmd == "backup":
        backup_rules(args.apply)
    elif args.cmd == "restore":
        restore_rules(args.apply)
    elif args.cmd == "counters":
        show_counters(args.apply)
    elif args.cmd == "monitor":
        live_monitor(args.log, SURICATAMON_BIN)
    elif args.cmd == "diag":
        diag_status(args.config, args.iface or DEFAULT_IFACE, args.queue)
    else:
        print("Unknown command", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
