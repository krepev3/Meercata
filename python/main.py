#!/usr/bin/env python3
"""Meercata Python port (modular).

Default: dry-run (prints commands). Use --apply to execute.
Requires root for --apply when touching firewall/system services.
"""

import argparse
import json
import os
import re
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
from preflight import collect_requirements, render_requirements, render_suggestions, required_ok
from suricata_ctl import (
    follow_evidence_log,
    live_monitor,
    service_status,
    status,
    suricata_ids,
    suricata_ips,
    suricata_processes,
)
from systemd_unit import systemd_install, systemd_remove
from platform_support import (
    IS_WINDOWS,
    capture_interfaces,
    default_defaults_store,
    default_eve_log,
    default_suricata_config,
    suricata_executable,
    suricata_version_hint,
    valid_capture_target,
)
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

DEFAULT_CFG = os.environ.get("SURICATA_CFG", default_suricata_config())
try:
    DEFAULT_QUEUE = int(os.environ.get("QUEUE", "0"))
except ValueError:
    DEFAULT_QUEUE = 0
if not 0 <= DEFAULT_QUEUE <= 65535:
    DEFAULT_QUEUE = 0
DEFAULT_BACKEND = os.environ.get("BACKEND", "auto")  # auto|xt|nft
if DEFAULT_BACKEND not in {"auto", "xt", "nft", "windivert"}:
    DEFAULT_BACKEND = "auto"
DEFAULT_IFACE = os.environ.get("IFACE", "")
DEFAULT_FAIL_MODE = os.environ.get("FAIL_MODE", "open").lower()
if DEFAULT_FAIL_MODE not in {"open", "closed"}:
    DEFAULT_FAIL_MODE = "open"
SURICATAMON_BIN = os.environ.get("SURICATAMON_BIN", "builtin")
DEFAULT_WINDIVERT_FILTER = os.environ.get("WINDIVERT_FILTER", "true")
DEFAULT_TRIGGER_LOG = os.environ.get(
    "MEERCATA_TRIGGER_LOG",
    os.environ.get("MEERCATA_DROP_LOG", "./Trigger Drop-Alert.txt"),
)
DEFAULT_STORE = default_defaults_store()

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


def _command_ready(
    command: str,
    cfg: str = DEFAULT_CFG,
    backend: str = DEFAULT_BACKEND,
    iface: str = "",
    apply: bool = False,
    log_path: str | None = None,
) -> bool:
    checks = collect_requirements(
        command=command,
        config=cfg,
        backend=backend,
        iface=iface,
        apply=apply,
        log_path=log_path,
    )
    failures = [check for check in checks if check.required and not check.ok]
    if failures:
        print("[ERR] requirement check failed:")
        print(render_requirements(failures))
        print()
        print(render_suggestions(failures))
        return False
    return True


def startup_requirement_check(cfg: str, backend: str, iface: str) -> bool:
    """Run the mandatory full preflight before opening interactive Meercata."""
    checks = collect_requirements(
        command="check",
        config=cfg,
        backend=backend,
        iface=iface,
        full=True,
    )
    failures = [check for check in checks if check.required and not check.ok]
    if failures:
        print("[ERR] Meercata cannot start because required items are unavailable:")
        print(render_requirements(failures))
        print()
        print(render_suggestions(failures))
        launcher = "meercata.cmd check" if IS_WINDOWS else "python3 main.py check"
        print(f"\nRun '{launcher}' after resolving the items above.")
        return False
    print("[OK] Startup requirements satisfied.")
    return True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Meercata Python port (modular)")
    p.add_argument("--config", default=DEFAULT_CFG, help="suricata.yaml path")
    p.add_argument("--iface", default=DEFAULT_IFACE, help="capture target (required for IDS; also Linux IPS)")
    p.add_argument("--queue", type=int, default=DEFAULT_QUEUE, help="NFQUEUE number")
    p.add_argument("--backend", default=DEFAULT_BACKEND, choices=["auto", "xt", "nft", "windivert"], help="Linux firewall backend; Windows selects WinDivert automatically")
    p.add_argument("--fail-mode", default=DEFAULT_FAIL_MODE, choices=["open", "closed"], help="traffic behavior when no NFQUEUE listener exists")
    p.add_argument("--windivert-filter", default=DEFAULT_WINDIVERT_FILTER, help="Windows IPS WinDivert filter")
    p.add_argument("--forward", action="store_true", help="use WinDivert forwarding layer for Windows gateway IPS")
    p.add_argument("--apply", action="store_true", help="apply system and non-interactive YAML changes (otherwise dry-run)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ids", help="start Suricata in IDS mode")
    sub.add_parser("ips", help="start Suricata inline (NFQUEUE on Linux, WinDivert on Windows)")
    sub.add_parser("flush", help="flush NFQUEUE hooks")
    sub.add_parser("status", help="show Suricata service, process, and capture status")
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
    unit = sub.add_parser("unit-install", help="install systemd unit for inline mode (Linux only)")
    unit.add_argument("--iface", required=True, help="interface")
    unit.add_argument("--queue", type=int, required=True, help="NFQUEUE number")
    unit.add_argument("--backend", choices=["auto", "xt", "nft"], default=DEFAULT_BACKEND, help="backend preference")
    unit.add_argument("--fail-mode", choices=["open", "closed"], default=DEFAULT_FAIL_MODE, help="traffic behavior when Suricata is unavailable")
    sub.add_parser("unit-remove", help="remove systemd unit (Linux only)")
    allow = sub.add_parser("allowlist", help="insert allowlist rule before NFQUEUE")
    allow.add_argument("--direction", choices=["in", "out", "forward"], default="in")
    allow.add_argument("--proto", choices=["tcp", "udp", "all"], default="all")
    allow.add_argument("--addr", default="", help="IP/CIDR to allow")
    allow.add_argument("--port", default="", help="destination port (optional)")
    sub.add_parser("backup", help="backup iptables/ip6tables rules")
    sub.add_parser("restore", help="restore iptables/ip6tables rules")
    sub.add_parser("counters", help="show iptables/ip6tables counters")
    monitor = sub.add_parser("monitor", help="launch suricatamon or tail eve.json")
    monitor.add_argument("--log", default=default_eve_log())
    monitor.add_argument(
        "--trigger-log",
        "--drop-log",
        dest="trigger_log",
        default=DEFAULT_TRIGGER_LOG,
        help="append alerts and actual drops to this hunting-evidence text file; use an empty value to disable",
    )
    sub.add_parser("diag", help="show combined Suricata and platform diagnostics")
    sub.add_parser("check", help="check runtime requirements and show missing dependencies")
    return p.parse_args()


def rule_menu(cfg: str, apply: bool = True) -> None:
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
        if not _command_ready("rule-menu", cfg=cfg, apply=apply):
            continue
        changed = yaml_set_rule_state(cfg, target_name, desired, apply=apply)
        if changed:
            print(f"[{'OK' if apply else 'DRY'}] {target_name} -> {desired}")
        else:
            print("[OK] no change needed")
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
    os.system("cls" if IS_WINDOWS else "clear")


def _cfg_status(cfg: str) -> str:
    p = Path(cfg)
    return "ok" if p.exists() else "missing"


def _iface_ips() -> dict:
    """Return capture target -> address/details for the current platform."""
    return capture_interfaces()


def _iface_ok(iface: str) -> bool:
    return valid_capture_target(iface)


def _iface_ok_with_ip(iface: str, ipmap: dict) -> bool:
    return _iface_ok(iface) and (not IS_WINDOWS or iface in ipmap or "NPF_" in iface.upper())


def _queue_ok(queue: int) -> bool:
    return 0 <= queue <= 65535


def _parse_queue_input(raw: str, fallback: int) -> Tuple[int, bool]:
    """Parse queue input from user, returning (value, valid)."""
    stripped = raw.strip()
    if stripped.isdigit():
        val = int(stripped)
        if _queue_ok(val):
            return val, True
    return fallback, False


def diag_status(cfg: str, iface: str, queue: int) -> None:
    if IS_WINDOWS:
        print("[Diag] Suricata Windows service:", _service_status())
    else:
        print("[Diag] Suricata service (standard):", _service_status("suricata.service"))
        print("[Diag] Meercata inline service:", _service_status("suricata-inline.service"))
    processes = suricata_processes()
    if processes:
        print("[Diag] Suricata processes:")
        for process in processes:
            print(f"  - {process}")
    else:
        print("[Diag] Suricata processes: none")
    if IS_WINDOWS:
        print("[Diag] Capture backend: Npcap/pcap; WinDivert is used only by supported IPS builds")
    else:
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
            cfg = str(data.get("config", DEFAULT_CFG))
            iface = str(data.get("iface", DEFAULT_IFACE))
            queue = int(data.get("queue", DEFAULT_QUEUE))
            backend = str(data.get("backend", DEFAULT_BACKEND)).lower()
            if not _queue_ok(queue):
                queue = DEFAULT_QUEUE
            if backend not in {"auto", "xt", "nft", "windivert"}:
                backend = DEFAULT_BACKEND
            if iface and not valid_capture_target(iface, require_present=False):
                iface = DEFAULT_IFACE
            return cfg, iface, queue, backend
        except Exception:
            return DEFAULT_CFG, DEFAULT_IFACE, DEFAULT_QUEUE, DEFAULT_BACKEND
    return DEFAULT_CFG, DEFAULT_IFACE, DEFAULT_QUEUE, DEFAULT_BACKEND


def _save_defaults(cfg: str, iface: str, queue: int, backend: str) -> None:
    try:
        DEFAULT_STORE.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_STORE.write_text(json.dumps({"config": cfg, "iface": iface, "queue": queue, "backend": backend}))
    except Exception:
        pass


def _service_status(unit: str = "suricata.service") -> str:
    return service_status(unit)


def launch_eve_monitor(cfg: str, backend: str, iface: str) -> None:
    """Prompt for evidence paths and run the EVE-to-evidence collector."""
    log = _prompt("EVE log path", default_eve_log())
    trigger_log = _prompt("Alert/drop evidence log (type 'off' to disable)", DEFAULT_TRIGGER_LOG)
    if trigger_log.lower() in {"off", "none", "-"}:
        trigger_log = ""
    processes = suricata_processes()
    if not processes:
        print("[WARN] No Suricata process detected; monitoring will wait for new EVE events.")
    if _command_ready("monitor", cfg, backend, iface, log_path=log):
        if trigger_log:
            print(f"[INFO] Evidence log: {Path(trigger_log).resolve()}")
        print("[INFO] EVE monitoring and evidence collection will continue until Ctrl+C.")
        live_monitor(log, SURICATAMON_BIN, trigger_log_path=trigger_log)


def launch_threat_monitor() -> None:
    """Follow the readable threat-evidence file from the main menu."""
    trigger_log = _prompt("Threat evidence log", DEFAULT_TRIGGER_LOG)
    follow_evidence_log(trigger_log, lines=100)


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
        print("2) IPS (WinDivert inline)" if IS_WINDOWS else "2) IPS (NFQUEUE inline)")
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
                if _command_ready("ids", cfg, backend, iface, apply):
                    suricata_ids(apply, iface, cfg, queue)
            elif choice == "2":
                if not IS_WINDOWS:
                    ipmap = _iface_ips()
                    if not _iface_ok_with_ip(iface, ipmap):
                        iface = _prompt("Interface (required)", iface)
                apply = _prompt_bool("Apply (execute commands)?", False)
                if _command_ready("ips", cfg, backend, iface, apply):
                    windivert_filter = DEFAULT_WINDIVERT_FILTER
                    forward = False
                    if IS_WINDOWS:
                        windivert_filter = _prompt("WinDivert filter", DEFAULT_WINDIVERT_FILTER)
                        forward = _prompt_bool("Gateway/forwarding layer?", False)
                    suricata_ips(
                        apply,
                        iface,
                        cfg,
                        backend,
                        queue,
                        DEFAULT_FAIL_MODE == "open",
                        windivert_filter,
                        forward,
                    )
            elif choice == "3":
                status()
            elif choice == "4":
                launch_eve_monitor(cfg, backend, iface)
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
                            if _command_ready("rule-set", cfg=cfg, apply=True):
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
            if not name.endswith(".rules") or Path(name).name != name or Path(name).is_absolute():
                print("[ERR] rule-file name must be a local .rules filename")
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
            if not _command_ready("rule-add", cfg=cfg, apply=True):
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
                                    if _command_ready("af-packet-set", cfg=cfg, apply=True):
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
                        if _command_ready("runmode-set", cfg=cfg, apply=True):
                            yaml_set_runmode(cfg, mode)
                    elif sub == "3":
                        val = _prompt("nfq.batchcount value", "64")
                        if _command_ready("nfq-batchcount", cfg=cfg, apply=True):
                            yaml_set_nfq_kv(cfg, "batchcount", val)
                            print()
                            yaml_summary(cfg)
                    elif sub == "4":
                        val = _prompt("nfq.fail-open (yes/no)", "no")
                        if _command_ready("nfq-failopen", cfg=cfg, apply=True):
                            yaml_set_nfq_kv(cfg, "fail-open", val)
                            print()
                            yaml_summary(cfg)
                    elif sub == "5":
                        if _command_ready("nfq-queue", cfg=cfg, apply=True):
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
                if not _command_ready("flush", cfg, backend, iface, apply):
                    _pause()
                    continue
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
                if _command_ready("allowlist", cfg, backend, iface, apply):
                    allowlist_insert(apply, direction, proto, addr, port)
            elif choice == "3":
                show_counters(True)
            elif choice == "4":
                apply = _prompt_bool("Apply (save rules)?", False)
                if _command_ready("backup", cfg, backend, iface, apply):
                    backup_rules(apply)
            elif choice == "5":
                apply = _prompt_bool("Apply (restore rules)?", False)
                if _command_ready("restore", cfg, backend, iface, apply):
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
                if _command_ready("unit-install", cfg, backend, iface, apply):
                    systemd_install(apply, iface, queue, backend, cfg, DEFAULT_FAIL_MODE)
            elif choice == "2":
                apply = _prompt_bool("Apply (remove unit)?", False)
                if _command_ready("unit-remove", cfg, backend, iface, apply):
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
    executable = suricata_executable()
    if IS_WINDOWS and executable:
        version = f"Suricata detected: {suricata_version_hint(executable)} ({executable})"
    else:
        try:
            raw = subprocess.check_output([executable or "suricata", "-V"], text=True).strip()
            cleaned = raw.replace("This is ", "")
            version = f"Suricata detected: {cleaned}."
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
        print("2) Threat Monitoring (tail evidence continuously)")
        print("3) Rules / YAML")
        print("4) Hooks / firewall (Linux only)" if IS_WINDOWS else "4) Hooks / firewall")
        print("5) Systemd unit (Linux only)" if IS_WINDOWS else "5) Systemd unit")
        print("6) Set defaults (config/iface/queue/backend)")
        print("7) Check requirements")
        print("0) Quit")
        print()
        choice = input("Select option: ").strip()
        if choice in {"0", ""}:
            print("Bye.")
            return
        if choice == "1":
            cfg, iface, queue, backend = menu_suricata(cfg, iface, queue, backend)
        elif choice == "2":
            _clear_screen()
            _print_banner()
            print()
            print("-- Threat Monitoring --")
            print("Show the last 100 evidence lines and follow new records continuously.")
            print()
            launch_threat_monitor()
            _pause()
        elif choice == "3":
            menu_rules(cfg, queue)
        elif choice == "4":
            if IS_WINDOWS:
                print("[INFO] Windows does not use Linux NFQUEUE hooks. IDS uses Npcap; IPS requires WinDivert.")
                _pause()
            else:
                cfg, iface, queue, backend = menu_hooks(cfg, iface, queue, backend)
        elif choice == "5":
            if IS_WINDOWS:
                print("[INFO] systemd unit management is available only on Linux.")
                _pause()
            else:
                cfg, iface, queue, backend = menu_systemd(cfg, iface, queue, backend)
        elif choice == "6":
            _clear_screen()
            _print_banner()
            print()
            iface_map = _iface_ips()
            if iface_map:
                rows_if = [(name, ", ".join(ips)) for name, ips in iface_map.items()]
                print("[Windows capture targets]" if IS_WINDOWS else "[Interfaces with IP]")
                headers = ["Capture target", "Adapter"] if IS_WINDOWS else ["Interface", "IP"]
                print(_render_table(headers, rows_if))
                print()
            rows = [
                ("Suricata config", cfg, _cfg_status(cfg)),
                ("Interface", iface or "<none>", "ok" if _iface_ok_with_ip(iface, iface_map) else ("missing" if iface else "blank")),
                ("Queue", str(queue), ""),
                ("Backend", backend, backend if backend in {"auto", "xt", "nft", "windivert"} else "invalid"),
            ]
            print(_render_table(["Field", "Value", "Status"], rows))
            print()
            new_cfg = _prompt("Suricata config", cfg)
            new_iface = _prompt("Interface (blank allowed)", iface)
            q_in = _prompt("Queue number", str(queue))
            backend_choices = "auto/xt/nft/windivert" if IS_WINDOWS else "auto/xt/nft"
            new_backend = _prompt(f"Backend ({backend_choices})", backend).lower()
            # Validate inputs; keep previous on invalid.
            if Path(new_cfg).exists():
                cfg = new_cfg
            else:
                print(f"[WARN] Suricata config not found, keeping previous: {cfg}")
            if new_iface:
                if _iface_ok(new_iface) and new_iface in iface_map:
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
            valid_backends = {"auto", "xt", "nft", "windivert"} if IS_WINDOWS else {"auto", "xt", "nft"}
            if new_backend in valid_backends:
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
                ("Backend", backend, backend if backend in {"auto", "xt", "nft", "windivert"} else "invalid"),
            ]
            print("[Updated defaults]")
            print(_render_table(["Field", "Value", "Status"], rows))
            cfg_state = _cfg_status(cfg)
            if cfg_state != "ok":
                print(f"[WARN] Suricata config not found: {cfg}")
            else:
                print("[OK] Defaults recorded; Suricata config path exists.")
            if not iface:
                warning = "IDS requires --iface." if IS_WINDOWS else "IDS/IPS and systemd unit require --iface."
                print(f"[WARN] Interface is blank; {warning}")
            _save_defaults(cfg, iface, queue, backend)
            _pause()
        elif choice == "7":
            checks = collect_requirements(
                command="check",
                config=cfg,
                backend=backend,
                iface=iface,
                full=True,
            )
            print(render_requirements(checks))
            print("\n[OK] Required checks passed." if required_ok(checks) else "\n[ERR] One or more required checks failed.")
            _pause()
        else:
            print("[ERR] unknown option")


def main() -> None:
    if len(sys.argv) == 1:
        cfg, iface, _, backend = _load_defaults()
        if not startup_requirement_check(cfg, backend, iface):
            sys.exit(1)
        interactive_menu()
        return

    args = parse_args()
    if not _queue_ok(args.queue):
        print(f"[ERR] invalid queue '{args.queue}'; must be between 0 and 65535", file=sys.stderr)
        sys.exit(1)
    if (args.cmd == "ids" or (args.cmd == "ips" and not IS_WINDOWS)) and not args.iface:
        needed_for = "IDS" if IS_WINDOWS else "IDS/IPS"
        print(f"[ERR] --iface is required for {needed_for}", file=sys.stderr)
        sys.exit(1)
    needs_iface = args.cmd == "ids" or (not IS_WINDOWS and args.cmd in {"ips", "unit-install"})
    if needs_iface and args.iface and not _iface_ok(args.iface):
        print(f"[ERR] interface does not exist: {args.iface}", file=sys.stderr)
        sys.exit(1)
    checks = collect_requirements(
        command=args.cmd,
        config=args.config,
        backend=args.backend,
        iface=args.iface,
        apply=args.apply,
        log_path=getattr(args, "log", None),
        full=args.cmd == "check",
    )
    if args.cmd == "check":
        print(render_requirements(checks))
        suggestions = render_suggestions(checks)
        if suggestions:
            print()
            print(suggestions)
        sys.exit(0 if required_ok(checks) else 1)
    if not required_ok(checks):
        print("[ERR] requirement check failed:", file=sys.stderr)
        failures = [check for check in checks if check.required and not check.ok]
        print(render_requirements(failures), file=sys.stderr)
        print(file=sys.stderr)
        print(render_suggestions(failures), file=sys.stderr)
        sys.exit(1)

    if args.cmd == "ids":
        if not suricata_ids(args.apply, args.iface, args.config, args.queue):
            sys.exit(1)
    elif args.cmd == "ips":
        if not suricata_ips(
            args.apply,
            args.iface,
            args.config,
            args.backend,
            args.queue,
            args.fail_mode == "open",
            args.windivert_filter,
            args.forward,
        ):
            sys.exit(1)
    elif args.cmd == "flush":
        if not flush_all(args.apply, args.queue, args.iface):
            sys.exit(1)
    elif args.cmd == "status":
        status()
    elif args.cmd == "rules":
        yaml_rules_insight(args.config)
    elif args.cmd == "rule-set":
        changed = yaml_set_rule_state(args.config, args.file, args.state, apply=args.apply)
        if changed:
            print(f"[{'OK' if args.apply else 'DRY'}] {args.file} -> {args.state}")
        else:
            print("[OK] no change needed")
    elif args.cmd == "rule-menu":
        rule_menu(args.config, apply=args.apply)
    elif args.cmd == "yaml-summary":
        yaml_summary(args.config)
    elif args.cmd == "runmode-set":
        yaml_set_runmode(args.config, args.mode, apply=args.apply)
    elif args.cmd == "nfq-batchcount":
        yaml_set_nfq_kv(args.config, "batchcount", args.value, apply=args.apply)
    elif args.cmd == "nfq-failopen":
        yaml_set_nfq_kv(args.config, "fail-open", args.value, apply=args.apply)
    elif args.cmd == "nfq-queue":
        yaml_set_nfq_kv(args.config, "queue", str(args.queue), apply=args.apply)
    elif args.cmd == "unit-install":
        print("[WARN] Experimental: enabling this unit can break boot if misconfigured. Use with caution.")
        if not systemd_install(args.apply, args.iface or DEFAULT_IFACE, args.queue, args.backend, args.config, args.fail_mode):
            sys.exit(1)
    elif args.cmd == "unit-remove":
        if not systemd_remove(args.apply):
            sys.exit(1)
    elif args.cmd == "allowlist":
        if not allowlist_insert(args.apply, args.direction, args.proto, args.addr, args.port):
            sys.exit(1)
    elif args.cmd == "backup":
        if not backup_rules(args.apply):
            sys.exit(1)
    elif args.cmd == "restore":
        if not restore_rules(args.apply):
            sys.exit(1)
    elif args.cmd == "counters":
        show_counters(args.apply)
    elif args.cmd == "monitor":
        live_monitor(args.log, SURICATAMON_BIN, trigger_log_path=args.trigger_log)
    elif args.cmd == "diag":
        diag_status(args.config, args.iface or DEFAULT_IFACE, args.queue)
    else:
        print("Unknown command", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user; exiting.", file=sys.stderr)
        sys.exit(130)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[ERR] {exc}", file=sys.stderr)
        sys.exit(1)
