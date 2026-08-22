#!/usr/bin/env python3
"""Runtime requirement and command preflight checks for Meercata."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from platform_support import (
    IS_LINUX,
    IS_WINDOWS,
    binary_feature_enabled,
    is_administrator,
    npcap_admin_only,
    npcap_status,
    platform_name,
    suricata_env,
    suricata_executable,
    suricata_version_hint,
    valid_capture_target,
)


MIN_PYTHON = (3, 10)
PRIVILEGED_COMMANDS = {
    "ids",
    "ips",
    "flush",
    "unit-install",
    "unit-remove",
    "allowlist",
    "backup",
    "restore",
}
YAML_WRITE_COMMANDS = {
    "rule-set",
    "rule-menu",
    "rule-add",
    "af-packet-set",
    "runmode-set",
    "nfq-batchcount",
    "nfq-failopen",
    "nfq-queue",
}
CONFIG_COMMANDS = {
    "ids",
    "ips",
    "rules",
    "rule-set",
    "rule-menu",
    "rule-add",
    "af-packet-set",
    "yaml-summary",
    "runmode-set",
    "nfq-batchcount",
    "nfq-failopen",
    "nfq-queue",
    "unit-install",
}
LINUX_ONLY_COMMANDS = {
    "flush",
    "unit-install",
    "unit-remove",
    "allowlist",
    "backup",
    "restore",
    "counters",
}


@dataclass(frozen=True)
class Requirement:
    name: str
    ok: bool
    required: bool
    detail: str

    @property
    def state(self) -> str:
        if self.ok:
            return "OK"
        return "MISSING" if self.required else "OPTIONAL"


def _binary(name: str, required: bool) -> Requirement:
    path = shutil.which(name)
    return Requirement(name, bool(path), required, path or "not found in PATH")


def _suricata(
    required: bool,
    require_inline: bool,
    report_inline: bool = False,
    require_runtime: bool = False,
    report_runtime: bool = False,
) -> List[Requirement]:
    path = suricata_executable()
    inline_name = "Suricata WinDivert support" if IS_WINDOWS else "Suricata NFQ support"
    if not path:
        checks = [Requirement("suricata", False, required, "not found")]
        if require_inline or report_inline:
            checks.append(Requirement(inline_name, False, require_inline, "cannot check without Suricata"))
        return checks

    detail = path
    if IS_WINDOWS:
        detail = f"{path} - version {suricata_version_hint(path)}"
    else:
        try:
            result = subprocess.run([path, "-V"], text=True, capture_output=True, timeout=5)
            version = (result.stdout or result.stderr).strip().replace("\n", " ")
            if version:
                detail = f"{path} - {version}"
        except (OSError, subprocess.SubprocessError):
            pass
    checks = [Requirement("suricata", True, required, detail)]

    if IS_WINDOWS and (require_runtime or report_runtime):
        if npcap_admin_only() is True and not is_administrator():
            runtime_ok = True
            runtime_detail = "probe deferred until elevated because Npcap restricts DLL access to administrators"
        else:
            try:
                probe = subprocess.run(
                    [path, "-V"],
                    text=True,
                    capture_output=True,
                    timeout=3,
                    env=suricata_env(path),
                    cwd=str(Path(path).parent),
                )
                probe_output = (probe.stdout or probe.stderr).strip().replace("\n", " ")
                runtime_ok = probe.returncode == 0
                runtime_detail = probe_output or f"exit status {probe.returncode}"
            except subprocess.TimeoutExpired:
                runtime_ok = False
                runtime_detail = "version probe timed out after 3 seconds"
            except OSError as exc:
                runtime_ok = False
                runtime_detail = f"could not start: {exc}"
        checks.append(Requirement("Suricata runtime", runtime_ok, require_runtime, runtime_detail))

    if IS_WINDOWS and (require_inline or report_inline):
        enabled = binary_feature_enabled("WinDivert", path)
        checks.append(
            Requirement(
                inline_name,
                enabled is True,
                require_inline,
                "enabled" if enabled else "this Suricata build reports WinDivert disabled",
            )
        )
    elif not IS_WINDOWS and (require_inline or report_inline):
        try:
            result = subprocess.run([path, "--build-info"], text=True, capture_output=True, timeout=10)
            output = f"{result.stdout}\n{result.stderr}".lower()
            inline_ok = result.returncode == 0 and (
                re.search(r"nfq(?:ueue)?\s+support:\s+yes", output) is not None
                or re.search(r"^features:.*\bnfq\b", output, re.MULTILINE) is not None
            )
            inline_detail = "enabled" if inline_ok else "NFQ support not reported as enabled"
        except (OSError, subprocess.SubprocessError) as exc:
            inline_ok = False
            inline_detail = f"check failed: {exc}"
        checks.append(Requirement(inline_name, inline_ok, require_inline, inline_detail))
    return checks


def _firewall(backend: str, required: bool) -> List[Requirement]:
    nft = shutil.which("nft")
    iptables = shutil.which("iptables")
    checks: List[Requirement] = []
    if backend == "nft":
        checks.append(Requirement("nftables backend", bool(nft), required, nft or "nft not found"))
    elif backend == "xt":
        checks.append(Requirement("iptables backend", bool(iptables), required, iptables or "iptables not found"))
    else:
        detected = nft or iptables
        selected = "nft" if nft else ("iptables" if iptables else "none")
        checks.append(Requirement("firewall backend", bool(detected), required, f"auto selected: {selected}"))
    ip6tables = shutil.which("ip6tables")
    checks.append(Requirement("IPv6 iptables support", bool(ip6tables), False, ip6tables or "ip6tables not found; IPv6 xt rules unavailable"))
    return checks


def _config_test(config: Path, required: bool) -> Requirement:
    suricata = suricata_executable()
    if not suricata:
        return Requirement("Suricata configuration test", False, required, "cannot test without Suricata")
    timeout = 10 if IS_WINDOWS else 30
    try:
        result = subprocess.run(
            [suricata, "-T", "-c", str(config)],
            text=True,
            capture_output=True,
            timeout=timeout,
            env=suricata_env(suricata),
            cwd=str(Path(suricata).parent) if IS_WINDOWS else None,
        )
    except subprocess.TimeoutExpired:
        return Requirement("Suricata configuration test", False, required, f"timed out after {timeout} seconds")
    except OSError as exc:
        return Requirement("Suricata configuration test", False, required, f"check failed: {exc}")
    output = (result.stderr or result.stdout).strip().splitlines()
    detail = output[-1] if output else ("valid" if result.returncode == 0 else "validation failed")
    return Requirement("Suricata configuration test", result.returncode == 0, required, detail)


def collect_requirements(
    command: str = "check",
    config: str = "/etc/suricata/suricata.yaml",
    backend: str = "auto",
    iface: str = "",
    apply: bool = False,
    log_path: Optional[str] = None,
    full: bool = False,
) -> List[Requirement]:
    """Collect full-environment or command-specific requirements."""
    checks = [
        Requirement(
            "Python",
            sys.version_info >= MIN_PYTHON,
            True,
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} (requires >= 3.10)",
        ),
        Requirement("Operating system", IS_WINDOWS or IS_LINUX, True, platform_name()),
    ]

    needs_suricata = full or (apply and command in ({"ids", "ips", "unit-install"} | YAML_WRITE_COMMANDS))
    require_inline = apply and command == "ips"
    if not IS_WINDOWS:
        require_inline = require_inline or full or (apply and command == "unit-install")
    require_runtime = IS_WINDOWS and apply and command in ({"ids", "ips"} | YAML_WRITE_COMMANDS)
    checks.extend(
        _suricata(
            needs_suricata,
            require_inline=require_inline,
            report_inline=full,
            require_runtime=require_runtime,
            report_runtime=IS_WINDOWS and full,
        )
    )

    if IS_WINDOWS and (full or command in {"ids", "ips", "status", "diag"}):
        npcap_ok, npcap_detail = npcap_status()
        npcap_required = full or (apply and command in {"ids", "ips"})
        checks.append(Requirement("Npcap", npcap_ok, npcap_required, npcap_detail))

    if full or command in CONFIG_COMMANDS:
        cfg = Path(config)
        cfg_required = full or command in CONFIG_COMMANDS
        exists = cfg.is_file()
        checks.append(Requirement("Suricata configuration", exists, cfg_required, str(cfg) if exists else f"missing: {cfg}"))
        readable = exists and os.access(cfg, os.R_OK)
        checks.append(Requirement("Configuration readable", readable, cfg_required, str(cfg)))
        if full and exists:
            if readable and IS_WINDOWS:
                checks.append(
                    Requirement(
                        "Suricata configuration test",
                        True,
                        False,
                        "deferred to applied IDS/IPS start on Windows",
                    )
                )
            elif readable:
                checks.append(_config_test(cfg, True))
            else:
                checks.append(Requirement("Suricata configuration test", False, not IS_WINDOWS, "configuration is not readable"))
        if apply and command in YAML_WRITE_COMMANDS:
            writable = exists and os.access(cfg, os.W_OK)
            checks.append(Requirement("Configuration writable", writable, True, str(cfg)))

    firewall_commands = {"ips", "flush", "status", "diag", "counters", "allowlist", "backup", "restore", "unit-install"}
    if not IS_WINDOWS and (full or command in firewall_commands):
        firewall_required = apply and command in {"ips", "flush", "allowlist", "backup", "restore", "unit-install"}
        checks.extend(_firewall(backend, firewall_required or full))

    if not IS_WINDOWS and (full or command in {"unit-install", "unit-remove", "status", "diag"}):
        checks.append(_binary("systemctl", apply and command in {"unit-install", "unit-remove"}))
        systemd_running = Path("/run/systemd/system").is_dir()
        checks.append(
            Requirement(
                "systemd runtime",
                systemd_running,
                apply and command in {"unit-install", "unit-remove"},
                "running" if systemd_running else "not detected",
            )
        )
    if not IS_WINDOWS and (full or command == "unit-install"):
        checks.append(_binary("bash", apply and command == "unit-install"))
    if IS_WINDOWS and command in LINUX_ONLY_COMMANDS:
        checks.append(Requirement("Linux NFQUEUE operation", False, True, f"'{command}' is available only on Linux"))
    if not IS_WINDOWS and (full or command == "backup"):
        backup_tool = shutil.which("nft") or shutil.which("iptables-save") or shutil.which("ip6tables-save")
        checks.append(
            Requirement(
                "firewall backup helper",
                bool(backup_tool),
                apply and command == "backup",
                backup_tool or "nft/iptables-save/ip6tables-save not found",
            )
        )
    if not IS_WINDOWS and (full or command == "restore"):
        restore_tool = shutil.which("nft") or shutil.which("iptables-restore") or shutil.which("ip6tables-restore")
        checks.append(
            Requirement(
                "firewall restore helper",
                bool(restore_tool),
                apply and command == "restore",
                restore_tool or "nft/iptables-restore/ip6tables-restore not found",
            )
        )

    if full:
        if IS_WINDOWS:
            checks.extend([_binary("sc.exe", False), _binary("tasklist.exe", False), _binary("taskkill.exe", False)])
        else:
            checks.extend([_binary("ip", False), _binary("pgrep", False), _binary("pkill", False), _binary("tail", False)])
        pytest_available = importlib.util.find_spec("pytest") is not None
        install_test = "py -m pip install -e .[test]" if IS_WINDOWS else "python3 -m pip install -e '.[test]'"
        checks.append(Requirement("pytest test dependency", pytest_available, False, "installed" if pytest_available else f"install with: {install_test}"))
        privileged = is_administrator()
        privilege_name = "Administrator privileges" if IS_WINDOWS else "Root privileges"
        if privileged:
            privilege_detail = "administrator" if IS_WINDOWS else "effective UID 0"
        else:
            privilege_detail = "needed only for --apply system changes"
        checks.append(Requirement(privilege_name, privileged, False, privilege_detail))

    needs_interface = command == "ids" or (not IS_WINDOWS and command in {"ips", "unit-install"})
    if needs_interface:
        valid_iface = valid_capture_target(iface)
        checks.append(Requirement("Network interface", valid_iface, True, iface or "not configured"))
    elif full:
        valid_iface = valid_capture_target(iface)
        checks.append(Requirement("Configured interface", valid_iface, False, iface or "not configured"))

    if command == "monitor" and log_path:
        log = Path(log_path)
        readable = log.is_file() and os.access(log, os.R_OK)
        checks.append(Requirement("EVE log", readable, True, str(log)))

    if apply and command in PRIVILEGED_COMMANDS:
        privileged = is_administrator()
        name = "Administrator privileges" if IS_WINDOWS else "Root privileges"
        missing_detail = "run from an elevated Command Prompt or PowerShell" if IS_WINDOWS else "effective UID 0 required"
        ok_detail = "administrator" if IS_WINDOWS else "effective UID 0"
        checks.append(Requirement(name, privileged, True, ok_detail if privileged else missing_detail))

    return checks


def required_ok(checks: Iterable[Requirement]) -> bool:
    return all(check.ok or not check.required for check in checks)


def render_requirements(checks: Iterable[Requirement]) -> str:
    rows = [(check.state, "required" if check.required else "optional", check.name, check.detail) for check in checks]
    headers = ("State", "Level", "Requirement", "Detail")
    widths = [len(value) for value in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(str(value)))

    def format_row(row):
        return " | ".join(str(value).ljust(widths[idx]) for idx, value in enumerate(row))

    separator = "-+-".join("-" * width for width in widths)
    return "\n".join([format_row(headers), separator, *(format_row(row) for row in rows)])


def requirement_suggestion(check: Requirement) -> str:
    """Return a practical remediation for an unavailable requirement."""
    suggestions = {
        "Python": "Install Python 3.10 or newer and make 'py' or 'python' available.",
        "Operating system": "Run Meercata on Windows or Linux.",
        "suricata": "Install Suricata and set SURICATA_BIN if it is outside PATH or the standard installation directory.",
        "Suricata NFQ support": "Install a Suricata package built with NFQUEUE support and libnetfilter_queue, then confirm with: suricata --build-info.",
        "Suricata WinDivert support": "Install or compile a Windows Suricata build with WinDivert enabled; passive IDS mode remains available with Npcap.",
        "Suricata runtime": "Repair or reinstall the Windows Suricata package, then confirm that 'suricata.exe -V' exits successfully.",
        "Npcap": "Install Npcap, start its npcap driver, and enable WinPcap API-compatible mode if Suricata is installed as a Windows service.",
        "Suricata configuration": "Install/reinstall Suricata or pass an existing file using --config.",
        "Configuration readable": "Run with appropriate privileges or grant the current user safe read access to the Suricata configuration.",
        "Configuration writable": "Use --apply with appropriate privileges; Meercata creates a backup before editing.",
        "Suricata configuration test": "Run Suricata with -T -c and correct the reported configuration, dependency, or permission error.",
        "firewall backend": "Install nftables or iptables (Debian/Ubuntu: sudo apt install nftables iptables).",
        "nftables backend": "Install nftables (Debian/Ubuntu: sudo apt install nftables).",
        "iptables backend": "Install iptables (Debian/Ubuntu: sudo apt install iptables).",
        "IPv6 iptables support": "Install the iptables package if IPv6 xtables inspection is required.",
        "systemctl": "Install systemd tools, or avoid the optional systemd unit commands.",
        "systemd runtime": "Boot the host with systemd before using unit-install/unit-remove, or manage Meercata manually.",
        "bash": "Install Bash (Debian/Ubuntu: sudo apt install bash).",
        "firewall backup helper": "Install nftables or iptables utilities so nft/iptables-save is available.",
        "firewall restore helper": "Install nftables or iptables utilities so nft/iptables-restore is available.",
        "ip": "Install iproute2 (Debian/Ubuntu: sudo apt install iproute2).",
        "pgrep": "Install procps (Debian/Ubuntu: sudo apt install procps).",
        "pkill": "Install procps (Debian/Ubuntu: sudo apt install procps).",
        "tail": "Install coreutils, or use the built-in Python log follower.",
        "pytest test dependency": "Install test support from this folder with the command shown in the requirement detail.",
        "Root privileges": "Re-run the applied system command with sudo after reviewing its dry-run output.",
        "Administrator privileges": "Open Command Prompt or PowerShell with Run as administrator, then repeat the applied command.",
        "Linux NFQUEUE operation": "Run this NFQUEUE/systemd command on Linux; on Windows use IDS or a WinDivert-enabled Suricata build for IPS.",
        "Network interface": "On Windows use an adapter IP address or NPF device; on Linux use a name from 'ip link show'. Supply it with --iface.",
        "Configured interface": "Set a capture target in the interactive defaults or supply --iface when running IDS.",
        "EVE log": "Enable Suricata eve-log output or supply a readable eve.json using --log.",
    }
    return suggestions.get(check.name, f"Install or configure {check.name}, then run the requirement check again.")


def render_suggestions(checks: Iterable[Requirement]) -> str:
    missing = [check for check in checks if not check.ok]
    if not missing:
        return ""
    lines = ["Suggested actions:"]
    for index, check in enumerate(missing, 1):
        lines.append(f"{index}. {check.name}: {requirement_suggestion(check)}")
    return "\n".join(lines)
