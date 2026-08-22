#!/usr/bin/env python3
"""Operating-system integration shared by Meercata modules."""

from __future__ import annotations

import ipaddress
import mmap
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple


IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
PROJECT_DIR = Path(__file__).resolve().parent


def _windows_suricata_homes() -> list[Path]:
    homes: list[Path] = []
    configured = os.environ.get("SURICATA_HOME", "").strip()
    if configured:
        homes.append(Path(configured).expanduser())
    for parent in (PROJECT_DIR, *PROJECT_DIR.parents[:4]):
        homes.append(parent)
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    homes.append(Path(program_files) / "Suricata")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "").strip()
    if program_files_x86:
        homes.append(Path(program_files_x86) / "Suricata")
    unique: list[Path] = []
    seen: set[str] = set()
    for home in homes:
        key = os.path.normcase(os.path.abspath(str(home)))
        if key not in seen:
            unique.append(home)
            seen.add(key)
    return unique


def suricata_executable() -> Optional[str]:
    """Find Suricata from configuration, PATH, or standard Windows locations."""
    configured = os.environ.get("SURICATA_BIN", "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path.resolve())
        found = shutil.which(configured)
        if found:
            return found
    for name in (("suricata.exe", "suricata") if IS_WINDOWS else ("suricata",)):
        found = shutil.which(name)
        if found:
            return found
    if IS_WINDOWS:
        for home in _windows_suricata_homes():
            candidate = home / "suricata.exe"
            if candidate.is_file():
                return str(candidate.resolve())
    return None


def suricata_command() -> str:
    """Return an executable path, retaining a useful dry-run fallback."""
    return suricata_executable() or ("suricata.exe" if IS_WINDOWS else "suricata")


def npcap_directory() -> Optional[Path]:
    if not IS_WINDOWS:
        return None
    candidates = []
    configured = os.environ.get("NPCAP_DIR", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates.extend(
        [
            system_root / "System32" / "Npcap",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Npcap",
        ]
    )
    for candidate in candidates:
        if (candidate / "wpcap.dll").is_file():
            return candidate.resolve()
    return None


def npcap_admin_only() -> Optional[bool]:
    """Return Npcap's administrator-only setting when it can be read."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg
    except ImportError:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AdminOnly")
    except OSError:
        return None
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return None


def suricata_env(executable: Optional[str] = None) -> dict[str, str]:
    """Build a child-only environment that can load Suricata and Npcap DLLs."""
    env = os.environ.copy()
    if not IS_WINDOWS:
        return env
    additions: list[str] = []
    binary = executable or suricata_executable()
    if binary and Path(binary).is_file():
        additions.append(str(Path(binary).resolve().parent))
    npcap = npcap_directory()
    if npcap:
        additions.append(str(npcap))
    current = env.get("PATH", "")
    existing = {os.path.normcase(part) for part in current.split(os.pathsep) if part}
    additions = [part for part in additions if os.path.normcase(part) not in existing]
    if additions:
        env["PATH"] = os.pathsep.join([*additions, current])
    return env


def suricata_working_directory(executable: Optional[str] = None) -> Optional[str]:
    if not IS_WINDOWS:
        return None
    binary = executable or suricata_executable()
    if binary and Path(binary).is_file():
        return str(Path(binary).resolve().parent)
    return None


def default_suricata_config() -> str:
    if not IS_WINDOWS:
        return "/etc/suricata/suricata.yaml"
    for home in _windows_suricata_homes():
        candidate = home / "suricata.yaml"
        if candidate.is_file():
            return str(candidate.resolve())
    return str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Suricata" / "suricata.yaml")


def default_eve_log() -> str:
    configured = os.environ.get("SURICATA_EVE", "").strip()
    if configured:
        return configured
    if not IS_WINDOWS:
        return "/var/log/suricata/eve.json"
    config = Path(default_suricata_config())
    return str(config.parent / "log" / "eve.json")


def default_defaults_store() -> Path:
    if not IS_WINDOWS:
        return Path.home() / ".meercata_defaults.json"
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Meercata"
    return base / "defaults.json"


def binary_feature_enabled(feature: str, executable: Optional[str] = None) -> Optional[bool]:
    """Read a build-info marker without executing an untrusted or broken binary."""
    path = Path(executable or suricata_executable() or "")
    if not path.is_file():
        return None
    raw_needle = f"{feature} enabled:".encode("ascii", errors="ignore")
    needle = raw_needle.lower()
    try:
        with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
            pos = image.find(raw_needle)
            if pos < 0:
                pos = image.find(needle)
            if pos < 0:
                return None
            marker = bytes(image[pos : pos + len(needle) + 80]).replace(b"\x00", b" ").lower()
    except (OSError, ValueError):
        return None
    result = re.search(re.escape(needle) + rb"\s*(yes|no)", marker)
    return None if result is None else result.group(1) == b"yes"


def suricata_version_hint(executable: Optional[str] = None) -> str:
    path = Path(executable or suricata_executable() or "")
    if not path.is_file():
        return "not found"
    if IS_WINDOWS:
        try:
            with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
                match = re.search(rb"suricata-(\d+\.\d+(?:\.\d+)?)", image, re.IGNORECASE)
                if match:
                    return match.group(1).decode("ascii")
        except (OSError, ValueError):
            pass
    return str(path)


def npcap_status() -> Tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "Npcap is a Windows dependency"
    directory = npcap_directory()
    if not directory:
        return False, "wpcap.dll was not found in an Npcap directory"
    try:
        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            text=True,
            capture_output=True,
            timeout=5,
        )
        output = f"{result.stdout}\n{result.stderr}".upper()
        running = result.returncode == 0 and "RUNNING" in output
    except (OSError, subprocess.SubprocessError):
        running = False
    access = npcap_admin_only()
    access_detail = "; administrator-only capture access" if access is True else ""
    detail = f"{directory} ({'driver running' if running else 'driver not running'}{access_detail})"
    return running, detail


def is_administrator() -> bool:
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def capture_interfaces() -> Dict[str, list[str]]:
    """Return capture target -> display details for the current OS."""
    if not IS_WINDOWS:
        result: Dict[str, list[str]] = {}
        for family in ("-4", "-6"):
            try:
                output = subprocess.check_output(["ip", "-o", family, "addr", "show"], text=True)
            except (OSError, subprocess.CalledProcessError):
                continue
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    result.setdefault(parts[1], []).append(parts[3].split("/")[0])
        return result

    result: Dict[str, list[str]] = {}
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError):
        return result
    adapter = "Windows adapter"
    for raw_line in output.splitlines():
        line = raw_line.strip()
        header = re.match(r".+? adapter (.+):$", line, re.IGNORECASE)
        if header:
            adapter = header.group(1).strip()
            continue
        address_match = re.search(
            r"(?:IPv4 Address|Autoconfiguration IPv4 Address|IPv6 Address)\s*[^:]*:\s*([0-9A-Fa-f:.]+)",
            line,
            re.IGNORECASE,
        )
        if not address_match:
            continue
        address = address_match.group(1).rstrip(".")
        try:
            ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            continue
        result.setdefault(address, []).append(adapter)
    return result


_NPF_TARGET = re.compile(
    r"^(?:\\\\Device\\\\NPF_|\\Device\\NPF_)?\{[0-9A-Fa-f-]{36}\}$",
    re.IGNORECASE,
)


def valid_capture_target(target: str, require_present: bool = True) -> bool:
    if not target or "\x00" in target:
        return False
    if not IS_WINDOWS:
        return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", target)) and (
            not require_present or Path(f"/sys/class/net/{target}").exists()
        )
    try:
        ipaddress.ip_address(target.split("%", 1)[0])
        return not require_present or target in capture_interfaces()
    except ValueError:
        pass
    if _NPF_TARGET.fullmatch(target):
        return True
    return False


def platform_name() -> str:
    if IS_WINDOWS:
        return "Windows"
    if IS_LINUX:
        return "Linux"
    return sys.platform
