#!/usr/bin/env python3
"""NFQUEUE hook helpers, allowlist, backups, counters."""

import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import List

from utils import run


MANAGED_COMMENT = "meercata-managed"
XT_CHAINS = {
    "INPUT": "MEERCATA_INPUT",
    "OUTPUT": "MEERCATA_OUTPUT",
    "FORWARD": "MEERCATA_FORWARD",
}
NFT_TABLES = ("meercata", "suri")


def _delete_all(cmd: List[str], apply: bool) -> None:
    """Delete every occurrence of an exact rule; absence is not an error."""
    if not apply:
        run(cmd, apply=False)
        return
    while run(cmd, apply=True, ignore_errors=True):
        pass


def _remove_managed_xt(tool: str, apply: bool) -> None:
    base = [tool, "--wait"]
    for parent, managed in XT_CHAINS.items():
        _delete_all(base + ["-D", parent, "-m", "comment", "--comment", MANAGED_COMMENT, "-j", managed], apply)
        run(base + ["-F", managed], apply, ignore_errors=True)
        run(base + ["-X", managed], apply, ignore_errors=True)


def _legacy_xt_rules(tool: str, queue: int, iface: str) -> List[List[str]]:
    """Rules produced by Meercata versions before managed chains were added."""
    base = [tool, "--wait"]
    rules: List[List[str]] = []
    if iface:
        rules.extend([
            base + ["-D", "INPUT", "-i", iface, "-j", "NFQUEUE", "--queue-num", str(queue)],
            base + ["-D", "OUTPUT", "-o", iface, "-j", "NFQUEUE", "--queue-num", str(queue)],
            base + ["-D", "FORWARD", "-i", iface, "-j", "NFQUEUE", "--queue-num", str(queue)],
            base + ["-D", "FORWARD", "-o", iface, "-j", "NFQUEUE", "--queue-num", str(queue)],
        ])
    else:
        rules.extend([
            base + ["-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue)],
            base + ["-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue)],
            base + ["-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue)],
        ])
    return rules


def flush_xt(apply: bool, queue: int, iface: str) -> bool:
    tools = [tool for tool in ("iptables", "ip6tables") if shutil.which(tool)]
    for tool in tools:
        _remove_managed_xt(tool, apply)
        for rule in _legacy_xt_rules(tool, queue, iface):
            _delete_all(rule, apply)
    return True


def install_xt(apply: bool, queue: int, iface: str, fail_open: bool = True) -> bool:
    tools = [tool for tool in ("iptables", "ip6tables") if shutil.which(tool)]
    if "iptables" not in tools:
        print("[ERR] iptables not found")
        return False
    queue_flags = ["--queue-num", str(queue)] + (["--queue-bypass"] if fail_open else [])
    installed_tools: List[str] = []
    for tool in tools:
        base = [tool, "--wait"]
        _remove_managed_xt(tool, apply)
        commands: List[List[str]] = []
        for managed in XT_CHAINS.values():
            commands.append(base + ["-N", managed])
        commands.extend([
            base + ["-A", XT_CHAINS["INPUT"], "-i", "lo", "-j", "ACCEPT"],
            base + ["-A", XT_CHAINS["INPUT"], "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            base + ["-A", XT_CHAINS["OUTPUT"], "-o", "lo", "-j", "ACCEPT"],
            base + ["-A", XT_CHAINS["OUTPUT"], "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ])
        in_match = ["-i", iface] if iface else []
        out_match = ["-o", iface] if iface else []
        commands.extend([
            base + ["-A", XT_CHAINS["INPUT"], *in_match, "-j", "NFQUEUE", *queue_flags],
            base + ["-A", XT_CHAINS["OUTPUT"], *out_match, "-j", "NFQUEUE", *queue_flags],
            base + ["-A", XT_CHAINS["FORWARD"], *in_match, "-j", "NFQUEUE", *queue_flags],
        ])
        if iface:
            commands.append(base + ["-A", XT_CHAINS["FORWARD"], *out_match, "-j", "NFQUEUE", *queue_flags])
        for parent, managed in XT_CHAINS.items():
            commands.append(base + ["-I", parent, "1", "-m", "comment", "--comment", MANAGED_COMMENT, "-j", managed])
        tool_ok = True
        for cmd in commands:
            if not run(cmd, apply):
                tool_ok = False
                break
        if not tool_ok:
            for cleanup_tool in installed_tools + [tool]:
                _remove_managed_xt(cleanup_tool, apply)
            return False
        installed_tools.append(tool)
    return True


def flush_nft(apply: bool) -> bool:
    if not shutil.which("nft"):
        return True
    run(["nft", "delete", "table", "inet", "meercata"], apply, ignore_errors=True)
    # Also clean the table name used by Meercata v1.00 before managed ownership.
    run(["nft", "delete", "table", "inet", "suri"], apply, ignore_errors=True)
    return True


def flush_all(apply: bool, queue: int, iface: str) -> bool:
    """Remove NFQUEUE hooks for both iptables and nft. Returns True if all calls succeeded."""
    ok_xt = flush_xt(apply, queue, iface)
    ok_nft = flush_nft(apply)
    return bool(ok_xt and ok_nft)


def firewall_capabilities() -> List[str]:
    """Return human-readable list of detected firewall tools."""
    caps: List[str] = []
    if shutil.which("nft"):
        caps.append("nftables (nft)")
    if shutil.which("iptables"):
        caps.append("iptables (xtables)")
    if shutil.which("ip6tables"):
        caps.append("ip6tables")
    return caps


def _print_cmd_output(cmd: List[str], label: str) -> None:
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        print(f"[{label}]")
        print(out.strip() or "(empty)")
    except subprocess.CalledProcessError as exc:
        print(f"[WARN] {label} failed: {exc.output.strip() or exc}")


def _print_section(title: str) -> None:
    print(f"\n== {title} ==")


def show_firewall_rules() -> None:
    """Display current ruleset for detected firewalls in readable form."""
    if shutil.which("iptables"):
        try:
            out = subprocess.check_output(["iptables", "-vnL"], text=True, stderr=subprocess.STDOUT)
            _print_section("iptables")
            print(_format_iptables_output(out) or "(no rules)")
        except subprocess.CalledProcessError as exc:
            print(f"[WARN] iptables listing failed: {exc.output.strip() or exc}")
    if shutil.which("ip6tables"):
        try:
            out = subprocess.check_output(["ip6tables", "-vnL"], text=True, stderr=subprocess.STDOUT)
            _print_section("ip6tables")
            print(_format_iptables_output(out) or "(no rules)")
        except subprocess.CalledProcessError as exc:
            print(f"[WARN] ip6tables listing failed: {exc.output.strip() or exc}")
    if shutil.which("nft"):
        try:
            out = subprocess.check_output(["nft", "list", "table", "inet", "meercata"], text=True, stderr=subprocess.STDOUT)
            _print_section("nftables (table inet meercata)")
            print(out.strip() or "(empty)")
        except subprocess.CalledProcessError:
            try:
                out = subprocess.check_output(["nft", "list", "ruleset"], text=True, stderr=subprocess.STDOUT)
                _print_section("nftables (full ruleset)")
                print(out.strip() or "(empty)")
            except subprocess.CalledProcessError as exc:
                print(f"[WARN] nftables listing failed: {exc.output.strip() or exc}")


def existing_hooks(queue: int, iface: str) -> List[str]:
    """Return human-readable descriptions of NFQUEUE hooks present for queue/iface."""
    found: List[str] = []
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        for managed in XT_CHAINS.values():
            res = subprocess.run([tool, "-S", managed], text=True, capture_output=True)
            if res.returncode == 0 and f"--queue-num {queue}" in res.stdout:
                found.append(f"{tool} managed chain: {managed}")
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            res = subprocess.run([tool, "-S", chain], text=True, capture_output=True)
            if res.returncode != 0:
                continue
            for line in res.stdout.splitlines():
                if "NFQUEUE" not in line or f"--queue-num {queue}" not in line:
                    continue
                if iface:
                    if chain == "INPUT" and f"-i {iface}" not in line:
                        continue
                    if chain == "OUTPUT" and f"-o {iface}" not in line:
                        continue
                    if chain == "FORWARD" and f"-i {iface}" not in line and f"-o {iface}" not in line:
                        continue
                found.append(f"{tool} {chain}: {line}")
    if shutil.which("nft"):
        for table in ("meercata", "suri"):
            res = subprocess.run(["nft", "list", "table", "inet", table], text=True, capture_output=True)
            if res.returncode == 0:
                found.append(f"nft: table inet {table} present")
    return found


def install_nft(apply: bool, queue: int, iface: str, fail_open: bool = True) -> bool:
    if not shutil.which("nft"):
        print("[ERR] nft not found")
        return False
    match_in = f'iifname "{iface}"' if iface else ""
    match_out = f'oifname "{iface}"' if iface else ""
    queue_expr = f"queue {'flags bypass ' if fail_open else ''}to {queue}"
    script = f"""
create table inet meercata
add chain inet meercata preraw {{ type filter hook prerouting priority raw; policy accept; }}
add chain inet meercata outraw {{ type filter hook output     priority raw; policy accept; }}
add rule inet meercata preraw ct state established,related accept
add rule inet meercata outraw ct state established,related accept
add rule inet meercata preraw meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} {match_in} {queue_expr}
add rule inet meercata outraw meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} {match_out} {queue_expr}
"""
    return run(["nft", "-f", "-"], apply, stdin=script)


def allowlist_insert(apply: bool, direction: str, proto: str, addr: str, port: str) -> bool:
    chains = {"in": "INPUT", "out": "OUTPUT", "forward": "FORWARD"}
    if direction not in chains or proto not in {"tcp", "udp", "all"}:
        print("[ERR] invalid allowlist direction or protocol")
        return False
    if port and proto == "all":
        print("[ERR] a destination port requires tcp or udp")
        return False
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        print("[ERR] port must be between 1 and 65535")
        return False
    family = None
    if addr:
        try:
            family = ipaddress.ip_network(addr, strict=False).version
        except ValueError:
            print(f"[ERR] invalid IP/CIDR: {addr}")
            return False
    chain = chains[direction]
    flagproto = [] if proto == "all" else ["-p", proto]
    flagaddr = []
    if addr:
        flagaddr = ["-s", addr] if chain in ("INPUT", "FORWARD") else ["-d", addr]
    flagport = []
    if port:
        flagport = ["--dport", port]
    tools = []
    if family in (None, 4) and shutil.which("iptables"):
        tools.append("iptables")
    if family in (None, 6) and shutil.which("ip6tables"):
        tools.append("ip6tables")
    if not tools:
        print("[ERR] no compatible firewall tool found")
        return False
    return all(run([tool, "--wait", "-I", chain, "1", *flagproto, *flagaddr, *flagport, "-j", "ACCEPT"], apply) for tool in tools)


def backup_rules(apply: bool, directory: str = "/var/backups/meercata") -> bool:
    if not apply:
        print(f"[DRY] would backup iptables/ip6tables and Meercata nftables tables to {directory}")
        return True
    Path(directory).mkdir(parents=True, exist_ok=True)
    ok = True
    saved_any = False
    for tool, filename in (("iptables-save", "iptables.v4"), ("ip6tables-save", "iptables.v6")):
        if not shutil.which(tool):
            continue
        try:
            with (Path(directory) / filename).open("w", encoding="utf-8") as output:
                subprocess.run([tool], check=True, text=True, stdout=output)
            saved_any = True
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"[ERR] {tool} failed: {exc}")
            ok = False
    if shutil.which("nft"):
        for table in NFT_TABLES:
            nft_file = Path(directory) / f"nft-{table}.nft"
            result = subprocess.run(
                ["nft", "list", "table", "inet", table],
                text=True,
                capture_output=True,
            )
            if result.returncode == 0:
                try:
                    nft_file.write_text(result.stdout, encoding="utf-8")
                    saved_any = True
                except OSError as exc:
                    print(f"[ERR] cannot save nftables table inet {table}: {exc}")
                    ok = False
            else:
                print(f"[INFO] nftables table inet {table} is not present; skipped")
    if not saved_any:
        print("[ERR] no supported firewall rules were available to back up")
        return False
    if ok:
        print(f"[OK] saved rules to {directory}")
    return ok


def restore_rules(apply: bool, directory: str = "/var/backups/meercata") -> bool:
    ok = True
    restored_any = False
    if apply:
        v4 = Path(directory) / "iptables.v4"
        v6 = Path(directory) / "iptables.v6"
        if v4.exists():
            if shutil.which("iptables-restore"):
                with v4.open("r", encoding="utf-8") as source:
                    ok_v4 = run(["iptables-restore"], apply=True, stdin=source.read())
                print("[OK] restored IPv4 rules" if ok_v4 else "[ERR] IPv4 restore failed")
                ok = ok and ok_v4
                restored_any = restored_any or ok_v4
            else:
                print("[ERR] iptables-restore not found")
                ok = False
        else:
            print("[WARN] no IPv4 backup found")
        if v6.exists() and shutil.which("ip6tables"):
            if shutil.which("ip6tables-restore"):
                with v6.open("r", encoding="utf-8") as source:
                    ok_v6 = run(["ip6tables-restore"], apply=True, stdin=source.read())
                print("[OK] restored IPv6 rules" if ok_v6 else "[ERR] IPv6 restore failed")
                ok = ok and ok_v6
                restored_any = restored_any or ok_v6
            else:
                print("[ERR] ip6tables-restore not found")
                ok = False
        elif v6.exists():
            print("[WARN] ip6tables not present; skipped IPv6 restore")
        else:
            print("[WARN] no IPv6 backup found")
        nft_files = [(table, Path(directory) / f"nft-{table}.nft") for table in NFT_TABLES]
        present_nft_files = [(table, path) for table, path in nft_files if path.exists()]
        if present_nft_files and shutil.which("nft"):
            for table, nft_file in present_nft_files:
                with nft_file.open("r", encoding="utf-8") as source:
                    nft_body = source.read()
                check = subprocess.run(["nft", "-c", "-f", "-"], input=nft_body, text=True, capture_output=True)
                if check.returncode != 0:
                    print(f"[ERR] nftables table inet {table} backup validation failed: {(check.stderr or check.stdout).strip()}")
                    ok = False
                else:
                    run(["nft", "delete", "table", "inet", table], apply=True, ignore_errors=True)
                    ok_nft = run(["nft", "-f", "-"], apply=True, stdin=nft_body)
                    print(
                        f"[OK] restored nftables table inet {table}"
                        if ok_nft
                        else f"[ERR] nftables table inet {table} restore failed"
                    )
                    ok = ok and ok_nft
                    restored_any = restored_any or ok_nft
        elif present_nft_files:
            print("[ERR] nft backup exists but nft is not installed")
            ok = False
        if not restored_any:
            print("[ERR] no firewall backup was restored")
            ok = False
    else:
        print(f"[DRY] would restore rules from {directory}")
    return ok


def _print_counter(cmd: List[str], label: str) -> None:
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        print(f"[WARN] {label} counters failed: {exc}")
        return
    print(f"\n[{label}]")
    formatted = _format_iptables_output(out)
    print(formatted.strip() or "(no data)")


def show_counters(_apply: bool) -> None:
    # Always show counters; does not modify state.
    _print_counter(["iptables", "-vnL"], "iptables")
    if shutil.which("ip6tables"):
        _print_counter(["ip6tables", "-vnL"], "ip6tables")


def _format_iptables_output(text: str) -> str:
    lines = text.splitlines()
    sections = []
    current = None
    headers: List[str] = []
    rows: List[List[str]] = []

    def flush():
        if current is None:
            return
        parts = [f"Chain {current}"]
        if headers:
            parts.append(_render_table(headers, rows))
        else:
            parts.append(" (no rules)")
        sections.append("\n".join(parts))

    for ln in lines:
        if not ln.strip():
            continue
        if ln.startswith("Chain "):
            flush()
            current = ln
            headers = []
            rows = []
        elif not headers:
            headers = ln.split()
        else:
            rows.append(ln.split())
    flush()
    return "\n\n".join(sections)


def _render_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        if len(row) > len(widths):
            widths.extend(len(val) for val in row[len(widths):])
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))
    # If some rows are shorter, pad them
    def fmt(row: List[str]) -> str:
        padded = row + [""] * (len(widths) - len(row))
        return "|" + "|".join(f" {val.ljust(widths[i])} " for i, val in enumerate(padded)) + "|"
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, fmt(headers), sep]
    for row in rows:
        lines.append(fmt(row))
    lines.append(sep)
    return "\n".join(lines)
