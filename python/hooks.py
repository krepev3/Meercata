#!/usr/bin/env python3
"""NFQUEUE hook helpers, allowlist, backups, counters."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from utils import run


def flush_xt(apply: bool, queue: int, iface: str) -> bool:
    base_v4 = ["iptables", "--wait"]
    base_v6 = ["ip6tables", "--wait"]
    hooks = [
        (base_v4 + ["-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue)], True),
        (base_v4 + ["-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue)], True),
        (base_v4 + ["-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue)], True),
        (base_v4 + ["-D", "INPUT", "-i", "lo", "-j", "ACCEPT"], True),
        (base_v4 + ["-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], True),
        (base_v4 + ["-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], True),
        (base_v4 + ["-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], True),
        (base_v6 + ["-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue)], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue)], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue)], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "INPUT", "-i", "lo", "-j", "ACCEPT"], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], shutil.which("ip6tables") is not None),
        (base_v6 + ["-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], shutil.which("ip6tables") is not None),
    ]
    if iface:
        hooks.extend([
            (base_v4 + ["-D", "FORWARD", "-i", iface, "-j", "NFQUEUE", "--queue-num", str(queue)], True),
            (base_v4 + ["-D", "FORWARD", "-o", iface, "-j", "NFQUEUE", "--queue-num", str(queue)], True),
            (base_v6 + ["-D", "FORWARD", "-i", iface, "-j", "NFQUEUE", "--queue-num", str(queue)], shutil.which("ip6tables") is not None),
            (base_v6 + ["-D", "FORWARD", "-o", iface, "-j", "NFQUEUE", "--queue-num", str(queue)], shutil.which("ip6tables") is not None),
        ])
    ok = True
    for h, enabled in hooks:
        if not enabled:
            continue
        if not run(h, apply, ignore_errors=True):
            ok = False
    return ok


def install_xt(apply: bool, queue: int, iface: str) -> bool:
    base_v4 = ["iptables", "--wait"]
    base_v6 = ["ip6tables", "--wait"]
    nfq_flags = ["--queue-num", str(queue)]
    cmds: List[List[str]] = [
        base_v4 + ["-I", "INPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        base_v4 + ["-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        base_v4 + ["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
        base_v4 + ["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
    ]
    cmds_v6: List[List[str]] = []
    if shutil.which("ip6tables"):
        cmds_v6 = [
            base_v6 + ["-I", "INPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            base_v6 + ["-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            base_v6 + ["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
            base_v6 + ["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
        ]
    if iface:
        cmds.extend([
            base_v4 + ["-I", "INPUT", "2", "-i", iface, "-j", "NFQUEUE", *nfq_flags],
            base_v4 + ["-I", "OUTPUT", "2", "-o", iface, "-j", "NFQUEUE", *nfq_flags],
            base_v4 + ["-I", "FORWARD", "2", "-i", iface, "-j", "NFQUEUE", *nfq_flags],
            base_v4 + ["-I", "FORWARD", "2", "-o", iface, "-j", "NFQUEUE", *nfq_flags],
        ])
        if cmds_v6:
            cmds_v6.extend([
                base_v6 + ["-I", "INPUT", "2", "-i", iface, "-j", "NFQUEUE", *nfq_flags],
                base_v6 + ["-I", "OUTPUT", "2", "-o", iface, "-j", "NFQUEUE", *nfq_flags],
                base_v6 + ["-I", "FORWARD", "2", "-i", iface, "-j", "NFQUEUE", *nfq_flags],
                base_v6 + ["-I", "FORWARD", "2", "-o", iface, "-j", "NFQUEUE", *nfq_flags],
            ])
    else:
        cmds.extend([
            base_v4 + ["-I", "INPUT", "2", "-j", "NFQUEUE", *nfq_flags],
            base_v4 + ["-I", "OUTPUT", "2", "-j", "NFQUEUE", *nfq_flags],
            base_v4 + ["-I", "FORWARD", "2", "-j", "NFQUEUE", *nfq_flags],
        ])
        if cmds_v6:
            cmds_v6.extend([
                base_v6 + ["-I", "INPUT", "2", "-j", "NFQUEUE", *nfq_flags],
                base_v6 + ["-I", "OUTPUT", "2", "-j", "NFQUEUE", *nfq_flags],
                base_v6 + ["-I", "FORWARD", "2", "-j", "NFQUEUE", *nfq_flags],
            ])
    ok = True
    for c in cmds + cmds_v6:
        if not run(c, apply):
            ok = False
    return ok


def flush_nft(apply: bool) -> bool:
    if not shutil.which("nft"):
        return True
    return run(["nft", "delete", "table", "inet", "suri"], apply, ignore_errors=True)


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
            out = subprocess.check_output(["nft", "list", "table", "inet", "suri"], text=True, stderr=subprocess.STDOUT)
            _print_section("nftables (table inet suri)")
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
    if shutil.which("iptables"):
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            res = subprocess.run(["iptables", "-S", chain], text=True, capture_output=True)
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
                found.append(f"iptables {chain}: {line}")
    if shutil.which("nft"):
        res = subprocess.run(["nft", "list", "table", "inet", "suri"], text=True, capture_output=True)
        if res.returncode == 0:
            found.append("nft: table inet suri present")
    return found


def install_nft(apply: bool, queue: int, iface: str) -> bool:
    if not shutil.which("nft"):
        print("[ERR] nft not found")
        return False
    match_in = f'iifname "{iface}"' if iface else ""
    match_out = f'oifname "{iface}"' if iface else ""
    script = f"""
create table inet suri
add chain inet suri preraw {{ type filter hook prerouting priority raw; policy accept; }}
add chain inet suri outraw {{ type filter hook output     priority raw; policy accept; }}
add rule inet suri preraw ct state established,related accept
add rule inet suri outraw ct state established,related accept
add rule inet suri preraw meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} {match_in} queue flags bypass to {queue}
add rule inet suri outraw meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} {match_out} queue flags bypass to {queue}
"""
    return run(["nft", "-f", "-"], apply, stdin=script)


def allowlist_insert(apply: bool, direction: str, proto: str, addr: str, port: str) -> None:
    chain = {"in": "INPUT", "out": "OUTPUT", "forward": "FORWARD"}.get(direction, "INPUT")
    flagproto = [] if proto == "all" else ["-p", proto]
    flagaddr = []
    if addr:
        flagaddr = ["-s", addr] if chain in ("INPUT", "FORWARD") else ["-d", addr]
    flagport = []
    if port:
        flagport = ["--dport", port]
    cmd = ["iptables", "--wait", "-I", chain, "1", *flagproto, *flagaddr, *flagport, "-j", "ACCEPT"]
    run(cmd, apply)
    if shutil.which("ip6tables"):
        cmd6 = ["ip6tables", "--wait", "-I", chain, "1", *flagproto, *flagaddr, *flagport, "-j", "ACCEPT"]
        run(cmd6, apply)


def backup_rules(apply: bool, directory: str = "/var/backups/meercata") -> None:
    if not apply:
        print(f"[DRY] would backup iptables/ip6tables to {directory}")
        return
    Path(directory).mkdir(parents=True, exist_ok=True)
    run(["iptables-save"], apply=True, stdin=None)
    run(["bash", "-c", f"iptables-save > {os.path.join(directory, 'iptables.v4')}"], apply=True)
    if shutil.which("ip6tables"):
        run(["bash", "-c", f"ip6tables-save > {os.path.join(directory, 'iptables.v6')}"], apply=True)
    print(f"[OK] saved rules to {directory}")


def restore_rules(apply: bool, directory: str = "/var/backups/meercata") -> None:
    if apply:
        v4 = Path(directory) / "iptables.v4"
        v6 = Path(directory) / "iptables.v6"
        if v4.exists():
            run(["bash", "-c", f"iptables-restore < {v4}"], apply=True)
            print("[OK] restored IPv4 rules")
        else:
            print("[WARN] no IPv4 backup found")
        if v6.exists() and shutil.which("ip6tables"):
            run(["bash", "-c", f"ip6tables-restore < {v6}"], apply=True)
            print("[OK] restored IPv6 rules")
        elif v6.exists():
            print("[WARN] ip6tables not present; skipped IPv6 restore")
        else:
            print("[WARN] no IPv6 backup found")
    else:
        print(f"[DRY] would restore rules from {directory}")


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
