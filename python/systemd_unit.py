#!/usr/bin/env python3
"""Systemd unit scaffold helpers."""

import shlex
from pathlib import Path
from utils import run

ENV_FILE = "/etc/default/meercata"
UNIT_FILE = "/etc/systemd/system/suricata-inline.service"


def _quote_env(value: str) -> str:
    # Keep values safe for EnvironmentFile parsing (POSIX shell style).
    return shlex.quote(value)


def render_env(iface: str, queue: int, backend: str, cfg: str) -> str:
    return (
        f"IFACE={_quote_env(iface)}\n"
        f"QUEUE={queue}\n"
        f"BACKEND={_quote_env(backend)}\n"
        f"SURICATA_CFG={_quote_env(cfg)}\n"
    )


def render_unit() -> str:
    return """[Unit]
Description=Suricata Inline (NFQUEUE) with pre-hook install
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/meercata
ExecStartPre=/usr/bin/env bash -c 'set -e; case "${BACKEND:-auto}" in nft) if nft list table inet suri >/dev/null 2>&1; then nft delete table inet suri; fi; nft -f - <<NF
create table inet suri
add chain inet suri preraw { type filter hook prerouting priority raw; policy accept; }
add chain inet suri outraw { type filter hook output     priority raw; policy accept; }
add rule inet suri preraw ct state established,related accept
add rule inet suri outraw ct state established,related accept
add rule inet suri preraw meta l4proto { tcp, udp, icmp, ipv6-icmp } ${IFACE:+iifname "$IFACE" } queue flags bypass to ${QUEUE:-0}
add rule inet suri outraw meta l4proto { tcp, udp, icmp, ipv6-icmp } ${IFACE:+oifname "$IFACE" } queue flags bypass to ${QUEUE:-0}
NF
;; xt) iptables --wait -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables --wait -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables --wait -I INPUT 2 -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I OUTPUT 2 -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I FORWARD 2 -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I FORWARD 2 -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; ;; auto) if command -v nft >/dev/null 2>&1; then if nft list table inet suri >/dev/null 2>&1; then nft delete table inet suri; fi; nft -f - <<NF
create table inet suri
add chain inet suri preraw { type filter hook prerouting priority raw; policy accept; }
add chain inet suri outraw { type filter hook output     priority raw; policy accept; }
add rule inet suri preraw ct state established,related accept
add rule inet suri outraw ct state established,related accept
add rule inet suri preraw meta l4proto { tcp, udp, icmp, ipv6-icmp } ${IFACE:+iifname "$IFACE" } queue flags bypass to ${QUEUE:-0}
add rule inet suri outraw meta l4proto { tcp, udp, icmp, ipv6-icmp } ${IFACE:+oifname "$IFACE" } queue flags bypass to ${QUEUE:-0}
NF
else iptables --wait -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables --wait -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables --wait -I INPUT 2 -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I OUTPUT 2 -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I FORWARD 2 -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; iptables --wait -I FORWARD 2 -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}"; fi ;; esac'
ExecStart=/usr/bin/suricata -c "${SURICATA_CFG}" -q "${QUEUE}"
ExecStopPost=/usr/bin/env bash -c 'case "${BACKEND:-auto}" in nft) nft delete table inet suri 2>/dev/null || true ;; xt) iptables --wait -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables --wait -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables --wait -D INPUT -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D OUTPUT -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D FORWARD -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D FORWARD -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; ;; auto) if command -v nft >/dev/null 2>&1; then nft delete table inet suri 2>/dev/null || true; else iptables --wait -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables --wait -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables --wait -D INPUT -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D OUTPUT -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D FORWARD -i "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; iptables --wait -D FORWARD -o "${IFACE}" -j NFQUEUE --queue-num "${QUEUE}" 2>/dev/null || true; fi ;; esac'
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def systemd_install(apply: bool, iface: str, queue: int, backend: str, cfg: str) -> None:
    env_body = render_env(iface, queue, backend, cfg)
    unit_body = render_unit()
    if apply:
        run(["bash", "-c", f"cat > {ENV_FILE}"], apply=True, stdin=env_body)
        run(["bash", "-c", f"cat > {UNIT_FILE}"], apply=True, stdin=unit_body)
        run(["systemctl", "daemon-reload"], apply=True)
        run(["systemctl", "enable", "--now", Path(UNIT_FILE).name], apply=True)
        print("[OK] systemd unit installed/enabled")
    else:
        print(f"[DRY] would write {ENV_FILE}:\n{env_body}")
        print(f"[DRY] would write {UNIT_FILE}:\n{unit_body}")


def systemd_remove(apply: bool) -> None:
    if apply:
        run(["systemctl", "disable", "--now", Path(UNIT_FILE).name], apply=True)
        run(["rm", "-f", ENV_FILE, UNIT_FILE], apply=True)
        run(["systemctl", "daemon-reload"], apply=True)
        print("[OK] systemd unit removed")
    else:
        print(f"[DRY] would remove {ENV_FILE} and {UNIT_FILE} and disable service")
