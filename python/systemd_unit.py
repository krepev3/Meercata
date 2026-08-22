#!/usr/bin/env python3
"""Systemd unit and lifecycle-hook helpers."""

import os
import shlex
from pathlib import Path

from utils import run

ENV_FILE = "/etc/default/meercata"
UNIT_FILE = "/etc/systemd/system/suricata-inline.service"
HOOK_FILE = "/usr/local/sbin/meercata-inline-hook"


def _quote_env(value: str) -> str:
    return shlex.quote(value)


def render_env(iface: str, queue: int, backend: str, cfg: str, fail_mode: str = "open") -> str:
    return (
        f"IFACE={_quote_env(iface)}\n"
        f"QUEUE={queue}\n"
        f"BACKEND={_quote_env(backend)}\n"
        f"FAIL_MODE={_quote_env(fail_mode)}\n"
        f"SURICATA_CFG={_quote_env(cfg)}\n"
    )


def render_hook() -> str:
    """Return the privileged hook script used by the systemd service."""
    return r'''#!/usr/bin/env bash
set -eu

choose_backend() {
    if [ "${BACKEND:-auto}" = "auto" ]; then
        command -v nft >/dev/null 2>&1 && printf '%s\n' nft || printf '%s\n' xt
    else
        printf '%s\n' "$BACKEND"
    fi
}

xt_cleanup_tool() {
    tool="$1"
    command -v "$tool" >/dev/null 2>&1 || return 0
    for pair in 'INPUT MEERCATA_INPUT' 'OUTPUT MEERCATA_OUTPUT' 'FORWARD MEERCATA_FORWARD'; do
        set -- $pair
        while "$tool" --wait -D "$1" -m comment --comment meercata-managed -j "$2" 2>/dev/null; do :; done
        "$tool" --wait -F "$2" 2>/dev/null || true
        "$tool" --wait -X "$2" 2>/dev/null || true
    done
}

xt_setup_tool() {
    tool="$1"
    command -v "$tool" >/dev/null 2>&1 || return 0
    xt_cleanup_tool "$tool"
    for chain in MEERCATA_INPUT MEERCATA_OUTPUT MEERCATA_FORWARD; do "$tool" --wait -N "$chain"; done
    "$tool" --wait -A MEERCATA_INPUT -i lo -j ACCEPT
    "$tool" --wait -A MEERCATA_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$tool" --wait -A MEERCATA_OUTPUT -o lo -j ACCEPT
    "$tool" --wait -A MEERCATA_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    bypass=
    [ "${FAIL_MODE:-open}" = open ] && bypass=--queue-bypass
    "$tool" --wait -A MEERCATA_INPUT -i "$IFACE" -j NFQUEUE --queue-num "$QUEUE" $bypass
    "$tool" --wait -A MEERCATA_OUTPUT -o "$IFACE" -j NFQUEUE --queue-num "$QUEUE" $bypass
    "$tool" --wait -A MEERCATA_FORWARD -i "$IFACE" -j NFQUEUE --queue-num "$QUEUE" $bypass
    "$tool" --wait -A MEERCATA_FORWARD -o "$IFACE" -j NFQUEUE --queue-num "$QUEUE" $bypass
    "$tool" --wait -I INPUT 1 -m comment --comment meercata-managed -j MEERCATA_INPUT
    "$tool" --wait -I OUTPUT 1 -m comment --comment meercata-managed -j MEERCATA_OUTPUT
    "$tool" --wait -I FORWARD 1 -m comment --comment meercata-managed -j MEERCATA_FORWARD
}

nft_cleanup() {
    command -v nft >/dev/null 2>&1 && nft delete table inet meercata 2>/dev/null || true
}

nft_setup() {
    nft_cleanup
    queue_flags=
    [ "${FAIL_MODE:-open}" = open ] && queue_flags='flags bypass '
    nft -f - <<EOF
create table inet meercata
add chain inet meercata preraw { type filter hook prerouting priority raw; policy accept; }
add chain inet meercata outraw { type filter hook output priority raw; policy accept; }
add rule inet meercata preraw ct state established,related accept
add rule inet meercata outraw ct state established,related accept
add rule inet meercata preraw meta l4proto { tcp, udp, icmp, ipv6-icmp } iifname "$IFACE" queue ${queue_flags}to $QUEUE
add rule inet meercata outraw meta l4proto { tcp, udp, icmp, ipv6-icmp } oifname "$IFACE" queue ${queue_flags}to $QUEUE
EOF
}

backend="$(choose_backend)"
case "${1:-}" in
    start)
        if [ "$backend" = nft ]; then nft_setup; else xt_setup_tool iptables; xt_setup_tool ip6tables; fi
        ;;
    stop)
        if [ "$backend" = nft ]; then nft_cleanup; else xt_cleanup_tool iptables; xt_cleanup_tool ip6tables; fi
        ;;
    *) printf '%s\n' 'usage: meercata-inline-hook start|stop' >&2; exit 2 ;;
esac
'''


def render_unit() -> str:
    return f"""[Unit]
Description=Suricata Inline (NFQUEUE) managed by Meercata
After=network-online.target
Wants=network-online.target
Conflicts=suricata.service

[Service]
Type=simple
EnvironmentFile={ENV_FILE}
ExecStartPre=/usr/bin/suricata -T -c ${{SURICATA_CFG}}
ExecStartPre={HOOK_FILE} start
ExecStart=/usr/bin/suricata -c ${{SURICATA_CFG}} -q ${{QUEUE}}
ExecStopPost={HOOK_FILE} stop
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
"""


def systemd_install(
    apply: bool,
    iface: str,
    queue: int,
    backend: str,
    cfg: str,
    fail_mode: str = "open",
) -> bool:
    if not iface or backend not in {"auto", "xt", "nft"} or fail_mode not in {"open", "closed"}:
        print("[ERR] invalid systemd configuration")
        return False
    env_body = render_env(iface, queue, backend, cfg, fail_mode)
    unit_body = render_unit()
    hook_body = render_hook()
    if not apply:
        print(f"[DRY] would write {ENV_FILE}:\n{env_body}")
        print(f"[DRY] would write {HOOK_FILE}:\n{hook_body}")
        print(f"[DRY] would write {UNIT_FILE}:\n{unit_body}")
        return True
    try:
        Path(ENV_FILE).write_text(env_body, encoding="utf-8")
        Path(HOOK_FILE).write_text(hook_body, encoding="utf-8")
        os.chmod(HOOK_FILE, 0o755)
        Path(UNIT_FILE).write_text(unit_body, encoding="utf-8")
    except OSError as exc:
        print(f"[ERR] cannot install systemd files: {exc}")
        return False
    ok = run(["systemctl", "daemon-reload"], apply=True)
    ok = run(["systemctl", "enable", "--now", Path(UNIT_FILE).name], apply=True) and ok
    if ok:
        print("[OK] systemd unit installed and enabled")
    return ok


def systemd_remove(apply: bool) -> bool:
    if not apply:
        print(f"[DRY] would remove {ENV_FILE}, {HOOK_FILE}, and {UNIT_FILE}")
        return True
    run(["systemctl", "disable", "--now", Path(UNIT_FILE).name], apply=True, ignore_errors=True)
    ok = True
    for filename in (ENV_FILE, HOOK_FILE, UNIT_FILE):
        try:
            Path(filename).unlink(missing_ok=True)
        except OSError as exc:
            print(f"[ERR] cannot remove {filename}: {exc}")
            ok = False
    ok = run(["systemctl", "daemon-reload"], apply=True) and ok
    if ok:
        print("[OK] systemd unit removed")
    return ok
