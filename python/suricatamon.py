#!/usr/bin/env python3
"""Python port of the suricatamon Bash helper (colorized eve.json tail)."""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from platform_support import IS_WINDOWS, default_eve_log

COLOR = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "green": "\033[32m",
    "magenta": "\033[95m",
    "teal": "\033[96m",
    "cyan": "\033[36m",
    "gray": "\033[38;5;208m",  # repurpose "gray" slot to an orange accent
    "reset": "\033[0m",
}

DROP_ACTIONS = {"drop", "dropped", "block", "blocked", "reject", "rejected"}
DOMAIN_CACHE_LIMIT = 4096


def _c(txt: str, key: str) -> str:
    return f"{COLOR.get(key, '')}{txt}{COLOR['reset']}"


def _ipport(ip: Any, port: Any) -> str:
    ip_s = str(ip or "-")
    port_s = str(port or 0)
    return f"{ip_s}:{port_s}"


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_text(value: Any, default: str = "-") -> str:
    cleaned = re.sub(r"[\r\n\t]+", " ", str(value or "")).strip()
    return cleaned or default


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _normalized_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return ""


def event_domains(ev: Dict[str, Any]) -> List[str]:
    """Extract DNS names, TLS SNI, and HTTP hostnames carried by one EVE event."""
    domains: List[str] = []

    def add(value: Any) -> None:
        name = _clean_text(value, "")
        name = name.rstrip(".").lower()
        if name and not _is_ip(name) and name not in domains:
            domains.append(name)

    dns = ev.get("dns") if isinstance(ev.get("dns"), dict) else {}
    add(dns.get("rrname"))
    for query in dns.get("queries") or []:
        if isinstance(query, dict):
            add(query.get("rrname"))
    for answer in dns.get("answers") or []:
        if isinstance(answer, dict):
            add(answer.get("rrname"))
            add(answer.get("rdata"))
    grouped = dns.get("grouped") if isinstance(dns.get("grouped"), dict) else {}
    for values in grouped.values():
        if isinstance(values, list):
            for value in values:
                add(value)
    tls = ev.get("tls") if isinstance(ev.get("tls"), dict) else {}
    http = ev.get("http") if isinstance(ev.get("http"), dict) else {}
    add(tls.get("sni"))
    add(http.get("hostname"))
    return domains


def update_domain_cache(ev: Dict[str, Any], cache: Dict[str, List[str]]) -> None:
    """Remember observed IP-to-domain relationships for later alert enrichment."""
    domains = event_domains(ev)

    def remember(ip: Any, names: List[str]) -> None:
        ip_text = _normalized_ip(ip)
        if not ip_text or not names:
            return
        if ip_text not in cache and len(cache) >= DOMAIN_CACHE_LIMIT:
            cache.pop(next(iter(cache)))
        saved = cache.setdefault(ip_text, [])
        for name in names:
            if name not in saved:
                saved.append(name)
        del saved[8:]

    dns = ev.get("dns") if isinstance(ev.get("dns"), dict) else {}
    query_names = []
    rrname = _clean_text(dns.get("rrname"), "")
    if rrname:
        query_names.append(rrname)
    for query in dns.get("queries") or []:
        if isinstance(query, dict):
            name = _clean_text(query.get("rrname"), "")
            if name and name not in query_names:
                query_names.append(name)
    for answer in dns.get("answers") or []:
        if not isinstance(answer, dict):
            continue
        answer_name = _clean_text(answer.get("rrname"), "")
        names = [answer_name] if answer_name else query_names
        remember(answer.get("rdata"), names)
    grouped = dns.get("grouped") if isinstance(dns.get("grouped"), dict) else {}
    for record_type in ("A", "AAAA"):
        for address in grouped.get(record_type) or []:
            remember(address, query_names)

    # TLS SNI and HTTP hostname provide useful domain context even when the DNS
    # response occurred before the monitor started.
    if domains and (ev.get("tls") or ev.get("http")):
        remember(ev.get("dest_ip"), domains)


def domain_context(ev: Dict[str, Any], cache: Dict[str, List[str]]) -> List[str]:
    """Return direct and previously observed domains relevant to an event."""
    domains = event_domains(ev)
    for ip_key in ("dest_ip", "src_ip"):
        for name in cache.get(_normalized_ip(ev.get(ip_key)), []):
            if name not in domains:
                domains.append(name)
    return domains[:8]


def drop_action(ev: Dict[str, Any]) -> Optional[str]:
    """Return the normalized blocking action when EVE marks an event as dropped."""
    if str(ev.get("event_type", "")).lower() == "drop":
        return "drop"
    containers = (
        ev,
        ev.get("alert") or {},
        ev.get("flow") or {},
        ev.get("verdict") or {},
    )
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in ("action", "verdict"):
            value = container.get(key)
            if isinstance(value, str) and value.lower() in DROP_ACTIONS:
                return value.lower()
    return None


def format_drop_record(ev: Dict[str, Any]) -> Optional[str]:
    """Create an ANSI-free audit line for an event Suricata actually blocked."""
    action = drop_action(ev)
    if not action:
        return None
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    sid = _safe_int(alert.get("signature_id") or alert.get("sig_id"), 0)
    gid = _safe_int(alert.get("gid"), 1)
    rev = _safe_int(alert.get("rev"), 1)
    signature = re.sub(r"[\r\n\t]+", " ", str(alert.get("signature") or "")).strip()
    source = "[ET]" if 2000000 <= sid < 3000000 else "[RULE]"
    parts = [
        str(ev.get("timestamp", "")),
        "[DROP]",
        f"action={action}",
        f"src={_ipport(ev.get('src_ip'), ev.get('src_port'))}",
        f"dst={_ipport(ev.get('dest_ip'), ev.get('dest_port'))}",
        f"proto={ev.get('proto', '-')}",
    ]
    if signature:
        parts.extend((source, signature, f"[{gid}:{sid}:{rev}]"))
    if ev.get("app_proto"):
        parts.append(f"app={ev.get('app_proto')}")
    drop = ev.get("drop") if isinstance(ev.get("drop"), dict) else {}
    if drop.get("reason"):
        parts.append(f"reason={drop.get('reason')}")
    return " ".join(parts)


def format_alert_record(ev: Dict[str, Any]) -> Optional[str]:
    """Create an ANSI-free hunting record for every Suricata alert."""
    if str(ev.get("event_type", "")).lower() != "alert":
        return None
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    if not alert:
        return None
    sid = _safe_int(alert.get("signature_id") or alert.get("sig_id"), 0)
    gid = _safe_int(alert.get("gid"), 1)
    rev = _safe_int(alert.get("rev"), 1)
    severity = _safe_int(alert.get("severity"), 3)
    signature = re.sub(r"[\r\n\t]+", " ", str(alert.get("signature") or "-")).strip()
    category = re.sub(r"[\r\n\t]+", " ", str(alert.get("category") or "-")).strip()
    source = "[ET]" if 2000000 <= sid < 3000000 else "[RULE]"
    blocked_action = drop_action(ev)
    tag = "[DROP ALERT]" if blocked_action else "[ALERT]"
    action = blocked_action or str(alert.get("action") or "alert").lower()
    parts = [
        str(ev.get("timestamp", "")),
        tag,
        source,
        signature,
        f"[{gid}:{sid}:{rev}]",
        f"severity={severity}",
        f"category={category}",
        f"action={action}",
        f"src={_ipport(ev.get('src_ip'), ev.get('src_port'))}",
        f"dst={_ipport(ev.get('dest_ip'), ev.get('dest_port'))}",
        f"proto={ev.get('proto', '-')}",
    ]
    for key in ("app_proto", "flow_id", "in_iface", "ip_v", "pkt_src"):
        if ev.get(key) is not None:
            parts.append(f"{key}={ev.get(key)}")
    return " ".join(parts)


def format_trigger_record(
    ev: Dict[str, Any],
    domains: Optional[List[str]] = None,
    collected_at: Optional[str] = None,
) -> Optional[str]:
    """Format an alert or actual drop as a readable multi-line evidence block."""
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    action = drop_action(ev)
    if not alert and not action:
        return None

    sid = _safe_int(alert.get("signature_id") or alert.get("sig_id"), 0)
    gid = _safe_int(alert.get("gid"), 1)
    rev = _safe_int(alert.get("rev"), 1)
    severity = _safe_int(alert.get("severity"), 3) if alert else 0
    signature = _clean_text(alert.get("signature")) if alert else "-"
    category = _clean_text(alert.get("category")) if alert else "-"
    rule_source = "[ET]" if 2000000 <= sid < 3000000 else ("[RULE]" if alert else "-")
    tag = "[DROP ALERT]" if alert and action else ("[ALERT]" if alert else "[DROP]")
    effective_action = action or _clean_text(alert.get("action"), "alert").lower()
    observed_domains = domains if domains is not None else event_domains(ev)
    drop = ev.get("drop") if isinstance(ev.get("drop"), dict) else {}
    collected = collected_at or datetime.now().astimezone().isoformat(timespec="microseconds")
    separator = "=" * 88
    lines = [
        separator,
        f"Collected at    : {collected}",
        f"Event time      : {_clean_text(ev.get('timestamp'))}",
        f"Summary         : {tag} {rule_source} {signature}",
        f"Rule ID         : {gid}:{sid}:{rev}" if alert else "Rule ID         : -",
        f"Severity        : {severity}" if alert else "Severity        : -",
        f"Category        : {category}",
        f"Action          : {effective_action}",
        f"Source IP       : {_clean_text(ev.get('src_ip'))}",
        f"Source port     : {_clean_text(ev.get('src_port'))}",
        f"Destination IP  : {_clean_text(ev.get('dest_ip'))}",
        f"Destination port: {_clean_text(ev.get('dest_port'))}",
        f"DNS / Domain    : {', '.join(observed_domains) if observed_domains else 'not observed'}",
        f"Protocol        : {_clean_text(ev.get('proto'))}",
        f"App protocol    : {_clean_text(ev.get('app_proto'))}",
        f"Flow ID         : {_clean_text(ev.get('flow_id'))}",
        f"Interface       : {_clean_text(ev.get('in_iface'))}",
        f"IP version      : {_clean_text(ev.get('ip_v'))}",
        f"Packet source   : {_clean_text(ev.get('pkt_src'))}",
        f"Drop reason     : {_clean_text(drop.get('reason'))}",
        separator,
    ]
    return "\n".join(lines)


def append_trigger_record(trigger_log_path: str, record: str) -> bool:
    """Append one hunting record, returning False when logging must be disabled."""
    try:
        with open(trigger_log_path, "a", encoding="utf-8") as output:
            output.write(record + "\n")
    except OSError as exc:
        print(f"[WARN] cannot write trigger log {trigger_log_path}: {exc}; evidence logging disabled", file=sys.stderr)
        return False
    return True


def append_drop_record(drop_log_path: str, record: str) -> bool:
    """Backward-compatible alias for older integrations."""
    return append_trigger_record(drop_log_path, record)


def _color_for_alert(sig: str, category: str, classtype: str, severity: int, sid: int, gid: int) -> str:
    src_tag = "[RULE]"
    if sig.startswith("SURICATA "):
        src_tag = "[ENGINE]"
    elif 2000000 <= sid < 3000000:
        src_tag = "[ET]"
    elif 100000 <= sid < 2000000:
        src_tag = "[LOCAL]"

    sev_map = {1: "red", 2: "magenta", 3: "yellow", 4: "teal"}
    sev_key = sev_map.get(severity, "gray")
    blob = f"{sig} {category} {classtype}"
    if re.search(r"(?i)NMAP|RECON|SCAN|XMAS|NULL scan|SYN scan", blob):
        sev_key = "red"
    elif re.search(r"(?i)EXPLOIT|CVE-|LFI|RFI|RCE|SQLI|XSS|DESERIAL|XXE|CMD INJ", blob):
        sev_key = "red"
    elif re.search(r"(?i)MALWARE|TROJAN|BOTNET|C2|BEACON|RANSOM|BACKDOOR|COBALT|SLIVER|MYTHIC|EMPIRE", blob):
        sev_key = "magenta"
    elif re.search(r"(?i)POLICY|HUNTING", blob):
        sev_key = "yellow"
    elif re.search(r"(?i)INFO\b|Potential|Suspected", blob):
        sev_key = "teal"
    elif re.search(r"(?i)attempted-admin|attempted-user|attempted-recon", blob):
        sev_key = "yellow"
    return _c(f"{src_tag} {sig}", sev_key)


def _format_dns(ev: Dict[str, Any]) -> Optional[str]:
    dns = ev.get("dns") or {}
    name = dns.get("rrname") or ""
    queries = dns.get("queries") or []
    if not name and isinstance(queries, list) and queries:
        qname = queries[0].get("rrname") if isinstance(queries[0], dict) else None
        if qname:
            name = qname
    name = name or "-"
    answers: List[str] = []

    def _collect(seq: Any) -> None:
        if not isinstance(seq, list):
            return
        for ans in seq:
            if isinstance(ans, dict):
                rdata = ans.get("rdata")
                if rdata:
                    answers.append(str(rdata))
                continue
            if isinstance(ans, str):
                answers.append(ans)

    _collect(dns.get("answers", []))
    _collect(dns.get("grouped", {}).get("CNAME", []))

    answers = list(dict.fromkeys(answers))  # unique preserve order
    is_onion = re.search(r"\.onion$", name, re.IGNORECASE) is not None
    tag = _c("[DNS .onion]", "magenta") if is_onion else _c("[DNS]", "green")
    if answers:
        ans_txt = ", ".join(answers)
    elif queries:
        # If no answers, show query rrname/rrtype to retain context.
        descs = []
        for q in queries:
            if isinstance(q, dict):
                descs.append(f"{q.get('rrname','-')} ({q.get('rrtype','-')})")
        ans_txt = "; ".join(descs) if descs else "-"
    else:
        ans_txt = "-"
    return f"{ev.get('timestamp','')} {tag} {ev.get('src_ip','-')} → {name if not is_onion else _c(name,'magenta')} = {ans_txt}"


def _format_flow(ev: Dict[str, Any]) -> Optional[str]:
    flow = ev.get("flow") or {}
    action = flow.get("action")
    tag = _c("[FLOW]", "red") if action == "drop" else _c("[FLOW]", "blue")
    msg = (
        f"{_ipport(ev.get('src_ip'), ev.get('src_port'))} → {_ipport(ev.get('dest_ip'), ev.get('dest_port'))} "
        f"proto={ev.get('proto','-')} action={action or '-'}"
    )
    color = "red" if action == "drop" else "cyan"
    return f"{ev.get('timestamp','')} {tag} {_c(msg, color)}"


def _format_tls(ev: Dict[str, Any]) -> Optional[str]:
    tls = ev.get("tls")
    if not tls:
        return None
    msg = (
        f"{_ipport(ev.get('src_ip'), ev.get('src_port'))} → {_ipport(ev.get('dest_ip'), ev.get('dest_port'))} "
        f"SNI={tls.get('sni','-')} ver={tls.get('version','-')}"
    )
    return f"{ev.get('timestamp','')} {_c('[TLS]','magenta')} {_c(msg,'cyan')}"


def _format_http(ev: Dict[str, Any], wide: bool) -> Optional[str]:
    http = ev.get("http")
    if not http:
        return None
    msg = f"{ev.get('src_ip','-')} → {http.get('hostname','-')}{http.get('url','')}"
    if wide:
        msg += f" ua={http.get('http_user_agent','-')}"
    return f"{ev.get('timestamp','')} {_c('[HTTP]','teal')} {_c(msg,'cyan')}"


def _format_drop(ev: Dict[str, Any]) -> Optional[str]:
    drop = ev.get("drop")
    if not drop:
        return None
    msg = (
        f"{ev.get('src_ip','-')} → {ev.get('dest_ip','-')} "
        f"proto={ev.get('proto','-')} reason={drop.get('reason','-')}"
    )
    return f"{ev.get('timestamp','')} {_c('[DROP]','red')} {_c(msg,'red')}"


def _format_alert(ev: Dict[str, Any], show_sid: bool, wide: bool) -> Optional[str]:
    alert = ev.get("alert")
    if not alert:
        return None
    sig = alert.get("signature") or "-"
    cat = alert.get("category") or sig
    sev = _safe_int(alert.get("severity"), 3)
    gid = _safe_int(alert.get("gid"), 1)
    sid = _safe_int(alert.get("signature_id") or alert.get("sig_id"), 0)
    rev = _safe_int(alert.get("rev"), 1)
    classtype = alert.get("classtype") or ""
    sig = re.sub(r"^\[ROGUE AP\]\[DNS\]", "[ROGUE DNS][DNS]", sig)
    head = _color_for_alert(sig, cat, classtype, sev, sid, gid)
    msg_parts = [
        f"src={ev.get('src_ip','-')}",
        f"dst={ev.get('dest_ip','-')}",
    ]
    if show_sid:
        msg_parts.append(f"[{gid}:{sid}:{rev}]")
    if wide:
        if "proto" in ev:
            msg_parts.append(f"proto={ev.get('proto','-')}")
        if ev.get("src_port") is not None:
            msg_parts.append(f"sport={ev.get('src_port')}")
        if ev.get("dest_port") is not None:
            msg_parts.append(f"dport={ev.get('dest_port')}")
        if ev.get("app_proto"):
            msg_parts.append(f"app={ev.get('app_proto')}")
    action = drop_action(ev)
    if action:
        msg_parts.append(f"action={action}")
    msg = " ".join(msg_parts)
    alert_tag = _c("[DROP ALERT]", "red") if action else _c("[ALERT]", "yellow")
    return f"{ev.get('timestamp', '')} {alert_tag} {head} {_c(msg, 'cyan')}"


def _format_generic(ev: Dict[str, Any]) -> str:
    etype = str(ev.get("event_type", "?")).upper()
    ts = ev.get("timestamp", "")
    parts = [ts, _c(f"[{etype}]", "gray")]
    if ev.get("src_ip") or ev.get("dest_ip"):
        parts.append(_c(f"{_ipport(ev.get('src_ip'), ev.get('src_port'))} → {_ipport(ev.get('dest_ip'), ev.get('dest_port'))}", "cyan"))
    if ev.get("proto"):
        parts.append(_c(f"proto={ev.get('proto')}", "cyan"))
    if ev.get("app_proto"):
        parts.append(_c(f"app={ev.get('app_proto')}", "cyan"))
    for k, v in ev.items():
        if k in {"timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto", "flow", "alert", "dns", "http", "tls", "drop"}:
            continue
        # Keep small scalar fields for quick context; skip large/nested payloads.
        if isinstance(v, (str, int, float, bool)) and len(str(v)) <= 64:
            parts.append(_c(f"{k}={v}", "cyan"))
    return " ".join(parts)


def format_event(ev: Dict[str, Any], show_sid: bool, wide: bool) -> Optional[str]:
    try:
        etype = ev.get("event_type")
        if etype == "flow":
            return _format_flow(ev)
        if etype == "dns":
            return _format_dns(ev)
        if etype == "tls":
            return _format_tls(ev)
        if etype == "http":
            return _format_http(ev, wide)
        if etype == "drop":
            return _format_drop(ev)
        if etype == "alert":
            return _format_alert(ev, show_sid, wide)
        # Fallback: show everything else in a compact generic line.
        return _format_generic(ev)
    except Exception:
        # Skip malformed events without crashing the stream.
        return None
    return None


def _tail_proc(log_path: str) -> Optional[subprocess.Popen]:
    if IS_WINDOWS or not shutil.which("tail"):
        return None
    try:
        return subprocess.Popen(
            ["tail", "-F", log_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError:
        return None


def stream_events(log_path: str, show_sid: bool, wide: bool, trigger_log_path: str = "") -> None:
    trigger_logging = bool(trigger_log_path)
    if trigger_logging and Path(trigger_log_path).resolve() == Path(log_path).resolve():
        print("[WARN] trigger log cannot be the EVE input file; evidence logging disabled", file=sys.stderr)
        trigger_logging = False
    elif trigger_logging:
        print(f"[INFO] Alerts and actual drops will be appended to {trigger_log_path}")
    dns_cache: Dict[str, List[str]] = {}
    proc = _tail_proc(log_path)
    if proc and proc.stdout:
        source: Iterable[str] = proc.stdout
    else:
        # Fallback: simple follow loop without rotation handling.
        try:
            f = open(log_path, "r", encoding="utf-8", errors="ignore")
        except OSError as exc:
            print(f"[ERR] cannot read {log_path}: {exc}", file=sys.stderr)
            return
        f.seek(0, os.SEEK_END)

        def _iter() -> Iterable[str]:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line

        source = _iter()

    try:
        for line in source:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            update_domain_cache(ev, dns_cache)
            out = format_event(ev, show_sid, wide)
            if out:
                print(out, flush=True)
            if trigger_logging:
                record = format_trigger_record(ev, domain_context(ev, dns_cache))
                if record and not append_trigger_record(trigger_log_path, record):
                    trigger_logging = False
    except KeyboardInterrupt:
        pass
    finally:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="suricatamon (Python) - colorized eve.json tail")
    p.add_argument("--log", default=default_eve_log(), help="eve.json path")
    p.add_argument("--show-sid", default=os.environ.get("SURICATAMON_SHOW_SID", "0"), choices=["0", "1"], help="append [gid:sid:rev]")
    p.add_argument("--wide", default=os.environ.get("SURICATAMON_WIDE", "0"), choices=["0", "1"], help="include proto/ports/app")
    p.add_argument(
        "--trigger-log",
        "--drop-log",
        dest="trigger_log",
        default=os.environ.get(
            "MEERCATA_TRIGGER_LOG",
            os.environ.get("MEERCATA_DROP_LOG", "./Trigger Drop-Alert.txt"),
        ),
        help="append alerts and actual drops to this hunting-evidence text file; use an empty value to disable",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    if not os.path.isfile(args.log):
        print(f"[ERR] cannot read {args.log}", file=sys.stderr)
        sys.exit(2)
    show_sid = args.show_sid == "1"
    wide = args.wide == "1"
    stream_events(args.log, show_sid, wide, args.trigger_log)


if __name__ == "__main__":
    main()
