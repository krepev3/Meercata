#!/usr/bin/env python3
"""Python port of the suricatamon Bash helper (colorized eve.json tail)."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional

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


def _c(txt: str, key: str) -> str:
    return f"{COLOR.get(key, '')}{txt}{COLOR['reset']}"


def _ipport(ip: Any, port: Any) -> str:
    ip_s = str(ip or "-")
    port_s = str(port or 0)
    return f"{ip_s}:{port_s}"


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
    sev = int(alert.get("severity") or 3)
    gid = int(alert.get("gid") or 1)
    sid = int(alert.get("signature_id") or alert.get("sig_id") or 0)
    rev = int(alert.get("rev") or 1)
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
    msg = " ".join(msg_parts)
    return f"{ev.get('timestamp', '')} {_c('[ALERT]', 'yellow')} {head} {_c(msg, 'cyan')}"


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
    if not shutil.which("tail"):
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


def stream_events(log_path: str, show_sid: bool, wide: bool) -> None:
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
            out = format_event(ev, show_sid, wide)
            if out:
                print(out, flush=True)
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
    p.add_argument("--log", default=os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"), help="eve.json path")
    p.add_argument("--show-sid", default=os.environ.get("SURICATAMON_SHOW_SID", "0"), choices=["0", "1"], help="append [gid:sid:rev]")
    p.add_argument("--wide", default=os.environ.get("SURICATAMON_WIDE", "0"), choices=["0", "1"], help="include proto/ports/app")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    if not os.path.isfile(args.log):
        print(f"[ERR] cannot read {args.log}", file=sys.stderr)
        sys.exit(2)
    show_sid = args.show_sid == "1"
    wide = args.wide == "1"
    stream_events(args.log, show_sid, wide)


if __name__ == "__main__":
    main()
