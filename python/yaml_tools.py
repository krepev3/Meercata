#!/usr/bin/env python3
"""YAML helpers for Suricata config."""

import datetime
import shutil
from pathlib import Path
from typing import List, Optional, Tuple


def _backup_yaml(cfg: str) -> Path:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = Path(f"{cfg}.{ts}.bak")
    shutil.copy2(cfg, dst)
    print(f"[OK] YAML backup: {dst}")
    return dst


def _read_yaml_lines(cfg: str) -> Optional[List[str]]:
    path = Path(cfg)
    if not path.exists():
        print(f"[ERR] YAML not found: {cfg}")
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines(True)
    except OSError as exc:
        print(f"[ERR] cannot read {cfg}: {exc}")
        return None


def _render_table(headers: List[str], rows: List[Tuple[str, ...]]) -> str:
    cols = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(row[i])))

    def fmt_row(values: List[str]) -> str:
        parts = [f" {str(v).ljust(widths[i])} " for i, v in enumerate(values)]
        return "|" + "|".join(parts) + "|"

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, fmt_row(headers), sep]
    for row in rows:
        lines.append(fmt_row(list(row)))
    lines.append(sep)
    return "\n".join(lines)


def yaml_default_rule_path(cfg: str) -> str:
    path = ""
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return "/var/lib/suricata/rules"
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        if "default-rule-path:" in line:
            _, rhs = line.split("default-rule-path:", 1)
            path = rhs.strip().strip("'\"")
            break
    return path or "/var/lib/suricata/rules"


def yaml_rulefiles(cfg: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    in_block = False
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return results
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if not in_block and stripped.startswith("rule-files:"):
            in_block = True
            continue
        if in_block:
            if stripped.startswith("#"):
                # Allow commented rule lines to be parsed as disabled.
                if "- " in stripped:
                    name = stripped.split("- ", 1)[1].split("#", 1)[0].strip().strip("'\"")
                    if name:
                        results.append(("disabled", name))
                continue
            if stripped and not stripped.startswith("-") and not stripped.startswith("#"):
                if ":" in stripped:
                    break
            if stripped.startswith("-"):
                name = stripped.lstrip("-").split("#", 1)[0].strip().strip("'\"")
                if name:
                    results.append(("enabled", name))
    return results


def yaml_af_packet_entries(cfg: str) -> List[Tuple[str, str, str]]:
    """Return list of (state, interface, raw_line) from af-packet section."""
    entries: List[Tuple[str, str, str]] = []
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return entries
    in_af = False
    for raw in lines:
        stripped = raw.lstrip()
        if stripped.startswith("af-packet:"):
            in_af = True
            continue
        if in_af:
            if stripped and not stripped.startswith(("-", "#")) and ":" in stripped and not stripped.startswith((" ", "\t")):
                in_af = False
                continue
            if "- interface:" in stripped:
                content = stripped.lstrip("# ").strip()
                if content.startswith("- interface:"):
                    iface = content.split(":", 1)[1].strip().strip("'\"")
                    state = "disabled" if stripped.lstrip().startswith("#") else "enabled"
                    entries.append((state, iface, raw.rstrip("\n")))
    return entries


def yaml_set_af_packet_state(cfg: str, target: str, desired: str) -> bool:
    assert desired in {"enabled", "disabled"}
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return False
    in_af = False
    changed = False
    for idx, raw in enumerate(lines):
        stripped = raw.lstrip()
        if stripped.startswith("af-packet:"):
            in_af = True
            continue
        if in_af:
            if stripped and not stripped.startswith(("-", "#")) and ":" in stripped and not stripped.startswith((" ", "\t")):
                in_af = False
                continue
            if "- interface:" in stripped:
                content = stripped.lstrip("# ").strip()
                if content.startswith("- interface:"):
                    iface = content.split(":", 1)[1].strip().strip("'\"")
                    if iface == target:
                        indent = raw[: len(raw) - len(raw.lstrip())]
                        body = content
                        if desired == "enabled":
                            new_line = indent + body + ("\n" if raw.endswith("\n") else "")
                        else:
                            # ensure commented
                            new_line = indent + "# " + body + ("\n" if raw.endswith("\n") else "")
                        if new_line != raw:
                            lines[idx] = new_line
                            changed = True
                        break
    if changed:
        _backup_yaml(cfg)
        with open(cfg, "w", encoding="utf-8") as f:
            f.writelines(lines)
    return changed


def yaml_set_rule_state(cfg: str, target: str, desired: str) -> bool:
    assert desired in {"enabled", "disabled"}
    changed = False
    out_lines: List[str] = []
    in_block = False
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return False
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if not in_block and stripped.startswith("rule-files:") and not stripped.startswith("#"):
            in_block = True
            out_lines.append(line)
            continue
        if in_block:
            if stripped and not stripped.startswith("-") and not stripped.startswith("#"):
                if ":" in stripped:
                    in_block = False
            if in_block:
                current = line
                payload = stripped
                if stripped.startswith("#") and "- " in stripped:
                    payload = stripped.split("- ", 1)[1]
                elif stripped.startswith("- "):
                    payload = stripped[2:]
                payload = payload.split("#", 1)[0].strip().strip("'\"")
                if payload == target:
                    new_line = "  - " + target if desired == "enabled" else "  # - " + target
                    if new_line != current.strip():
                        current = new_line
                        changed = True
                out_lines.append(current)
                continue
        out_lines.append(line)
    if changed:
        _backup_yaml(cfg)
        with open(cfg, "w", encoding="utf-8") as f:
            for ln in out_lines:
                f.write(ln + "\n")
    return changed


def yaml_add_rulefile(cfg: str, filename: str) -> bool:
    """Append a rule-file entry if it is not already present. Returns True if added."""
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return False
    present = False
    added = False
    out_lines: List[str] = []
    in_block = False
    block_lines: List[str] = []
    block_indent = ""

    def flush_block():
        nonlocal added
        if not present:
            block_lines.append(f"{block_indent}  - {filename}")
            added = True
        out_lines.extend(block_lines)

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if not in_block and stripped.startswith("rule-files:") and not stripped.startswith("#"):
            in_block = True
            block_indent = line[: len(line) - len(line.lstrip())]
            block_lines = [line]
            continue
        if in_block:
            # If we hit a new top-level key (non-list, non-comment) we flush the block.
            if stripped and not stripped.startswith(("-", "#")) and ":" in stripped:
                flush_block()
                in_block = False
                out_lines.append(line)
                continue
            # Still inside block; track presence
            payload = stripped
            if stripped.startswith("#") and "- " in stripped:
                payload = stripped.split("- ", 1)[1]
            elif stripped.startswith("- "):
                payload = stripped[2:]
            payload = payload.split("#", 1)[0].strip().strip("'\"")
            if payload == filename:
                present = True
            block_lines.append(line)
            continue
        out_lines.append(line)

    if in_block:
        flush_block()
    if not in_block and not block_lines and not present:
        # No rule-files block found; create one.
        out_lines.append("rule-files:")
        out_lines.append(f"  - {filename}")
        added = True

    if present:
        return False
    if added:
        _backup_yaml(cfg)
        with open(cfg, "w", encoding="utf-8") as f:
            for ln in out_lines:
                f.write(ln + "\n")
    return added


def yaml_rules_insight(cfg: str) -> None:
    base = yaml_default_rule_path(cfg)
    entries = yaml_rulefiles(cfg)
    rows: List[Tuple[str, str, str, str, str]] = []
    for state, f in entries:
        path = Path(base) / f
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        rows.append((state, f, str(path), "yes" if exists else "no", str(size)))
    print(f"YAML: {cfg}")
    print(f"default-rule-path: {base}")
    print("\n[Rule-files]")
    if rows:
        print(_render_table(["State", "Name", "Path", "Exists", "Bytes"], rows))
    else:
        print(" (none)")
    enabled = sum(1 for s, _ in entries if s == "enabled")
    disabled = sum(1 for s, _ in entries if s == "disabled")
    print(f"\nSummary: {enabled} enabled, {disabled} disabled, total {len(entries)}.")


def yaml_summary(cfg: str) -> None:
    home = ""
    external = ""
    capture_blocks: List[str] = []
    nfq_block: List[Tuple[str, str]] = []
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return
    in_vars = in_addr = in_af = in_pcap = in_nfq = False
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("vars:"):
            in_vars = True
            continue
        if in_vars and stripped.startswith("address-groups:"):
            in_addr = True
            continue
        if in_addr and stripped.startswith("HOME_NET:"):
            home = stripped.split("HOME_NET:", 1)[1].strip().strip("'\"")
        if in_addr and stripped.startswith("EXTERNAL_NET:"):
            external = stripped.split("EXTERNAL_NET:", 1)[1].strip().strip("'\"")
        if in_addr and (":" in stripped and not stripped.startswith(("-", "HOME_NET", "EXTERNAL_NET"))):
            in_addr = False
        if stripped.startswith("af-packet:"):
            in_af = True
            continue
        if in_af and stripped.startswith("- interface:"):
            capture_blocks.append(stripped.split("interface:", 1)[1].strip().strip("'\""))
        if in_af and (":" in stripped and not stripped.startswith("-")):
            in_af = False
        if stripped.startswith("pcap:"):
            in_pcap = True
            continue
        if in_pcap and stripped.startswith("interface:"):
            capture_blocks.append(stripped.split("interface:", 1)[1].strip().strip("'\""))
        if in_pcap and (":" in stripped and not stripped.startswith("-") and not stripped.startswith("interface:")):
            in_pcap = False
        if stripped.startswith("nfq:"):
            in_nfq = True
            continue
        if in_nfq and stripped.startswith("-"):
            continue
        if in_nfq and ":" in stripped:
            key, val = stripped.split(":", 1)
            nfq_block.append((key.strip(), val.strip()))
        if in_nfq and (not stripped or (":" in stripped and not stripped.startswith((" ", "\t")))):
            in_nfq = False
    print(f"YAML: {cfg}")
    # Networks table
    net_rows = [("HOME_NET", home or "-"), ("EXTERNAL_NET", external or "-")]
    print("\n[Networks]")
    print(_render_table(["Key", "Value"], net_rows))

    # Capture interfaces
    print("\n[Capture]")
    if capture_blocks:
        rows = [(iface,) for iface in capture_blocks]
        print(_render_table(["Interface"], rows))
    else:
        print(" (none)")

    # NFQ block
    print("\n[NFQ]")
    if nfq_block:
        print(_render_table(["Key", "Value"], nfq_block))
    else:
        print(" (none)")


def yaml_set_runmode(cfg: str, mode: str) -> None:
    if mode not in {"workers", "autofp"}:
        print("[ERR] runmode must be workers|autofp")
        return
    lines = []
    changed = False
    raw_lines = _read_yaml_lines(cfg)
    if raw_lines is None:
        return
    for raw in raw_lines:
        line = raw.rstrip("\n")
        if line.lstrip().startswith("#"):
            lines.append(line)
            continue
        if "runmode:" in line:
            new_line = f"runmode: {mode}"
            if new_line != line.strip():
                line = new_line
                changed = True
        lines.append(line)
    if changed:
        _backup_yaml(cfg)
        with open(cfg, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[OK] runmode -> {mode}")
    else:
        print("[OK] no change needed")


def yaml_set_nfq_kv(cfg: str, key: str, value: str) -> None:
    lines = []
    in_nfq = False
    set_key = False
    raw_lines = _read_yaml_lines(cfg)
    if raw_lines is None:
        return
    for raw in raw_lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if stripped.startswith("#"):
            lines.append(line)
            continue
        if stripped.startswith("nfq:"):
            in_nfq = True
            lines.append("nfq:")
            continue
        if in_nfq and stripped and not stripped.startswith(("-", "#")) and ":" in stripped and not stripped.startswith((" ", "\t")):
            in_nfq = False
        if in_nfq:
            if stripped.split(":", 1)[0].strip() == key:
                lines.append(f"  {key}: {value}")
                set_key = True
                continue
        lines.append(line)
    if not set_key:
        if not any(l.strip().startswith("nfq:") for l in lines):
            lines.append("nfq:")
        lines.append(f"  {key}: {value}")
    _backup_yaml(cfg)
    with open(cfg, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] nfq.{key} -> {value}")
