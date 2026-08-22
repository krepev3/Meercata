#!/usr/bin/env python3
"""YAML helpers for Suricata config."""

import datetime
import os
import stat
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from platform_support import IS_WINDOWS, suricata_env, suricata_executable


def _backup_yaml(cfg: str) -> Path:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dst = Path(f"{cfg}.{ts}.bak")
    shutil.copy2(cfg, dst)
    print(f"[OK] YAML backup: {dst}")
    return dst


def _write_yaml(cfg: str, lines: List[str]) -> Path:
    """Back up and atomically replace a configuration while preserving metadata."""
    path = Path(cfg)
    original_stat = path.stat()
    backup = _backup_yaml(cfg)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp:
            temp_name = temp.name
            for line in lines:
                temp.write(line if line.endswith("\n") else line + "\n")
            temp.flush()
            os.fsync(temp.fileno())
        os.chmod(temp_name, stat.S_IMODE(original_stat.st_mode))
        if hasattr(os, "chown"):
            try:
                os.chown(temp_name, original_stat.st_uid, original_stat.st_gid)
            except PermissionError:
                pass
        os.replace(temp_name, path)
    except Exception:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)
        raise
    suricata = suricata_executable()
    if suricata:
        validation = None
        validation_error = ""
        try:
            validation = subprocess.run(
                [suricata, "-T", "-c", str(path)],
                text=True,
                capture_output=True,
                timeout=30,
                env=suricata_env(suricata),
                cwd=str(Path(suricata).parent) if IS_WINDOWS else None,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            validation_error = str(exc)
        if validation is None or validation.returncode != 0:
            restore_temp = ""
            try:
                with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
                    restore_temp = temp.name
                shutil.copy2(backup, restore_temp)
                os.replace(restore_temp, path)
            finally:
                if restore_temp:
                    Path(restore_temp).unlink(missing_ok=True)
            output = "" if validation is None else (validation.stderr or validation.stdout)
            detail = output.strip().splitlines()
            message = detail[-1] if detail else (validation_error or "unknown validation error")
            raise RuntimeError(f"Suricata rejected the updated configuration; restored backup: {message}")
    return backup


def restore_yaml_backup(cfg: str, backup: Path) -> None:
    """Atomically restore a backup created by a configuration edit."""
    os.replace(backup, cfg)


def _read_yaml_lines(cfg: str) -> Optional[List[str]]:
    path = Path(cfg)
    if not path.exists():
        print(f"[ERR] YAML not found: {cfg}")
        return None
    try:
        return path.read_text(encoding="utf-8").splitlines(True)
    except (OSError, UnicodeError) as exc:
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
    fallback = str(Path(cfg).resolve().parent / "rules") if IS_WINDOWS else "/var/lib/suricata/rules"
    path = ""
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return fallback
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        if "default-rule-path:" in line:
            _, rhs = line.split("default-rule-path:", 1)
            path = rhs.strip().strip("'\"")
            break
    return path or fallback


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
    af_indent = 0
    for raw in lines:
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.lstrip()
        if stripped.startswith("af-packet:"):
            in_af = True
            af_indent = indent
            continue
        if in_af:
            if stripped and not stripped.startswith("#") and indent <= af_indent:
                in_af = False
                continue
            if "- interface:" in stripped:
                content = stripped.lstrip("# ").strip()
                if content.startswith("- interface:"):
                    iface = content.split(":", 1)[1].strip().strip("'\"")
                    state = "disabled" if stripped.lstrip().startswith("#") else "enabled"
                    entries.append((state, iface, raw.rstrip("\n")))
    return entries


def yaml_set_af_packet_state(cfg: str, target: str, desired: str, apply: bool = True) -> bool:
    if desired not in {"enabled", "disabled"}:
        raise ValueError("desired state must be enabled or disabled")
    lines = _read_yaml_lines(cfg)
    if lines is None:
        return False
    in_af = False
    af_indent = 0
    changed = False
    for idx, raw in enumerate(lines):
        indent_len = len(raw) - len(raw.lstrip())
        stripped = raw.lstrip()
        if stripped.startswith("af-packet:"):
            in_af = True
            af_indent = indent_len
            continue
        if in_af:
            if stripped and not stripped.startswith("#") and indent_len <= af_indent:
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
        if apply:
            _write_yaml(cfg, lines)
        else:
            print(f"[DRY] would set af-packet interface {target} -> {desired}")
    return changed


def yaml_set_rule_state(cfg: str, target: str, desired: str, apply: bool = True) -> bool:
    if desired not in {"enabled", "disabled"}:
        raise ValueError("desired state must be enabled or disabled")
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
                    is_disabled = stripped.startswith("#")
                    should_change = (desired == "enabled" and is_disabled) or (desired == "disabled" and not is_disabled)
                    if should_change:
                        indent = line[: len(line) - len(stripped)]
                        if desired == "enabled":
                            current = indent + stripped.lstrip("# ")
                        else:
                            current = indent + "# " + stripped
                        changed = True
                out_lines.append(current)
                continue
        out_lines.append(line)
    if changed:
        if apply:
            _write_yaml(cfg, out_lines)
        else:
            print(f"[DRY] would set rule-file {target} -> {desired}")
    return changed


def yaml_add_rulefile(cfg: str, filename: str) -> bool:
    """Append a rule-file entry if it is not already present. Returns True if added."""
    if not filename.endswith(".rules") or Path(filename).name != filename or Path(filename).is_absolute():
        raise ValueError("rule filename must be a local .rules filename")
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
        _write_yaml(cfg, out_lines)
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
    in_vars = in_addr = in_pcap = in_nfq = False
    pcap_indent = nfq_indent = 0
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
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
        if stripped.startswith("pcap:"):
            in_pcap = True
            pcap_indent = indent
            continue
        if in_pcap and stripped and indent <= pcap_indent:
            in_pcap = False
        if in_pcap and stripped.startswith("interface:"):
            capture_blocks.append(stripped.split("interface:", 1)[1].strip().strip("'\""))
        if stripped.startswith("nfq:"):
            in_nfq = True
            nfq_indent = indent
            continue
        if in_nfq and stripped and indent <= nfq_indent:
            in_nfq = False
        if in_nfq and stripped.startswith("-"):
            continue
        if in_nfq and ":" in stripped:
            key, val = stripped.split(":", 1)
            nfq_block.append((key.strip(), val.strip()))
    capture_blocks = [iface for state, iface, _ in yaml_af_packet_entries(cfg) if state == "enabled"] + capture_blocks
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


def yaml_set_runmode(cfg: str, mode: str, apply: bool = True) -> None:
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
        if line.lstrip().startswith("runmode:"):
            indent = line[: len(line) - len(line.lstrip())]
            new_line = f"{indent}runmode: {mode}"
            if new_line != line.strip():
                line = new_line
                changed = True
        lines.append(line)
    if changed:
        if apply:
            _write_yaml(cfg, lines)
            print(f"[OK] runmode -> {mode}")
        else:
            print(f"[DRY] would set runmode -> {mode}")
    else:
        print("[OK] no change needed")


def yaml_set_nfq_kv(cfg: str, key: str, value: str, apply: bool = True) -> None:
    lines: List[str] = []
    in_nfq = False
    set_key = False
    nfq_indent = ""
    raw_lines = _read_yaml_lines(cfg)
    if raw_lines is None:
        return
    for raw in raw_lines:
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        if stripped.startswith("#"):
            lines.append(line)
            continue
        if stripped.startswith("nfq:"):
            in_nfq = True
            nfq_indent = indent
            lines.append(f"{nfq_indent}nfq:")
            continue
        if in_nfq:
            # Leaving nfq block when a new top-level/sibling key appears.
            if stripped and not stripped.startswith(("-", "#")) and ":" in stripped and not line.startswith(f"{nfq_indent}  "):
                if not set_key:
                    lines.append(f"{nfq_indent}  {key}: {value}")
                    set_key = True
                in_nfq = False
            if not in_nfq:
                lines.append(line)
                continue
            current_key = stripped.split(":", 1)[0].strip()
            if current_key == key:
                lines.append(f"{nfq_indent}  {key}: {value}")
                set_key = True
            else:
                lines.append(line)
            continue
        lines.append(line)

    if in_nfq and not set_key:
        lines.append(f"{nfq_indent}  {key}: {value}")
        set_key = True

    if not set_key:
        lines.append("nfq:")
        lines.append(f"  {key}: {value}")

    original = [raw.rstrip("\n") for raw in raw_lines]
    if lines == original:
        print("[OK] no change needed")
        return
    if apply:
        _write_yaml(cfg, lines)
        print(f"[OK] nfq.{key} -> {value}")
    else:
        print(f"[DRY] would set nfq.{key} -> {value}")
