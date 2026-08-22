# Meercata v1.00

Meercata is a safety-focused command-line and interactive controller for Suricata. It supports Linux IDS/IPS operations and native Windows IDS monitoring with Npcap.

## Current implementation

The actively maintained Python implementation is in [`python/`](python/).

- Windows 10/11 and Windows Server: Npcap-based passive IDS, service/process status, EVE monitoring, evidence logging, rules, YAML management, and requirement checks.
- Linux: IDS, NFQUEUE inline IPS, nftables/iptables hooks, rules, YAML management, monitoring, and optional systemd lifecycle.
- Safe defaults: mutating CLI operations are dry-run unless `--apply` is supplied.
- Validated YAML edits: timestamped backup, atomic write, Suricata configuration test, and automatic rollback on failure.
- Tests: 50 passed and 2 platform-specific tests skipped in the validated Windows build.

## Windows quick start

```powershell
cd python
.\meercata.cmd check
.\meercata-admin.cmd
```

For a running Suricata Windows service, use **Suricata control -> Status** and **Suricata control -> Monitor**. See [`python/WINDOWS.md`](python/WINDOWS.md) for setup and operating details.

## Linux quick start

```bash
cd python
./meercata check
./meercata
```

See [`python/README.md`](python/README.md) for the full command reference, safety model, and platform notes.

## Tests

```bash
cd python
python -m pytest -q
```

## Repository layout

- `python/` - current cross-platform Meercata v1.00 implementation
- `Bash/` - discontinued baseline retained for historical reference

Operational logs, EVE data, evidence files, caches, staged rules, and local configuration backups are intentionally excluded from version control.
