# Meercata v1.00 - Windows

Meercata v1.00 is the Windows release of the Meercata Suricata controller. It provides Npcap-based passive IDS operation, Windows service diagnostics, live EVE monitoring, readable alert evidence, rule management, and safe Suricata configuration changes.

## Supported platform

- Windows 10/11
- Windows Server
- Python 3.10+
- Suricata with Npcap support
- Npcap packet capture driver

Administrator rights are required for packet capture, Windows service operations, and configuration changes under `C:\Program Files`.

## Start

Open PowerShell in this folder.

```powershell
.\meercata.cmd check
.\meercata-admin.cmd
```

`meercata-admin.cmd` requests elevation and opens the interactive UI. For CLI arguments, open PowerShell as Administrator and use `meercata.cmd`.

## Daily workflow

1. Launch `meercata-admin.cmd`.
2. Select **Suricata control -> Status** and confirm the service is running.
3. Select **Suricata control -> Monitor**.
4. Accept the default EVE path or enter your Suricata `eve.json` path.
5. Leave the monitor open while collecting new alert evidence.
6. Press `Ctrl+C` to stop Meercata Monitor; the Suricata service continues running.

## CLI examples

```powershell
.\meercata.cmd check
.\meercata.cmd status
.\meercata.cmd diag
.\meercata.cmd rules
.\meercata.cmd yaml-summary
.\meercata.cmd monitor `
  --log "C:\Program Files\Suricata\log\eve.json" `
  --trigger-log ".\Trigger Drop-Alert.txt"
```

Global options such as `--config`, `--iface`, and `--apply` must appear before the subcommand.

## Safety model

- Mutating non-interactive commands are dry-run unless `--apply` is supplied.
- Suricata YAML changes use timestamped backups and atomic writes.
- Configuration changes are validated with Suricata before being accepted.
- Failed validation restores the previous configuration.
- Runtime evidence and local deployment artifacts are ignored by Git.

## IDS and IPS

The validated v1.00 setup is a passive Windows IDS using Npcap. It detects and records traffic without blocking it. Windows inline IPS is available only when the installed Suricata binary was compiled with WinDivert support.

## Documentation

See [`WINDOWS.md`](WINDOWS.md) for detailed Windows operation and platform limitations.

## Tests

```powershell
python -m pytest -q
```

Validated result: 50 passed, 2 platform-specific tests skipped.

## Linux version

Meercata v2 for Linux is being developed separately and is not included in this Windows v1.00 folder.
