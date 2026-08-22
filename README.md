# Meercata v1.00 for Windows

Meercata v1.00 is a Windows-based Suricata IDS controller and monitoring utility. This repository release targets Windows 10/11 and Windows Server with Suricata and Npcap.

The maintained source is in [`Meercata-v1.00-Windows/`](Meercata-v1.00-Windows/).

## Windows capabilities

- Npcap/pcap passive IDS capture
- Suricata Windows service and process status
- Interactive and command-line operation
- Live EVE JSON monitoring
- Readable alert and drop evidence logging
- Rule-file and Suricata YAML management
- Requirement checks, validation, backups, and rollback protection
- Native Windows launchers with Administrator/UAC support

## Requirements

- Windows 10/11 or Windows Server
- Python 3.10 or newer
- Suricata with Npcap support
- Npcap
- Administrator rights for packet capture, service operations, and protected configuration changes

## Quick start

```powershell
cd Meercata-v1.00-Windows
.\meercata.cmd check
.\meercata-admin.cmd
```

For a running Suricata Windows service, use **Suricata control -> Status** and **Suricata control -> Monitor**.

## Important mode note

The validated v1.00 deployment is a passive IDS: it detects and logs traffic but does not block it. Windows inline IPS requires a Suricata build with WinDivert enabled.

## Linux roadmap

Meercata v2 for Linux is a separate work in progress and is not part of this Windows v1.00 release.

Operational logs, EVE data, evidence files, rule archives, caches, and machine-specific configuration backups are intentionally excluded from this public repository.
