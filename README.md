# Meercata

Meercata is a Python-based Suricata controller and monitoring project. It provides operator tools for checking requirements, observing runtime health, working with rules and configuration, and managing supported Suricata workflows.

This repository contains two separate implementations: **Meercata v1.00 for Windows** and **Meercata v2.00 for Debian Linux**. Each version has its own source, requirements, documentation, and development status. Suricata performs packet inspection; Meercata provides the control and monitoring tools around it.

## Versions at a glance

| | Meercata v1.00 | Meercata v2.00 |
|---|---|---|
| Platform | Windows 10/11 and Windows Server | Debian Linux; installed qualification targets Debian 13 |
| Python | 3.10 or newer | 3.11 or newer |
| Interface | Interactive terminal menu and CLI | Interactive terminal menu and CLI with JSON output |
| Main scope | Passive IDS operation, live EVE monitoring, rules and YAML management | Transactional control, health monitoring, RuleOps, recovery, and Debian packaging |
| Current status | Windows v1.00; validated deployment scope is passive IDS | Development version `2.0.0.dev24`, with subsequent terminal-menu additions; production readiness remains gated |
| Source and guide | [Windows v1.00](Meercata-v1.00-Windows/) | [Debian Linux v2.00](Meercata-v2.00-DebianLinux/) |

## Repository layout

```text
Meercata-v1.00-Windows/       Windows application, launchers, tests, and operating guide
Meercata-v2.00-DebianLinux/  Linux application, packaging, tests, and qualification records
docs/                       Research portfolio, architecture, validation plan, and roadmap
```

## Meercata v1.00 — Windows

Meercata v1.00 provides a Windows operator interface for Suricata with Npcap-based passive IDS capture.

### Capabilities

- Interactive terminal menu and command-line operation.
- Requirement checks and Suricata service/process diagnostics.
- Live EVE JSON monitoring and readable alert/drop evidence logging.
- Rule-file inspection and management.
- Suricata YAML changes with validation, backups, and rollback protection.
- Native Windows launchers with Administrator/UAC support.

### Requirements

- Windows 10/11 or Windows Server.
- Python 3.10 or newer.
- Suricata for Windows with Npcap support, valid configuration and rules, and EVE JSON output.
- Npcap.
- Administrator rights for packet capture, service operations, and protected configuration changes.

### Quick start

From the repository root, open PowerShell and run:

```powershell
cd Meercata-v1.00-Windows
.\meercata.cmd check
.\meercata-admin.cmd
```

`meercata-admin.cmd` requests elevation and opens the interactive menu. For an existing Suricata Windows service, use **Suricata control -> Status** and **Suricata control -> Monitor**.

The validated Windows v1.00 setup is **passive IDS**: it detects and records traffic without blocking it. Windows inline IPS additionally requires a Suricata build with WinDivert support.

### Windows documentation

- [Windows v1.00 overview and CLI examples](Meercata-v1.00-Windows/README.md)
- [Windows setup, capture modes, and platform limitations](Meercata-v1.00-Windows/WINDOWS.md)
- [Windows operations manual and operator documentation](https://github.com/krepev3/Meercata-Documentation)

## Meercata v2.00 — Debian Linux

Meercata v2.00 develops a transactional Suricata control plane for Debian Linux. The current package version is **`2.0.0.dev24`**. The source also includes terminal-menu additions made after the recorded dev24 qualification milestone.

**Current status: development and controlled lab qualification. Production readiness remains gated.**

### Capabilities

- Interactive terminal menu, CLI commands, and structured JSON output.
- Health checks for Suricata, systemd readiness, interfaces, EVE freshness, resources, and supported nftables/NFQUEUE state.
- Durable health-transition monitoring, scheduled-run freshness checks, and queued delivery over verified HTTPS with retries, receipts, and dead letters.
- RuleOps candidate staging, differences, Suricata validation, and fixed PCAP regression checks.
- Transaction records, audit logging, rollback/recovery foundations, and restricted privileged operations.
- Native Debian packaging, systemd integration, and dedicated qualification tools.

### Requirements and source quick start

The controller requires **Python 3.11 or newer**. Installed deployment qualification targets Debian 13 with systemd, Suricata 8, and the dependencies described in the Debian package documentation.

To inspect the development CLI and open its terminal menu, run these commands from the repository root:

```bash
cd Meercata-v2.00-DebianLinux
python3 -m meercata --version
python3 -m meercata paths --json
python3 -m meercata
```

The menu requires an interactive terminal. It can open without root privileges or installed configuration; health checks and operational actions require their corresponding configuration, services, and permissions. Opening the menu does not start Suricata or activate IPS.

### Development boundaries

Public IDS/IPS start/stop controls, direct YAML editing, and live rule promotion remain unavailable or gated. The original live EVE threat-alert viewer is also unavailable in the v2 menu; v2 monitoring currently records **health-transition events**.

The dev24 records cover local HTTPS delivery and delivery-health qualification alongside earlier milestones. Remaining production gates include installed monitoring and retention under real systemd, deployment collector and credential validation, traffic/hardware capacity, endurance testing, and release operations. Later terminal-menu additions do not automatically extend the recorded dev24 results.

### Linux documentation

- [Linux v2.00 capabilities, CLI reference, and current status](Meercata-v2.00-DebianLinux/README.md)
- [Native Debian package requirements and lifecycle](Meercata-v2.00-DebianLinux/NATIVE-DEBIAN.md)
- [Production roadmap and acceptance gates](Meercata-v2.00-DebianLinux/PRODUCTION-ROADMAP.md)
- [Qualification procedures and evidence](Meercata-v2.00-DebianLinux/QUALIFICATION.md)
- [Dev24 completion report and remaining work](Meercata-v2.00-DebianLinux/DEV24-REPORT.md)

## Research and validation

Meercata is also documented as an **applied network security research project**. The research portfolio describes goals, architecture, evidence interpretation, and planned experiments:

- [Research portfolio — goals, scope, and claims](docs/RESEARCH_PORTFOLIO.md)
- [System architecture and evidence interpretation](docs/ARCHITECTURE.md)
- [Experimental validation plan and report template](docs/VALIDATION_PLAN.md)
- [Dated research log and claims ledger](docs/RESEARCH_LOG.md)
- [Evidence-gated research roadmap](docs/ROADMAP.md)

Read validation reports alongside their recorded version, environment, and limitations. Source code, passing unit tests, and lab qualifications alone do not establish deployment-specific detection effectiveness, packet-blocking reliability, capacity, or production readiness.

## Operational data

Operational logs, raw EVE data, local credentials, rule archives, caches, and machine-specific configuration backups should remain outside the public repository. The Linux project's committed qualification records document bounded development checks and their limitations.
