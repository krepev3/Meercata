# Meercata v1.00

Meercata is a Python command-line and interactive utility for running Suricata in IDS or NFQUEUE inline IPS mode, managing Suricata YAML settings, inspecting events, and installing an optional systemd service.

Windows is supported for Npcap-based IDS, monitoring, configuration management, status, and WinDivert IPS when the installed Suricata build enables WinDivert. See [WINDOWS.md](WINDOWS.md) for setup and platform-specific commands.

## Safety model

- Non-interactive commands are dry-run unless `--apply` is supplied for firewall, process, YAML, backup, restore, and systemd changes. The interactive menu applies an edit only after its own prompt.
- Meercata-owned iptables/ip6tables hooks use dedicated `MEERCATA_*` chains and the `meercata-managed` comment.
- nftables hooks use the dedicated `inet meercata` table.
- Foreground IDS/IPS records whether the standard or Meercata inline service was active before launch. On normal exit, `Ctrl+C`, validation failure, or startup failure, it stops remaining Suricata processes, removes Meercata-owned NFQUEUE hooks, and restarts only the services that were previously active.
- Runtime restoration does not reset UFW, Docker, unrelated firewall rules, saved defaults, or Suricata YAML changes.
- `--fail-mode open` (the default) keeps traffic flowing if the NFQUEUE listener disappears. Use `--fail-mode closed` only when blocking all traffic is preferable to bypassing inspection.
- YAML changes receive unique backups, are written atomically, and are checked with `suricata -T` when Suricata is available. A rejected change is restored automatically.

## Requirements

- Linux with Python 3.10 or newer
- Suricata
- nftables or iptables; ip6tables is used when available
- systemd only for the optional inline service

Meercata has no third-party Python runtime dependencies. `pytest` is an optional test dependency and can be installed with `pip install -e '.[test]'`.

## Examples

```bash
./meercata
./meercata check
python3 main.py --help
python3 main.py check
python3 main.py --iface eth0 ids
python3 main.py --iface eth0 --backend auto --fail-mode open ips
sudo python3 main.py --apply --iface eth0 --backend nft ips
python3 main.py status
python3 main.py --config /etc/suricata/suricata.yaml yaml-summary
python3 main.py monitor --log /var/log/suricata/eve.json --trigger-log "./Trigger Drop-Alert.txt"
```

Global options must appear before the subcommand. Running `python3 main.py` opens the interactive menu.

The main interactive menu is organized as follows:

```text
1) Suricata control
2) Threat Monitoring (tail evidence continuously)
3) Rules / YAML
4) Hooks / firewall
5) Systemd unit
6) Set defaults (config/iface/queue/backend)
7) Check requirements
0) Quit
```

**Threat Monitoring** is a direct front-menu evidence viewer. It shows the last 100 lines from `Trigger Drop-Alert.txt` and follows appended records continuously until `Ctrl+C`, equivalent to `tail -n 100 -F`. The EVE-to-evidence collector remains available under **Suricata control → Monitor** and should run in another terminal when live collection is required.

## Requirement checks

Run the complete preflight report before first use or after changing the host configuration:

```bash
python3 main.py check
```

The report checks Python and Linux compatibility, Suricata and its NFQUEUE build support, configuration presence/readability/validity, the selected firewall backend, systemd availability, helper commands, privileges, and the configured interface. Missing required items cause exit status `1`; unavailable optional features are reported without failing the check.

Meercata also performs a smaller command-specific preflight automatically. Read-only commands are not blocked by unrelated optional dependencies. Commands using `--apply` require the binaries, permissions, configuration access, and privileges needed for that specific operation.

Running `python3 main.py` without arguments performs the full mandatory check before the interactive menu opens. If a required item is missing, startup stops, lists the unavailable requirements, and prints installation or configuration suggestions. The executable `./meercata` launcher additionally detects a missing Python installation or Python older than 3.10 before importing `main.py`.

If `/etc/suricata/suricata.yaml` is protected from the current user, run the check with appropriate privileges or provide a readable configuration using `--config`.

Before using `--apply` remotely, keep a separate recovery session available and make a firewall backup. Test the Suricata configuration and interface selection first.

## Alert and drop evidence logging

The built-in monitor appends every Suricata alert and every actual blocked/dropped/rejected event to a separate ANSI-free hunting-evidence text log. This includes detection-only alerts such as `ET TOR Known Tor Exit Node Traffic group 11`. An alert that also blocks traffic is recorded once as `[DROP ALERT]` rather than being duplicated.

Each evidence item is written as a labeled multi-line block. It preserves the Suricata event timestamp and the local collection timestamp, ET/rule source, signature, GID/SID/revision, severity, category, action, source/destination IP and port, protocol, and available application, flow, interface, IP-version, packet-source, and drop-reason fields.

While monitoring, Meercata builds a bounded in-memory IP-to-domain cache from DNS answers, TLS SNI, and HTTP hostnames in EVE. Alert/drop records include direct or previously observed DNS/domain context for their source or destination IP. When no trustworthy association has been observed, the record explicitly says `DNS / Domain : not observed` instead of guessing. The cache resets when the monitor restarts.

The interactive **Suricata control → Monitor** workflow prompts for the EVE input and evidence-log paths. The default is relative to the directory where Meercata is launched:

```text
./Trigger Drop-Alert.txt
```

Type `off` at the interactive evidence-log prompt to disable it. For an explicit path inside this project:

```bash
./meercata monitor \
  --log /var/log/suricata/eve.json \
  --trigger-log "$PWD/Trigger Drop-Alert.txt"
```

The older `--drop-log` option and `MEERCATA_DROP_LOG` environment variable remain accepted as compatibility aliases. The file is created when the first alert or actual drop occurs. Never use `eve.json` itself as the evidence-log destination. This is an operational hunting log, not a tamper-proof forensic container; hash or copy it to protected storage after collection when chain-of-custody matters.

## Tests

```bash
pytest
```

The test suite uses `.pytest_tmp` inside this project directory.

## Change history

### 2026-08-09 — Safety and reliability update

- Added dedicated `MEERCATA_INPUT`, `MEERCATA_OUTPUT`, and `MEERCATA_FORWARD` chains for owned iptables/ip6tables rules.
- Added the `meercata-managed` rule comment and the dedicated nftables `inet meercata` table.
- Added cleanup compatibility for NFQUEUE rules created by the earlier v1.00 implementation.
- Added automatic firewall cleanup when foreground Suricata exits or fails to start.
- Added consistent `--fail-mode open|closed` support for nftables and iptables.
- Added validation for interfaces, queues, allowlist addresses, protocols, ports, and rule filenames.
- Improved IPv4 and IPv6 allowlist handling.
- Removed shell redirection from firewall backup and restore operations.
- Corrected command failure reporting and nonzero CLI exit behavior.
- Corrected multi-interface `af-packet` and multi-setting NFQ parsing.
- Added atomic Suricata YAML writes, unique backups, `suricata -T` checks, and automatic restoration after validation failure.
- Made non-interactive YAML modifications obey dry-run mode unless `--apply` is supplied.
- Reworked the systemd unit lifecycle with a dedicated hook script, configuration testing, cleanup, restart control, and conflict protection against the standard Suricata service.
- Added Python packaging metadata and console entry points in `pyproject.toml`.
- Added automated firewall, rollback, YAML, and systemd tests; 19 tests pass.
- Added a local `.gitignore` for Python, pytest, and build artifacts.

### 2026-08-09 — Requirement and completeness audit

- Added the `check` command and interactive **Check requirements** menu option.
- Added command-specific automatic preflight checks for both CLI and interactive actions so missing unrelated tools do not block read-only functionality.
- Added checks for Python version, Linux, Suricata version, Suricata NFQUEUE support, configuration existence/readability/writability, `suricata -T` validation, firewall backend, firewall backup/restore helpers, systemd and Bash, optional pytest availability, interface selection, EVE log readability, and root privileges.
- Added support for both `NFQ support` and Suricata 8's `NFQueue support` build-info formats.
- Removed the interactive startup failure when Suricata is missing; the menu can now open and display the requirement report.
- Added nftables backup and validated restore support for the Meercata-owned table.
- Hardened status reporting when `systemctl` or `pgrep` is unavailable.
- Added validation and fallback for invalid environment and saved-default queue/backend/interface values.
- Added seven regression tests for requirement detection, status portability, and nftables backup/restore; 26 tests pass.

### 2026-08-09 — Automatic startup requirement gate

- Added `startup_requirement_check()` before the interactive application opens.
- Startup now stops safely when mandatory requirements are unavailable and lists only the failed mandatory checks.
- Added practical install/configuration suggestions for every required and optional check.
- Added suggestions to full `check` output and failed command-specific CLI/interactive checks.
- Added the executable `./meercata` source launcher to detect missing Python or Python older than 3.10 before `main.py` is imported.
- Added tests for remediation suggestions, startup blocking, and launcher shell syntax; 29 tests pass.

### 2026-08-09 — UAT legacy nftables backup fix

- UAT discovered an active legacy `inet suri` table created by the earlier v1.00 implementation.
- Extended firewall backup to save both `inet meercata` and legacy `inet suri` tables independently.
- Extended validated restore to restore either table independently without deleting the other restored table.
- Improved backup dry-run output to mention nftables coverage.
- Added regression coverage for legacy-table backup and restore; 30 tests pass.
- Added clean CLI Ctrl-C handling with exit status `130`; IPS shutdown still removes its hooks through the existing cleanup path.

### 2026-08-09 — UAT live IDS process detection fix

- Live IDS successfully captured DNS, TLS, IPv4, and IPv6 events on `wlan0` and shut down without leaving NFQUEUE hooks.
- UAT showed that Suricata renames its process to `Suricata-Main`, causing exact-name `pgrep`/`pkill` calls to miss a manually launched engine.
- Changed process detection and stopping to safely match the Suricata executable command line.
- Recorded a non-blocking AF_PACKET fanout/cluster-id warning observed during IDS UAT; packet capture still operated correctly.
- Added process-control regression coverage; 31 tests pass.

### 2026-08-09 — UAT live IPS diagnostics update

- Live fail-open IPS successfully inspected DNS/TLS traffic through NFQUEUE queue `4` while preserving gateway and internet access.
- Normal Ctrl-C shutdown removed the foreground process and `inet meercata` table automatically.
- Confirmed observed packet loss continued after IPS cleanup and therefore belongs to the Wi-Fi/network baseline.
- Added foreground Suricata process reporting to compact `diag` output so it no longer shows only the inactive systemd service during CLI IDS/IPS sessions.
- Added diagnostics regression coverage; 32 tests pass.

### 2026-08-09 — UAT event monitor verification

- Verified compact live formatting for DNS, TLS, mDNS, file-info, statistics, and alert events.
- Verified real ET rule alerts include signature source, SID/revision, protocol, ports, and application protocol.
- Verified generated `example.com` DNS and TLS traffic appears in the monitor.
- Corrected the generic CLI Ctrl-C message so stopping only the monitor no longer claims IDS/IPS cleanup occurred.

### 2026-08-09 — UAT systemd inline lifecycle verification

- Verified the systemd dry run produces the expected environment, fail-open nftables hook, Suricata configuration test, inline NFQUEUE command, and shutdown cleanup.
- Verified live installation enables and starts `suricata-inline.service`, launches Suricata on queue `4`, creates the owned `inet meercata` table, and preserves internet connectivity.
- Verified live removal stops the process, removes the service files and nftables hooks, and leaves connectivity working.
- UAT exposed an ambiguous diagnostic that reported only the inactive standard `suricata.service` while the Meercata inline service was active.
- Updated `diag` to report the standard Suricata service and `suricata-inline.service` independently.
- Normalized `systemctl` state output across versions that return different nonzero codes for an inactive or removed unit.
- Added regression coverage for explicit systemd unit queries and dual-service diagnostics; 34 tests pass.

### 2026-08-09 — Complete foreground exit restoration

- Added a centralized `restore_pre_run_state()` lifecycle function used by both foreground IDS and IPS.
- Records active `suricata.service` and `suricata-inline.service` state before stopping either service for a foreground run.
- On `Ctrl+C`, normal exit, validation failure, or startup failure, stops any remaining Suricata engine, removes Meercata-owned nftables and iptables/ip6tables NFQUEUE hooks, and restarts only services that were active before launch.
- Kept cleanup ownership-scoped: UFW, Docker, unrelated firewall rules, YAML configuration, and saved defaults are not reset.
- Added IDS and IPS interruption regression tests; 36 tests pass.

### 2026-08-09 — Actual drop-event audit log

- Added configurable `--drop-log` support to Meercata and the built-in monitor, defaulting to `/var/log/suricata/meercata-drops.log`.
- Added an interactive drop-log prompt with `off` support and custom paths, including filenames containing spaces.
- Logs only events EVE identifies as actually dropped, blocked, or rejected; detection-only ET alerts are not mislabeled as drops.
- Added ANSI-free drop records containing action, endpoints, protocol, ET/rule signature, SID/revision, application protocol, and drop reason when available.
- Highlights blocked alerts as `[DROP ALERT]` in the live display and prevents the EVE input file from being reused as the drop-log output.
- Added drop detection, text output, file append, and monitor argument regression tests; 40 tests pass.

### 2026-08-09 — Alert and drop hunting evidence expansion

- Expanded the monitor audit file to include every Suricata alert, including allowed ET detections such as known Tor exit-node traffic, as well as actual drops, blocks, and rejects.
- Renamed the preferred option to `--trigger-log` while retaining `--drop-log` and `MEERCATA_DROP_LOG` as compatibility aliases.
- Changed the default evidence filename to `./Trigger Drop-Alert.txt`, placing it in the directory from which Meercata is launched.
- Added hunting fields for severity, category, action, flow ID, interface, IP version, and packet source when EVE provides them.
- Prevented duplicate records when an alert is also a drop by classifying it as one `[DROP ALERT]` entry.
- Added exact ET Tor alert evidence regression coverage; 41 tests pass.

### 2026-08-09 — Readable timing, IP, and DNS evidence

- Reworked each alert/drop audit entry into a labeled multi-line block for easier human review.
- Added both the original Suricata `Event time` and Meercata `Collected at` timestamp.
- Separated source and destination IP addresses and ports into explicit evidence fields.
- Added direct domain extraction from DNS, TLS SNI, and HTTP hostnames.
- Added a bounded live DNS cache that correlates observed IPv4/IPv6 answer addresses with later alert/drop endpoints.
- Uses `not observed` when no trustworthy domain association exists rather than inventing DNS context.
- Added timing, endpoint, readable-format, and DNS-correlation regression coverage; 42 tests pass.

### 2026-08-09 — Front-menu Threat Monitoring

- Added **Threat Monitoring** directly to the main interactive menu as option `2`.
- Reordered the remaining front-menu entries while keeping all existing functionality available.
- Reused the same continuous built-in monitor and readable `Trigger Drop-Alert.txt` alert/drop evidence collector.
- Displays the resolved evidence path, warns when no Suricata process is detected, and runs until `Ctrl+C`.
- Kept the original monitor entry under **Suricata control** for compatibility.
- Added front-menu routing regression coverage; 43 tests pass.

### 2026-08-09 — Continuous evidence-tail correction

- Corrected front-menu **Threat Monitoring** to act as the evidence viewer rather than launching a second EVE collector.
- Shows the last 100 lines and follows file recreation and newly appended records using the equivalent of `tail -n 100 -F -- FILE`.
- Creates the selected evidence file when absent, resolves its full path, and continues until `Ctrl+C`.
- Leaves evidence collection and the evidence file untouched when the viewer stops.
- Kept EVE monitoring and evidence generation under **Suricata control → Monitor**.
- Added exact tail-command regression coverage; 44 tests pass.

### 2026-08-16 — Native Windows compatibility

- Added Windows discovery for `suricata.exe`, `suricata.yaml`, EVE logs, Npcap, capture targets, and per-user defaults.
- Added a Windows launcher, process/service diagnostics, administrator checks, and child-only Npcap DLL path handling.
- Added Npcap/pcap IDS commands and WinDivert IPS commands with static build-capability detection.
- Prevented Linux NFQUEUE, firewall, and systemd operations from running on Windows.
- Added a bounded Suricata runtime probe so applied commands cannot stop services before a broken engine is detected.
- Added native Python evidence following and Windows defaults to the EVE monitor.
- Added Windows setup documentation and regression coverage; 49 tests pass and 2 Linux-only shell syntax tests are skipped on Windows.

Future functional, safety, configuration, CLI, or packaging changes should be recorded in this section with their date and verification result.
