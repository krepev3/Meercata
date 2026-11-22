# Meercata v2.00

Meercata v2.00 is the production-hardening track for the Python Suricata controller. It is a CLI-only application with no GUI. It is intentionally separate from Meercata v1.00 so the tested v1 implementation remains available as a stable reference while the control plane is redesigned safely.

## Current status

**Phase 4 monitoring-delivery foundations and the Phase 5 installed fail-open IPS lifecycle gates are complete through dev24; dev25 adds installed monitoring/retention qualification — not production-ready.**

The Python package provides durable transaction primitives, recovery inspection, versioned read-only health collection, isolated RuleOps qualification, socket mediation, and package-owned privilege/supervision. Dev12–dev22 qualified readiness, RuleOps, regression, repository delivery, recovery, fail-open nftables/NFQUEUE, bounded overload, the installed private IPS lifecycle, and durable local monitoring. Dev23 adds scheduled-run freshness, a crash-safe bounded outbox, verified-HTTPS connector contract, exponential retry, durable receipts, and dead letters. Dev24 qualifies real loopback HTTPS, token/CA rotation, collector deduplication, persistent outage recovery, and a delivery-pressure watchdog. Public live rule promotion and IPS activation remain deliberately absent from the CLI while real collector/credential availability, deployment-specific capacity, soak, and release-operations gates remain open.

Dev25 provides a two-stage disposable Debian 13 VM gate for installed monitoring,
service-user permissions, credential/CA rotation, timer freshness, log retention,
bounded disk-full behavior, and reboot recovery. See [the VM procedure](MONITOR-SYSTEMD-VM.md)
and the separately recorded dev25 evidence/report for the executed results.

## Implemented CLI

```text
meercata                         # terminal menu when stdin/stdout are terminals
meercata menu                    # explicitly open the terminal menu
meercata --version
meercata paths [--json]
meercata health [--json]
meercata health --watch [--json] [--interval SECONDS]
meercata monitor run [--json]
meercata monitor status [--json]
meercata monitor events [--json] [--limit 1..100]
meercata monitor freshness [--json]
meercata monitor deliver [--json]
meercata monitor delivery-status [--json]
meercata monitor delivery-health [--json]
meercata monitor dead-letters [--json] [--limit 1..100]
meercata transactions list [--incomplete | --recovery-required] [--json]
meercata transactions show TRANSACTION_ID [--json]
meercata rules status [--json]
meercata rules stage [--json]
meercata rules diff CANDIDATE_ID [--json]
meercata rules validate CANDIDATE_ID [--json]
meercata rules regress CANDIDATE_ID PACK_ID [--json]
meercata rules promote CANDIDATE_ID  # gated pending installed-host qualification
```

There is no GUI, web server, remote API, or generic command-execution interface.

## Interactive terminal menu (development addition after dev24)

From this source directory, launch `python3 -m meercata` or `python3 main.py`.
The installed `meercata` launcher opens the same menu. Use `meercata menu` to
request it explicitly. Input and output must both be terminals; without a
terminal, no-argument invocation retains help/exit 2 and explicit `menu` refuses
to prompt. Existing subcommands, JSON output, and service invocations are unchanged.

```text
1) Suricata control
2) Threat Monitoring / health events
3) Rules / YAML
4) Hooks / firewall
5) Systemd / supervision
6) Configuration / paths (read-only)
7) Check requirements / health
8) Transactions / recovery
0) Quit
```

The familiar banner/menu wraps the existing v2 CLI. It opens without installed
configuration or root privileges. Opening/navigating it only reads the health
configuration; health/service status is explicitly **not checked** until a health
refresh is selected. The dashboard then labels that timestamped snapshot as the
last observation. A configured mode does not imply a running IDS or IPS service.
Use health watch for continuous sampling and Ctrl+C to return to the menu.

Working actions include health, monitor history/freshness, HTTPS queue/receipt
status and delivery health, candidate status/diff/validation/PCAP regression,
ET/Open staging, fixed paths, and transaction inspection. Actions that write
monitor/candidate state or send events require an explicit in-menu confirmation
(default no). Backend permissions and validation remain in effect; the menu
does not grant privileges or accept shell commands. Missing configuration and
permission failures leave navigation available. `0` or Enter goes back/quits;
EOF exits, and Ctrl+C at the main prompt exits with code 130. `NO_COLOR` disables
the orange banner; `TERM=dumb` also disables screen clearing.

The original EVE alert/drop evidence viewer, IDS/IPS start/stop, direct YAML
editing, editable defaults, and service/firewall mutations are visibly marked
unavailable or gated. **Health-transition events are not threat-alert evidence.**
Public rule promotion remains gated. This restores terminal navigation, not all
v1 functionality. It adds no runtime dependency and does not change the frozen
dev24 evidence. Dev25's installed monitoring/retention VM gate is a separate milestone.

## Implemented Phase 1 foundation

- typed actor, command-result, transaction, state-history, and error models;
- fixed production paths and isolated test paths;
- non-blocking single-controller mutation lock;
- structured append-only JSONL audit records;
- allowlisted fixed-argv subprocess execution with a clean environment, timeouts, process-group termination, and bounded output;
- atomic, size-bounded transaction and last-known-good state storage;
- snapshot, stage, validate, apply, verify, commit, rollback, and recovery orchestration;
- recovery discovery for interrupted and partially committed transactions.

## Implemented Phase 2 health

- stable health-v1 JSON schema and exit codes 0 healthy, 1 degraded, 2 critical, and 3 unknown/configuration error;
- one-shot, JSON, and continuous watch CLI output;
- systemd readiness, exact process, interface, Suricata socket, capture mode, and capture-interface checks;
- EVE freshness and packet-progress/stall checks;
- packet-drop, TCP reassembly-gap, memcap/emergency, disk, memory, RSS, and sampled CPU checks;
- IPS nftables queue/interface/bypass/counter and NFQUEUE listener/drop checks;
- bounded read-only Suricata 8 socket protocol with mutating commands denied;
- production socket reads mediated through the exact no-argument privileged health snapshot.

## Implemented Phase 3 RuleOps development pipeline

- strict ET/Open-only configuration and fixed Suricata paths;
- UUID-owned candidate directories, atomic manifests, hashes, rule/action counts, and duplicate detection;
- bounded added/removed/changed identity differences and unexpected-reduction policy;
- fixed-argv `suricata-update` staging with reload disabled;
- explicit `suricata -T -S --init-errors-fatal` candidate validation;
- immutable fixed-path PCAP packs with pinned hashes and required/forbidden alert oracles;
- bounded offline replay and EVE evaluation recorded against candidate and pack hashes;
- required structured audit events for staging and validation;
- narrow non-blocking reload polling and failed-rule verification;
- transaction-backed promotion, post-reload health verification, rollback reload, and recovery-failure classification;
- production CLI promotion gate until the Phase 4 boundary passes installed-host qualification.

## Initial Phase 4 privilege boundary

- Python-only helper with fixed RuleOps, health snapshot, transaction-bound nftables, and emergency-bypass operation identifiers;
- transaction UUID as the only helper operand; candidate and destination paths are derived internally;
- active controller-lock and exact transaction-state authorization;
- root-private candidate sealing, independent strict validation, and independent PCAP replay;
- durable activation intent, atomic active-file replacement, directory synchronization, and idempotent receipts;
- rollback ownership proof that refuses to overwrite unrelated administrator changes;
- fixed non-interactive sudo client argv and anchored sudoers command/UUID policy;
- reviewed tmpfiles ownership/mode template and separate privileged audit stream;
- helper-owned non-blocking reload, active-hash verification, failed-rule checks, and idempotent applied/rollback receipts;
- dedicated health service identity with no RuleOps authorization;
- readiness-aware Suricata override and bounded periodic health-monitoring unit templates.
- Python-only deterministic production image builder with fixed inventory, modes, hashes, upgrade preflight, verification, and read-only removal planning.
- Python-only staged-image qualification using real isolated Python imports, sudoers parsing, systemd verification, disposable sysusers materialization, and tmpfiles dry-run.
- Guarded root-owned installation qualification in the pinned official Debian 13 container, with actual sysusers/tmpfiles application, ownership, launcher, sudo authorization, systemd, and data-preservation checks.
- Reproducible native Debian binary-package builder and narrowly reviewed POSIX-shell lifecycle hooks with install, idempotent configure, upgrade-integrity, removal-order, and data-preservation contracts.
- Official Debian 13 Backports Suricata 8.0.6 package qualification with authenticated metadata, runtime capability gates, strict configuration validation, and dependency-satisfied Meercata install/removal isolation.
- Hash-pinned Debian 13 KVM qualification with systemd PID 1, live Suricata notification readiness, root-owned socket mediation, 15 healthy IDS checks, and sandboxed health timer execution.
- Root-only, hash-pinned Debian 13 KVM RuleOps qualifier requiring two independently validated and PCAP-approved candidates, a committed non-blocking reload, a forced post-reload rollback, restoration reload, final health, receipts, and audit evidence.
- Original seven-case production regression baseline with deterministic positive DNS/HTTP/TCP/UDP and benign DNS/HTTP/TLS captures.
- Network-isolated signed APT repository qualification with explicit key pinning, independent signature verification, metadata/package tamper rejection, authenticated install, authenticated upgrade, and safe removal.
- Two-phase, hash-pinned Debian 13 KVM crash/restart-limit/reboot qualification with a root-private sealed marker, timer execution, 15/15 post-reboot health, and protected-file integrity checks.
- Guarded disposable-network live NFQUEUE qualification with deterministic accepted and blocked HTTP paths, kernel listener/counter evidence, listener-loss fail-open proof, and a clearly non-capacity bounded timing sample.
- Cgroup-bounded NFQUEUE load qualification with mixed verdict correctness, queue/resource/Suricata degradation counters, `SIGKILL` listener loss during traffic, controlled listener-present saturation, and explicit `queue-overload` emergency bypass.
- Private installed `meercata-ips.target` with listener-first startup, policy-first shutdown, a 500 ms listener/drop guard, fixed failsafe removal, distro-Suricata exclusion, and no independently enabled component units.
- Two-phase Debian 13 KVM qualification of guard/engine failure, complete fail-open stop, reboot auto-recovery, protected-file integrity, least-privilege IPS health, and disabled/inactive cleanup.
- Durable SHA-256-bound health transitions with deduplication, recovery events, interruption repair, service-owned state/log isolation, journal output, bounded history, and logrotate policy.
- Real loopback TLS qualification and an independent delivery-health timer covering retries, age, backlog, and dead letters; private CA bundles remain root-controlled.
- Root-configured verified-HTTPS monitoring delivery with a crash-safe bounded outbox, idempotency keys, exponential retry, synchronized receipts, dead letters, and an independent freshness watchdog.

## Relationship to v1.00

- `Meercata v1.00` remains the frozen functional reference.
- Its latest recorded baseline is 44 passing automated tests plus completed live IDS, IPS, systemd, monitoring, cleanup, YAML, and firewall UAT.
- v1 source files are not copied blindly into v2.
- Proven v1 behavior may be migrated module by module only after v2 safety contracts and tests exist.
- Threat evidence produced by v1 is user data and is never treated as source code or copied into v2 automatically.

## Production objective

Python remains the control plane. It validates requests, stages changes, calls fixed system tools, audits operations, monitors health, and performs recovery. Suricata and the Linux kernel remain the data plane and continue handling packets.

```text
Operator CLI / automation
          |
          v
Unprivileged Meercata control plane
  validation | policy | health | audit
          |
          v
Restricted privileged operations
  systemd | Suricata socket | nftables/NFQUEUE
          |
          v
Suricata + kernel packet-processing data plane
```

## Core production principles

1. Every mutation is locked, staged, validated, audited, verified, and recoverable.
2. No controller input is passed through a shell.
3. Privileged operations are narrow, explicit, and deny by default.
4. Meercata automatically restores only state it owns.
5. Fail-open or fail-closed behavior is explicit across every failure path.
6. A successful command is not a successful deployment until post-change health checks pass.
7. Threat evidence and controller audit logs are separate data products.
8. Production behavior must be testable with PCAP, integration, failure-injection, load, and recovery tests.
9. v1 compatibility is preserved deliberately, not assumed.

## Documents

- [Production roadmap](PRODUCTION-ROADMAP.md)
- [Architecture decisions](ARCHITECTURE-DECISIONS.md)
- [Threat model](THREAT-MODEL.md)
- [Privileged-operation inventory](PRIVILEGED-OPERATIONS.md)
- [V1 reference manifest](V1-REFERENCE-MANIFEST.json)
- [Health contract](HEALTH.md)
- [RuleOps contract](RULEOPS.md)
- [Live RuleOps VM qualification](RULEOPS-VM.md)
- [Privileged helper contract](PRIVILEGED-HELPER.md)
- [Supervision contract](SUPERVISION.md)
- [Production packaging contract](PACKAGING.md)
- [Native Debian package contract](NATIVE-DEBIAN.md)
- [Signed APT repository qualification](APT-REPOSITORY.md)
- [Crash and reboot recovery qualification](RECOVERY-VM.md)
- [Installed IPS systemd lifecycle](IPS-SYSTEMD.md)
- [Durable monitoring contract](MONITORING.md)
- [Installed monitoring and retention VM qualification](MONITOR-SYSTEMD-VM.md)
- [Suricata package qualification](SURICATA-PACKAGES.md)
- [Staged-image qualification contract](QUALIFICATION.md)
- [Change log](CHANGELOG.md)

## Development verification

```bash
python3 -m pytest -q
python3 -m meercata --version
python3 -m meercata paths --json
python3 -m meercata health --json
python3 -m meercata transactions list --json
python3 -m meercata rules status --json
python3 -m meercata.package_builder --help
python3 -m meercata.package_qualifier --help
python3 -m meercata.container_qualifier --help
python3 -m meercata.debian_package --help
python3 -m meercata.debian_lifecycle_qualifier --help
python3 -m meercata.systemd_vm_qualifier --help
python3 -m meercata.ruleops_vm_qualifier --help
python3 -m meercata.apt_repository_qualifier --help
python3 -m meercata.recovery_vm_qualifier --help
python3 -m meercata.ips_systemd_vm_qualifier --help
python3 -m meercata.monitor_qualifier --help
python3 -m meercata.monitor_delivery_qualifier --help
python3 -m meercata.monitor_tls_qualifier --help
```

## Planned production filesystem layout

```text
/etc/meercata/          root-owned production configuration
/usr/lib/meercata/      installed and versioned Python package
/var/lib/meercata/      state, transactions, snapshots, last-known-good
/var/log/meercata/      controller audit and operational logs
/run/meercata/          lock, PID, socket, and temporary runtime state
```

Development files remain in this project folder. Production services must not execute directly from a mutable Git working tree.

## Change discipline

Every functional, security, configuration, packaging, or operational change must:

1. be recorded in `CHANGELOG.md`;
2. state its production requirement and acceptance criteria;
3. include automated tests;
4. preserve or explicitly migrate compatibility;
5. include rollback behavior;
6. pass the relevant dry-run, failure, and live UAT gate before release.
