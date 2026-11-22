# Meercata v2.00 Change Log

All notable v2 changes are recorded here. Entries must state the scope, affected production requirement, verification performed, and rollback or compatibility impact.

## Unreleased — Terminal operator menu after dev24 (2026-11-08)

### Scope and production requirement

- Restore the familiar MEERCATA banner and numbered terminal navigation over
  existing v2 health, monitoring, delivery, RuleOps and transaction commands.
- Add explicit `meercata menu`, automatic menu entry only on interactive
  no-argument invocation, and the source-tree `python3 main.py` entry point.
- Keep navigation available without installation or active configuration. Show
  configured mode separately from timestamped, explicitly refreshed health.
- Require default-no confirmation for state-writing/testing/delivery actions;
  preserve all existing privilege, argument-validation and release boundaries.
- Identify the unmigrated threat-evidence viewer, IDS/IPS lifecycle, YAML/default
  editing and service/firewall controls explicitly. Health events are not threat
  evidence. No private mutation or public rule-promotion gate is opened.

### Verification

- Added menu/CLI tests for navigation, command routing, confirmation, UUID/pack
  input rejection, missing configuration, permission failures, terminal output,
  health refresh/watch interruption, EOF and noninteractive compatibility.
- Extended package inventory coverage to require the menu module. All 503 v2
  tests passed (including 59 new menu cases) in 44.78 seconds.
- Real terminal smoke tests passed through both `python3 main.py` and
  `python3 -m meercata`: opening without configuration, health refresh returning
  unknown, gated IPS refusal, submenu navigation, empty transaction inspection,
  screen clearing and clean exit. No host service/firewall configuration changed.

### Compatibility and rollback

- Scripted commands and JSON contracts are unchanged. Redirected no-argument
  execution retains help/exit 2; explicit `menu` requires terminal input/output.
- No new Python dependency, service, helper permission or configuration format.
  Version remains the dev24 development baseline pending the next release;
  historical dev24 artifacts and qualification evidence are unchanged.
- Reverting the menu module, CLI entry routing and source launcher restores the
  prior help-only entry behavior. No runtime-data migration is required.

## 2026-10-09 — Dev24 loopback HTTPS and delivery-health qualification

### Added and corrected

- Completed the disposable loopback HTTPS qualifier with strict CA/hostname checks, real token retirement, collector idempotency, retry persistence across a fresh worker, recovery, and on-disk CA rotation. The ordinary configuration/token/CA loader handles queued delivery.
- Corrected the generated test CA's mandatory key-usage extensions for strict Python TLS verification. Collector sockets and threads close on exceptions, and handshakes/requests have bounded timeouts.
- Completed `monitor delivery-health` and its independent one-minute systemd watchdog: queue count, oldest age, retries, dead letters, last receipt, stable JSON, and exit codes 0/1/2/3. Corrupt dead letters and ambiguous timestamps fail visibly.
- Completed the root-controlled optional private CA configuration, package launcher/schema inventory, timer lifecycle ordering, CLI manual, and operational documentation. The watchdog needs no token or network access.
- Added a strict twelve-check evidence schema, live TLS/cleanup tests, CLI threshold boundaries, actual durable backlog tests, and CA permission/path refusal coverage. Historical dev22/dev23 evidence remains unchanged; rerun local qualifiers report the actual package version.
- Advanced the development version to `2.0.0.dev24` and declared the JSON-schema test dependency.

### Production requirements addressed

- Verified HTTPS transport, credential/trust rotation, durable retry and recovery, collector deduplication, independent delivery-pressure visibility, and bounded private-CA loading.

### Verification

- All twelve real loopback TLS/delivery-health checks passed; evidence is retained as `qualification-evidence/monitor-tls-dev24.json`.
- The complete v2 regression suite passed 444 tests, and the frozen v1 suite passed all 44 tests. These include static systemd validation and real disposable TLS/Unix sockets.
- Staged image, root-owned Debian 13 container, and deterministic native package reports are retained separately under `qualification-evidence/` for this milestone.

### Compatibility and rollback

- Existing monitor commands remain compatible. System trust is used when `ca_file` is omitted; TLS verification is always enabled. Installation supplies no active configuration/token and enables no service.
- Delivery timer enablement includes the delivery-health watchdog. Removal stops the watchdog before delivery and preserves durable state and credentials.
- Removing the TLS qualifier/schema/launcher, private-CA option, delivery-health command/units, and version bump restores the dev23 delivery scope; stop the new watchdog before package rollback.
- This gate uses a disposable local collector. Production endpoints/secrets, installed monitor timer execution, external DNS/proxy/availability, long-duration retention/soak, deployment traffic capacity, and release operations remain unqualified.

## 2026-08-26 — Dev23 durable monitor delivery foundation qualified

### Added and corrected

- Added deterministic event IDs and a mode-0600 durable outbox for every health transition. The latest durable transition must be queued before a newer transition can be recorded, making capacity/backpressure fail closed without silently skipping delivery.
- Added a fixed verified-HTTPS JSON POST connector with an `Idempotency-Key`, root-controlled endpoint and token path, bounded response reads/timeouts/batches, no redirect handling, and no CLI endpoint, token, executable, or header surface.
- Added bounded exponential retry for network/TLS, HTTP 408/425/429, and 5xx outcomes; permanent rejection or attempt exhaustion moves the envelope to a bounded dead-letter directory.
- Added synchronized delivery/dead-letter receipts, receipt-first restart reconciliation, bounded status/dead-letter inspection, strict schemas, symlink/shape/hash/size/count refusal, and explicit at-least-once collector semantics.
- Added `monitor freshness` with a fixed three-minute threshold and independent hardened freshness timer. Added an opt-in delivery service/timer with no capabilities, `NoNewPrivileges`, network address-family restriction, and writes limited to monitor roots.
- Added the root-controlled credential directory, rotation for delivery receipts, safe package-removal ordering, three delivery/freshness schemas, an eight-check qualifier/evidence report, and fixed package inventory. Advanced the development version to `2.0.0.dev23`; Python remains the only implementation language and the application remains CLI-only.

### Production requirements addressed

- Scheduled-monitor staleness detection, durable transition handoff, bounded retry/backoff, permanent-failure visibility, restart-safe local acknowledgment, credential isolation, and a central HTTPS connector boundary.

### Verification

- The deterministic eight-check gate passed enqueue, duplicate suppression, deferred retry, eventual acceptance, permanent rejection/dead-lettering, receipt-first crash reconciliation without a second transport call, stale-observation detection, and non-HTTPS endpoint refusal. Evidence is retained in `qualification-evidence/monitor-delivery-dev23.json`.
- Unit coverage verifies verified-TLS context construction, fixed POST path/headers, HTTP classification, root-scoped token validation, corrupt-envelope refusal, strict JSON schemas, bounded CLI exits, package removal ordering, thirteen systemd units, and twelve tmpfiles directories.
- The complete v2 suite passed 421 tests and the frozen v1 suite passed all 44 tests. Two final native dev23 packages were byte-identical; the build report is retained separately from the artifact.

### Compatibility and rollback

- Dev22 transition/status/event behavior and schemas remain compatible. Existing transition history is not bulk-replayed; the latest durable transition is enrolled when monitoring next runs.
- Installation creates no token, installs no active configuration, and enables no timer. Delivery remains inactive until an operator provisions the approved endpoint/token and explicitly enables its timer.
- Removing the delivery/freshness units, outbox module/schemas/config table, qualification assets, and version bump restores dev22 local-only monitoring. Runtime outbox, dead letters, receipts, transitions, and state remain preserved data on normal package removal.
- No real collector, production credential, certificate rotation, proxy, collector availability, or long-duration soak was qualified; those remain deployment gates.

## 2026-08-26 — Dev22 durable health-transition monitoring qualified

### Added and corrected

- Added CLI-only `monitor run`, `monitor status`, and bounded `monitor events` commands with a stable `monitor-v1` JSON observation contract.
- Added SHA-256 condition fingerprints, monotonic transition sequences, baseline/severity/condition/recovery reasons, bounded affected-check summaries, and identical-observation deduplication with consecutive counts.
- Added mode-0600 durable state and append-only transition JSONL below service-owned mode-0700 directories, a separate non-blocking writer lock, append-before-state ordering, file/directory synchronization, and state repair from the newer durable event after interruption.
- Added fail-closed schema, symlink, regular-file, status/hash, 256 KiB record/state, 10,000 active-event, and 8 MiB active-log boundaries. Unexpected health collection failures become visible `unknown` transitions instead of unhandled tracebacks.
- Added a hardened `meercata-monitor.service` and persistent one-minute timer that conflicts with the legacy raw health timer, exposes structured results through journald, and can write only the three monitor directories. Installation does not enable either timer.
- Added a 4 MiB/weekly, 12-generation compressed logrotate contract, explicit `logrotate` package dependency, safe removal ordering, monitoring contract, deterministic seven-check qualifier/schema/evidence, and fixed package inventory.
- Advanced the development version to `2.0.0.dev22`. No GUI, webhook, SMTP, external SaaS, credential, caller-selected executable, or new implementation language was added.

### Production requirements addressed

- Alert deduplication, condition and recovery transitions, crash-safe local delivery, bounded status/history inspection, service-user write isolation, journal collection point, and finite active-log/rotation policy.

### Verification

- The seven-check disposable qualification passed critical baseline, duplicate suppression, same-severity condition change, recovery, missing-state repair without duplicate events, invalid-state refusal, and oversized-log refusal. The schema-valid report is retained in `qualification-evidence/monitoring-dev22.json`.
- Staged systemd verification includes both monitor units; tmpfiles qualification now covers nine directories with three monitor paths owned only by `meercata`; package removal stops the monitor timer/service before health authorization is removed.
- The complete v2 suite passed 405 tests and the frozen v1 suite passed all 44 tests. Two final native dev22 packages were byte-identical; the build report is retained separately from the artifact.

### Compatibility and rollback

- Direct `health`, its JSON schema, watch mode, and legacy health timer remain available. Starting the new monitor timer stops the legacy timer to prevent duplicate scheduled collection.
- Monitor state and transition history are data, not package payload, and survive normal removal. Removing the monitor units, logrotate policy, service-owned directories, module/schema/contract, qualifier, and version bump restores dev21 scheduled-health behavior.
- External collector credentials, network delivery/retry/dead-letter behavior, stale-timer alerts, and long-duration soak remain deployment gates; the local qualifier does not claim them.

## 2026-08-25 — Dev21 installed fail-open IPS systemd lifecycle qualified

### Added and corrected

- Added a private `meercata-ips.target` lifecycle with a readiness-aware Suricata NFQUEUE engine, transactional policy activation, and a 500 ms listener/drop guard. Component units cannot be enabled independently and stop in fail-open order.
- Added fixed root-only engine, bootstrap, guard, status, and configuration-independent failsafe launchers. The engine forwards only a validated systemd notification socket into its clean environment; no caller-selected executable, unit, path, table, or ruleset is accepted.
- Added listener-first startup, policy-before-listener shutdown, distro-Suricata exclusion, durable activation/emergency receipts, any-drop overload bypass, listener-loss bypass, and an `ExecStopPost` failsafe for both guard failure and normal shutdown.
- Extended the no-argument health snapshot to mediate the fixed Suricata socket, owned nftables table, and kernel NFQUEUE status. IPS health now recognizes `NFQ#QUEUE`, uses the NFQ interface packet counter, and the hardened health unit retains only the capabilities required for identity change, fixed reads, audit, and nftables query.
- Added a two-phase, root-only, hash-pinned Debian 13 KVM qualifier covering installed package identity, listener-first activation, guard and engine `SIGKILL`, inactive fail-open shutdown, a changed boot ID, automatic recovery, 17/17 least-privilege IPS health checks, protected-file integrity, and disabled/inactive cleanup.
- Added the strict qualification schema, launcher, systemd operating contract, package inventory, removal ordering, and automated unit/policy coverage. Advanced the development version to `2.0.0.dev21`; public IPS activation remains deliberately absent from the CLI.

### Production requirements addressed

- Installed IPS supervision, readiness, dependency ordering, listener-loss and overload response, root/helper separation, reboot recovery, protected state integrity, and deterministic fail-open cleanup.

### Verification

- The decisive disposable KVM run used official Debian 13 and exact Backports Suricata `1:8.0.6-1~bpo13+1` plus suricata-update `1.3.8-1~bpo13+1`.
- Both bounded `SIGKILL` cases removed the owned policy, ordinary stop left the target and all three components inactive with no Meercata table, and reboot restored the target, listener, transaction-owned policy, guard, and fully healthy service-user monitoring.
- All eleven schema-valid checks passed and cleanup disabled/stopped the target and removed the policy. Evidence is retained in `qualification-evidence/ips-systemd-vm-dev21.json`.
- The complete v2 suite passed 390 tests and the frozen v1 suite passed all 44 tests. Two final native dev21 packages were byte-identical; the build report is retained separately from the artifact.

### Compatibility and rollback

- Dev21 does not expose a public CLI activation command, enable the target during package installation, change an unrelated firewall table, or authorize the health identity for RuleOps or mutable nftables operations.
- Operators must stop the target, wait for all components to become inactive, and then start it; a single target `restart` is not a safe grouped restart. Package removal disables/stops the target before removing health authorization or runtime launchers while preserving configuration, receipts, and audit data.
- Removing the private units/launchers/qualifier/schema/contract and version bump restores dev20 behavior; the fail-open target must be stopped first.

## 2026-08-25 — Dev20 bounded NFQUEUE load and overload gate qualified

### Added

- Added a guarded Python-only six-second mixed-load profile with eight accepted-transfer workers, four blocked-flow workers, deterministic payload hashing, measured latency/goodput, nftables counter progress, and zero-tolerance normal NFQUEUE transport drops.
- Added bounded Suricata CPU/RSS/thread sampling and EVE IPS, NFQ-error, memcap-pressure, flow-emergency, TCP gap/memcap-drop, and alert-overflow evidence.
- Added `SIGKILL` listener-loss injection while accepted traffic remains active, a 90% minimum completion floor, zero corruption requirement, and formerly blocked-port fail-open recovery.
- Added controlled listener-present saturation using a 16-packet Suricata pending profile, 128 connections/64 workers, observed queue-drop proof, transaction-bound `queue-overload` emergency bypass, and exact post-bypass payload recovery.
- Added mandatory cgroup CPU/RAM/PID limits, read-only-container contract, strict schema/evidence, unit coverage, documentation, and package inventory integration.
- Advanced the development version to `2.0.0.dev20`; public IPS lifecycle commands remain disabled.

### Production requirements addressed

- Bounded concurrent verdict correctness, normal queue integrity, resource/degradation telemetry, crash-time fail-open continuity, saturation detection, and explicit overload recovery.

### Verification

- The decisive ten-check run passed 227 accepted payloads and 68 intended blocked flows with zero failure, corruption, unexpected accept, normal kernel queue drop, or userspace queue drop.
- Synthetic goodput was 303.951 Mbit/s with 206.656 ms median and 310.134 ms p95 transfer latency. Suricata peak RSS was 69,922,816 bytes; NFQ errors, flow emergency, TCP gaps/memcap drops, and alert overflow were zero.
- All 1370 completed transfers succeeded across injected listener `SIGKILL`. Controlled saturation produced three kernel queue drops; emergency bypass removed the owned policy and restored the deterministic 1 MiB payload.
- The schema-valid result is retained in `qualification-evidence/nfqueue-load-dev20.json`. The complete v2 suite passed 356 tests and the frozen v1 suite passed all 44 tests.
- Two final native dev20 packages were byte-identical; the build report is retained separately from the artifact.

### Compatibility and rollback

- No host firewall, service, route, address, cgroup, or module-loading command was changed. All live mutations and load remained inside the bounded disposable container; its derived image is removed after qualification.
- Dev20 does not enable automatic production bypass or public IPS commands. Removing the load qualifier, schema, evidence, contract, package entries, and version bump restores dev19 behavior.

## 2026-08-22 — Dev19 live NFQUEUE functional gate qualified

### Added

- Added a guarded Python-only routed client → Meercata gateway → server harness inside a `--network none` Debian 13 container with explicit forwarding and child network namespaces.
- Added real dev18 policy activation on queue 42, Suricata NFQueue capability/configuration validation, kernel listener inspection, directional nftables counter proof, deterministic 1 MiB accepted traffic, a private-SID blocked path with EVE action proof, and listener-loss fail-open delivery on the formerly blocked port.
- Added a five-transfer min/median/max latency and aggregate-throughput sample labelled strictly as bounded functional evidence, not production capacity.
- Added bounded process groups/cleanup, the strict `nfqueue-functional-qualification-v1` schema, unit coverage, operating contract, and package inventory integration.
- Advanced the development version to `2.0.0.dev19`; public IPS activation remains disabled.

### Production requirements addressed

- Reproducible routed NFQUEUE functional topology, explicit accept/drop oracles, listener identity and queue counters, blocking evidence, listener-loss fail-open proof, and safe namespace cleanup.

### Verification

- The complete v2 suite passed 346 tests and the frozen v1 suite passed all 44 tests.
- The decisive guarded run passed all nine checks. Queue 42 attached with zero initial kernel/userspace drops; the accepted 1 MiB payload matched SHA-256 `e335c89377c278eabfd5fca137165ad28743965b5739a6ef708817e9a0e5f48b`; SID 9900019 blocked port 9090 with EVE action `blocked`; queue counters advanced; and port 9090 delivered the same payload after listener loss.
- The five bounded transfers recorded 39.988/42.277/44.485 ms minimum/median/maximum and 197.75 Mbit/s aggregate throughput. The nine-check schema-valid report is retained as `qualification-evidence/nfqueue-functional-dev19.json` and is not a capacity claim.
- Two final native dev19 packages were byte-identical with 116 payload files and 12 managed directories; the build report is retained separately from the artifact.

### Compatibility and rollback

- No host firewall, service, or route was changed. An exploratory NFQ open caused the host kernel's normal autoload of its installed `nfnetlink_queue` module; no `modprobe` was executed and the module was not unloaded. The final code now refuses to begin unless the backend is already available, making this precondition explicit.
- Both qualification containers were automatically removed; child namespaces, processes, routes, addresses, forwarding, and the Meercata table existed only in their disposable network namespaces.
- Removing the dev19 qualifier, schema, contract, package entries, and version bump restores dev18 behavior. Dev18 transaction evidence remains historical and version-bound.

## 2026-08-22 — Dev18 transactional nftables helper gate qualified

### Added

- Added transaction-bound `nftables.snapshot`, `nftables.apply`, `nftables.verify`, and `nftables.rollback` privileged operations with UUID-only helper/client arguments and exact state/lock/config-intent authorization.
- Added root-private mode-0600 policy, snapshot, prepared activation, applied activation, and rollback receipts with file and directory synchronization.
- Added last-known-state ownership proof: an existing table must match both the complete dev17 policy and the prior root activation receipt before a later transaction may snapshot or replace it.
- Added rollback refusal for any third-party/drifted state, idempotent recovery from prepared/applied receipts, and the gated `IpsNftablesWorkflow` transaction orchestration without public CLI exposure.
- Added `emergency.bypass` with three fixed reasons, anchored incident references, durable prepared intent, idempotent retry, configuration-independent recovery, best-effort audit, and removal restricted to an exactly owned `inet meercata` table.
- Added exact sudoers authorization, lazy per-operation helper construction, the guarded live transaction qualifier, `nftables-transaction-qualification-v1` schema/evidence, and the operating contract.
- Advanced the development version to `2.0.0.dev18`; Suricata NFQUEUE lifecycle and public IPS activation remain disabled.

### Production requirements addressed

- Durable pre-run state, atomic owned policy application, exact post-apply verification, bounded rollback, last-known-state receipts, audit separation, emergency connectivity bypass, and unrelated-firewall preservation.

### Verification

- The complete v2 suite passed 337 tests and the frozen v1 suite passed all 44 tests.
- In the isolated Debian 13 namespace, a first real nftables transaction committed; a second real transaction applied and then hit a forced verification failure; automatic rollback restored the first semantic fingerprint and reached `ROLLED_BACK`.
- Five root-private receipts, 16 controller audit events, 15 privileged audit events, emergency bypass, and unchanged unrelated-table semantics passed. The seven-check report is retained in `qualification-evidence/nftables-transaction-dev18.json`.
- Two final native dev18 packages were byte-identical with 113 payload files and 12 managed directories; the build report is retained in `qualification-evidence/deb-build-dev18.json`.

### Compatibility and rollback

- No host nftables state, systemd service, Suricata process, or public CLI surface was changed. Live mutations remained inside the disposable container namespace.
- The dedicated health identity remains authorized only for the no-argument health snapshot; nftables and bypass operations are restricted to `meercata-operators` through anchored sudoers expressions.
- Removing the dev18 workflow/service/client/qualifier, helper operations, sudoers aliases, schema, evidence, and contract restores dev17 behavior. Packet verdict, listener-loss traffic, overload/latency, systemd, crash, and reboot gates remain pending.

## 2026-08-22 — Dev17 fail-open nftables namespace foundation qualified

### Added

- Added strict `[ips]` configuration that shares the health interface/queue, permits only the initial `gateway-forward` topology, and rejects fail-closed policy until a separate HA or bypass design is approved.
- Added a deterministic Python nftables compiler for the dedicated `inet meercata` table, one forward hook, two directional NFQUEUE rules, mandatory counters/bypass, stable ownership comments, and native atomic `nft -f` replacement batches.
- Added full-table ownership inspection and stable semantic fingerprints that ignore only kernel handles and live counter values; foreign metadata, extra objects/rules, and interface/queue/policy drift fail closed.
- Added the guarded Debian 13 network-namespace qualifier, `nftables-namespace-qualification-v1` schema, recorded evidence, operating contract, configuration example, package inventory, and explicit nftables package dependency.
- Advanced the development version to `2.0.0.dev17`; the privileged IPS transaction helper and public IPS activation remain disabled.

### Production requirements addressed

- Dedicated nftables ownership, atomic NFQUEUE policy construction, initial end-to-end fail-open intent, refusal of fail-closed configuration, unrelated-firewall isolation, and machine-readable namespace evidence.

### Verification

- The complete v2 suite passed 322 tests and the frozen v1 suite passed all 44 tests.
- The live Debian 13 gate used a pinned image, read-only source/root filesystems, `--network none`, and only `CAP_NET_ADMIN`. Native nftables 1.1.3 passed syntax check, initial apply, atomic replacement, foreign ownership rejection, drift rejection, and isolated removal.
- An unrelated `inet operator_guard` table retained the same semantic SHA-256 across every Meercata mutation. The seven-check schema-valid result is retained in `qualification-evidence/nftables-namespace-dev17.json`.
- Two final native dev17 packages were byte-identical with 108 payload files and 12 managed directories; the build report is retained separately from the artifact.

### Compatibility and rollback

- No host firewall was modified; live nftables operations occurred only in the disposable container network namespace and cleanup removed both qualification tables there.
- v1 iptables/ip6tables compatibility behavior remains reference-only. Dev17 emits nftables policy for gateway-forward scope only and does not install hooks through the CLI or helper.
- Removing the IPS config/compiler/qualifier modules, schema, evidence, documentation, and dependency restores dev16 behavior. Listener-loss traffic, Suricata NFQUEUE verdicts, overload/latency, helper rollback, service lifecycle, and reboot remain gated.

## 2026-08-15 — Dev16 crash and reboot recovery gate qualified

### Added

- Added a two-phase root-only, hash-pinned Debian 13 KVM/QEMU qualifier for Suricata automatic restart, start-limit lockout, explicit recovery, normal reboot, health-timer persistence/execution, and protected-file integrity.
- Added bounded fixed-argv `SIGKILL` injection against only the systemd-tracked main process, plus best-effort reset/restart if qualification aborts after mutation.
- Added a create-only root-owned mode-0600 reboot marker binding the boot ID, exact packages, supervision policy, crash results, timer state, and protected configuration/rules/manifest hashes.
- Added the `recovery-vm-qualification-v1` schema, installed launcher, operating contract, strict state tests, and fixed package inventory.
- Advanced the development version to `2.0.0.dev16`; public rule promotion and IPS mutations remain disabled.

### Production requirements addressed

- Readiness-aware automatic restart, bounded restart storms, operator-visible start-limit failure, explicit service recovery, enabled monitoring across reboot, and configuration/rules/package integrity across restart and reboot.

### Verification

- The complete v2 suite passed 295 tests. The qualifier also passed the earlier dev12 readiness gate from the installed dev16 package before destructive testing.
- Live phase 1 proved a new ready PID and increased restart counter after `SIGKILL`, then reached the rolling start limit, rejected a new start, reset the failure, restored 15/15 health, enabled the timer, and sealed the pre-reboot state.
- Live phase 2 required a changed kernel boot ID, then passed exact package/policy checks, Suricata readiness with restart count zero, genuine post-boot timer execution, 15/15 health, and unchanged configuration, active-rules, and package-manifest hashes.
- The final schema-valid result is retained in `qualification-evidence/recovery-vm-dev16.json`; the reproducible native build report is retained separately to avoid embedding the artifact hash inside the artifact.

### Compatibility and rollback

- The qualifier cannot run without root, systemd PID 1, Debian 13, KVM/QEMU, the approved image hash, exact packages, and its exact destructive-test confirmation phrase.
- It does not change Suricata configuration, active rules, RuleOps transactions, firewall state, or IPS policy. The health timer is deliberately enabled for the reboot test.
- On a failed disposable run, reset the unit failure state and start Suricata; discard the overlay if service state is uncertain. Removing the module, launcher, schema, contract, and inventory entries restores dev15 behavior.

## 2026-08-15 — Dev15 signed APT repository gate qualified

### Added and corrected

- Added a double-guarded, network-isolated Debian 13 qualifier that builds two native revisions and publishes SHA-256-bound `Packages`, by-hash, `Release`, `Release.gpg`, and `InRelease` metadata.
- Added an expiring RSA-3072 qualification-only signing key, explicit deb822 `Signed-By` pinning, independent `sqv` payload/signer verification, and explicit denial of insecure or unauthenticated APT modes.
- Added fail-closed wrong-key, signed-metadata tamper, and package-byte tamper fixtures before authenticated install, upgrade, and removal checks.
- Corrected the source contract to omit the deb822 `Trusted` override: `Trusted: no` forcibly marks packages untrusted even after a valid pinned signature, while omitting it lets APT derive trust only from `Signed-By` verification.
- Added `apt-repository-qualification-v1`, recorded dev15 evidence, an operating contract, fixed package inventory, and automated evidence/hash-binding checks.
- Advanced the development version to `2.0.0.dev15`; public rule promotion remains disabled.

### Production requirements addressed

- Repository authenticity, explicit key pinning, signed metadata freshness and package hash binding, tamper rejection, authenticated APT install/upgrade, dependency integrity, normal removal, and machine-readable delivery evidence.

### Verification

- The decisive root-owned container used the approved Debian 13 image digest, a read-only source mount, loopback-only networking, and an empty route table.
- All ten live checks passed with official Debian Backports Suricata `1:8.0.6-1~bpo13+1` and suricata-update `1.3.8-1~bpo13+1`: both tamper classes and the unpinned key returned APT exit 100; revision 1 installed; revision 2 upgraded; removal left only protected configuration state.
- The exact signer fingerprint, repository metadata hashes, and installed/upgraded artifact hashes are retained in `qualification-evidence/apt-repository-dev15.json` and validated against the strict schema.
- The complete v2 suite passed 286 tests and the frozen v1 suite passed all 44 tests. Two final native dev15 builds were byte-identical with 99 payload files and 12 managed directories.

### Compatibility and rollback

- The key and repositories exist only inside the disposable container. No host APT source, trusted key, package, configuration, service, rule, or firewall state was changed.
- Removing the qualifier, schema, evidence, contract, and inventory entries restores the dev14 package surface. Historical evidence remains bound to its recorded artifact and version.
- This does not qualify production key custody/rotation, release publishing, HTTPS/mirrors/CDN, availability, crash/reboot recovery, IPS/NFQUEUE, retention, or purge.

## 2026-08-15 — Dev14 production regression baseline qualified

### Added

- Added `production-baseline-v1`, an original seven-case synthetic corpus spanning positive DNS, HTTP, raw TCP, and raw UDP detections plus benign-negative DNS, HTTP, and TLS traffic.
- Added a standard-library-only deterministic packet generator with fixed RFC 5737 addresses, locally administered MAC addresses, timestamps, checksums, and reviewed PCAP SHA-256 values.
- Bound the positive oracle set to four stable ET/Open identities from the exact dev13 ruleset snapshot, with cross-case forbidden alerts and all four identities forbidden in each benign case.
- Added the strict `regression-corpus-qualification-v1` evidence schema, recorded dev14 replay evidence, fixed package inventory, provenance documentation, and byte-reproduction tests.
- Advanced the development version to `2.0.0.dev14`; public rule promotion remains disabled.

### Production requirements addressed

- Redistribution-safe multi-protocol acceptance traffic, positive detection continuity, benign false-positive protection, immutable corpus provenance, and machine-readable full-ruleset replay evidence.

### Verification

- All seven captures regenerated byte-identically and their manifest passed Draft 2020-12 validation.
- Suricata 8.0.6 loaded the exact dev13 ET/Open snapshot with 52,322 active and 15,941 disabled rules. Each of the four positive cases emitted exactly one intended alert and no other protected identity; all three benign cases emitted zero alerts.
- The complete v2 suite passed 279 tests and the frozen v1 suite passed all 44 tests. Two native dev14 packages were byte-identical with 96 payload files and 12 managed directories.

### Compatibility and rollback

- The pack adds only root-owned read-only package data and does not alter active configuration, stage candidates automatically, enable public promotion, or reload Suricata.
- Removing the dev14 pack inventory, schema, evidence, and documentation restores the dev13 package surface. Existing dev13 RuleOps VM evidence remains valid for the exact artifact and image recorded there.

## 2026-08-14 — Dev13 deterministic RuleOps inputs completed

### Added

- Added the original synthetic `dev13-ruleops-v1` UDP PCAP, pinned manifest, reproducible timestamped hex source, and provenance notes. The fixture contains no captured user or third-party traffic.
- Added two alert-only, hash-distinct revision overlays for private qualification SID `9900013`; both produce exactly one expected alert under local Suricata 8.0.6 replay.
- Added the pack as a fixed, hash-bound package inventory with an explicit managed directory and production modes.
- Added a root-only, disposable-VM candidate-preparation mode that verifies exact overlay hashes, rejects SID collisions, builds from the active ET/Open ruleset, and passes both candidates through ordinary policy, Suricata validation, and PCAP regression gates.
- Corrected rule indexing for valid ET/Open PCRE options containing an unescaped double quote inside a regular-expression character class while retaining quoted fake-`sid` masking.
- Kept full-corpus indexing linear by using a safe structural-suffix fast path and falling back to the quote-aware scanner for ambiguous rules; unterminated quoted fake SIDs remain rejected.
- Forced the Suricata Unix command manager off for every unprivileged validation, privileged sealed-candidate validation, and offline PCAP replay. This prevents short-lived offline processes from replacing the live daemon's socket pathname with a stale inode.

### Production requirements addressed

- Reproducible non-sensitive qualification traffic, immutable expected-alert evidence, deterministic candidate construction, and removal of manual candidate-state preparation from the live gate.

### Verification

- The PCAP regenerated byte-identically, its manifest passed the Draft 2020-12 schema, both overlays returned exactly one `(gid 1, sid 9900013)` alert with Suricata 8.0.6, and focused packaging, regression, and qualifier tests passed.
- The complete v2 suite passed 275 tests. Two native dev13 builds were byte-identical with 84 payload files and 11 managed directories; the artifact SHA-256 remains recorded only in the external build evidence to avoid embedding the artifact hash inside that artifact.
- The corrected parser indexed the complete live 52,322-rule ET/Open corpus, including the previously incompatible PCRE, before candidate preparation was retried.
- Live failure injection proved that offline validation had invalidated the command socket while leaving Suricata running. With `unix-command.enabled=no` forced on the offline argv, the socket inode remained unchanged across strict validation and all 15 runtime health checks stayed healthy.
- The exact dev13 artifact recorded in `qualification-evidence/deb-build-dev13.json` was installed in the hash-pinned Debian 13 KVM guest. Its success transaction reached `COMMITTED`; the injected post-reload failure reached `ROLLED_BACK`; the final active hash matched the committed ruleset; and 15/15 health checks, both receipt sets, and both audit streams passed. The schema-valid result is retained in `qualification-evidence/ruleops-vm-dev13.json`.
- Public promotion remains disabled pending a broader reviewed production PCAP corpus and the remaining installed-host gates.

### Compatibility and rollback

- Candidate preparation is unavailable outside the existing exact disposable-VM, root, image-hash, OS, virtualization, and package-version guard. Removing the pack inventory, preparation mode, and fixture files restores the earlier manual preparation contract without changing the public CLI.

## 2026-08-14 — Phase 4 live RuleOps VM qualifier implemented

### Added

- Added a root-only, hash-pinned Debian 13 KVM/QEMU qualifier for two pre-approved, hash-distinct RuleOps candidates.
- Added a committed promotion path using the existing transaction engine, exact four-operation helper, non-blocking Suricata reload, and ordinary health verification.
- Added a second promotion that requires genuine healthy post-reload state before injecting a critical qualification result, then requires filesystem restoration and a verified rollback reload.
- Added root-only receipt, final active-hash, last-known-good, controller-audit, privileged-audit, and final-health verification.
- Added the `ruleops-vm-qualification-v1` schema, installed qualifier launcher, operating contract, packaging inventory, and negative unit coverage.
- Kept public `meercata rules promote` disabled and advanced the development version to `2.0.0.dev13`.

### Production requirements addressed

- Live transaction-bound rule activation, controlled non-blocking reload, post-change health gating, rollback reload, durable mutation evidence, and fail-closed disposable-host qualification.

### Verification

- Focused qualifier, packaging, policy, Debian builder, staged qualifier, and dev12 compatibility tests passed during implementation; the final combined v2 suite passed 272 tests.
- The staged image passed all six qualification checks with 77 payload files and 10 managed directories. Two independent native builds were byte-identical; the final SHA-256 is recorded externally in `qualification-evidence/deb-build-dev13.json` to avoid embedding an artifact hash inside that artifact.
- Frozen v1, all JSON schemas/evidence, sudoers, POSIX hook syntax, bytecode compilation, and CLI entry points were reverified at the dev13 implementation checkpoint.
- No live dev13 result is claimed until two reviewed candidates and the approved redistribution-safe PCAP corpus are provisioned and the guarded VM run emits schema-valid evidence.

### Compatibility and rollback

- The new qualifier cannot run without root, the exact disposable-VM confirmation, approved image hash, Debian/systemd/KVM identity, exact packages, and pre-approved candidates.
- It is not a public promotion path and does not relax the helper, sudoers, path, ownership, transaction, regression, or audit boundaries.
- Removing the qualifier module, launcher, schema, tests, contract, and inventory entries restores dev12 behavior; active rules must be restored from the recorded pre-run snapshot before discarding any failed live qualification VM.

## 2026-08-13 — Phase 4 live systemd VM readiness qualified

### Added and corrected

- Added a hash-pinned Debian 13 KVM/QEMU qualifier for real `systemd` PID 1, exact installed package versions, Suricata notification readiness, the root-owned Unix socket, service-user health, and timer execution.
- Qualified the official Backports Suricata 8.0.6 daemon live in AF_PACKET IDS mode on `enp0s2`; all 15 health checks passed with real traffic counters and EVE output.
- Canonicalized Suricata 8's `AF_PACKET_DEV` socket value to the configured AF_PACKET policy, removing a false critical result without accepting any unrelated capture mode.
- Corrected the health oneshot capability boundary so its exact sudoers-allowlisted read-only helper can cross from the `meercata` identity to the root-owned socket. The unit retains only `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, and `CAP_AUDIT_WRITE` in its bounding set.
- Added the `systemd-vm-readiness-v1` schema, recorded dev12 VM/build evidence, and advanced the development version to `2.0.0.dev12`.

### Production requirements addressed

- Readiness-aware process supervision, least-privilege read-only monitoring, live Unix-socket mediation, real AF_PACKET interface/counter verification, EVE freshness, periodic systemd health execution, and reproducible installed-host evidence.

### Verification

- The final native artifact contains 73 payload files and 10 managed directories; its SHA-256 is recorded in `qualification-evidence/deb-build-dev12.json`.
- The live VM passed five bounded qualification checks: Debian 13 KVM/systemd identity, exact packages, Suricata readiness, 15/15 healthy service-user checks, and a successful oneshot with an active one-minute timer.
- The fix first reproduced both failures on dev11, then passed from the fully installed dev12 package rather than source-tree substitutions.

### Compatibility and rollback

- No GUI, web service, remote API, new programming language, firewall mutation, IPS/NFQUEUE hook, or rule mutation was introduced.
- The package still does not enable its health timer automatically. Removing dev12 restores the distribution-owned Suricata unit after daemon reload; operator configuration and Meercata state remain protected.
- Rule reload/rollback, crash throttling, enabled-timer reboot persistence, IPS, signed repository delivery, and purge remain later qualification gates.

## 2026-08-13 — Phase 4 official Suricata 8 package qualification implemented

### Added

- Added a reviewed inert deb822 source example for the official Debian 13 `trixie-backports` suite, restricted to `main` and the Debian archive keyring.
- Pinned and qualified `suricata` `1:8.0.6-1~bpo13+1` and `suricata-update` `1.3.8-1~bpo13+1` on amd64.
- Added cleartext InRelease signature verification with `sqv`, authenticated release identity and freshness checks, signed APT package metadata capture, and dpkg file-integrity verification.
- Added fail-closed runtime gates for the Suricata version, detection, AF_PACKET, NFQUEUE, Unix socket, systemd notification, portable compiler target, and production installation paths.
- Added strict default-configuration validation with a fixed local rule and combined Suricata/Meercata systemd unit parsing.
- Added dependency-satisfied Meercata installation without `--ignore-depends`, followed by normal removal and byte-preservation checks for Suricata configuration, binary, and installed packages.
- Added the versioned `suricata-package-qualification-v1` report and operating contract.
- Made `suricata-update (>= 1.3.8)` an explicit native package dependency instead of relying on Suricata's optional recommendation.
- Advanced the development version to `2.0.0.dev11`.

### Production requirements addressed

- First-party package provenance, authenticated and fresh repository metadata, exact supported runtime versions, package-file integrity, required capture/control capabilities, explicit RuleOps tooling dependency, dependency-safe installation, and package ownership isolation.

### Verification

- Combined v2 suite: 260 tests passed; frozen v1 suite: 44 tests passed; the 20-file v1 reference manifest retained zero mismatches.
- Nine JSON schemas and five recorded qualification evidence files passed Draft 2020-12 validation; sudoers, maintainer-hook syntax, bytecode compilation, and CLI entry-point checks passed.
- Network-disabled Debian 13 qualification passed all eight Suricata-package checks, including two valid Debian InRelease signer identities, exact signed package metadata, 58 present package files, 13 permitted Debian-slim documentation exclusions, all required runtime capabilities, strict configuration validation, dependency-satisfied Meercata installation, combined-unit parsing, and isolated removal.
- The final Meercata artifact and repository package SHA-256 values are recorded in machine-readable evidence rather than embedded into package-owned documentation.

### Compatibility and rollback

- No third-party repository or source build was introduced. Meercata installs only an inert source example under `/usr/share`; it never activates APT sources or downloads packages on a host.
- Repository provisioning occurred only in a disposable container. The qualification run used no network and the source tree was read-only.
- Normal Meercata removal preserved both Debian Suricata packages and their binary/configuration bytes. No live daemon, traffic, socket mutation, rule reload, nftables/NFQUEUE operation, crash, or reboot was exercised.
- No v1 source or behavior was changed.

## 2026-08-13 — Phase 4 native Debian package lifecycle implemented

### Added

- Added a deterministic Python `.deb` builder mapping `2.0.0.devN` to ordered Debian versions `2.0.0~devN-R`.
- Added reviewed Debian control metadata, copyright metadata, complete payload md5sums, fixed timestamps, root-owned archive entries, single-threaded uniform xz compression, and post-build extraction verification.
- Added four approved POSIX-shell dpkg hooks limited to fixed install, configure, upgrade, remove, and abort dispatch; application/control-plane code remains Python.
- Added a Python lifecycle dispatcher for sysusers/tmpfiles application, sudoers validation, installed hash/mode/ownership verification, conditional daemon reload, health-unit shutdown, and sudo-before-helper removal ordering.
- Added first-install collision refusal and a pre-unpack upgrade integrity gate that preserves externally modified managed files for investigation.
- Added Debian slim documentation-exclusion compatibility while keeping every runtime, code, policy, unit, schema, and configuration-example artifact mandatory.
- Added versioned `deb-build-v1` and `debian-lifecycle-qualification-v1` contracts plus the native packaging runbook.
- Added pinned Debian 13 lifecycle qualification covering clean install, repeated configure, ordered upgrade, modified-file rejection, normal removal, and protected-data preservation.
- Advanced the development version to `2.0.0.dev10`.

### Production requirements addressed

- Native package reproducibility, root-owned archive integrity, explicit dependency metadata, minimal idempotent maintainer hooks, safe first installation, tamper-aware upgrade, least-surprise activation, sudo authorization removal order, and persistent configuration/recovery/audit data preservation.

### Verification

- Combined v2 suite: 251 tests passed; frozen v1 suite: 44 tests passed; the 20-file v1 reference manifest had zero mismatches.
- All eight JSON schemas and three recorded qualification evidence files passed Draft 2020-12 validation; sudoers parsing, POSIX-shell syntax, bytecode compilation, and CLI entry-point smoke checks passed.
- The reproducible Debian 13 build produced `meercata_2.0.0~dev10-1_all.deb` with 66 manifest files and nine owned directories; its final size and SHA-256 are recorded in the external build evidence to avoid embedding an artifact hash inside that same artifact.
- Pinned Debian 13 lifecycle qualification passed all seven checks across revisions 1, 2, and 3. The evidence is recorded in `qualification-evidence/deb-build-dev10.json` and `qualification-evidence/debian-lifecycle-dev10.json`.
- Shellcheck passed all four maintainer hooks. Lintian reported no errors, three documented warnings (fixed absolute systemctl path, development upload with no Debian bug closure, and the retained Markdown upstream changelog), and one informational intentional empty regression-pack directory.
- Debian 13's default repository exposes Suricata 7.0.10, below the supported 8.0.x line. The `suricata (>= 8.0)` dependency remains deliberately fail-closed; qualification of a reviewed Suricata 8 package source is a release gate.

### Compatibility and rollback

- POSIX shell was introduced only with explicit operator approval and only for the four dpkg-required lifecycle entry points; no application feature, command parsing, policy, or privileged operation moved out of Python.
- The package never installs active controller configuration, never enables or starts a service, and has no automatic destructive purge.
- Native lifecycle tests used disposable containers with network disabled during qualification; no live host package, identity, sudoers, systemd, Suricata, rule, firewall, configuration, state, or log was changed.
- No v1 source or behavior was changed.

## 2026-08-13 — Phase 4 root-owned Debian 13 container qualification implemented

### Added

- Added a Python-only root-owned installer/qualifier that refuses every environment except a confirmed Docker container running Debian 13 from the approved official pinned image digest.
- Added fixed preconditions for effective root, regular Docker marker, Debian identity, absent running systemd manager, exact confirmation phrase, and exact image digest.
- Added collision-free container-root installation with real `root:root` ownership, declared modes, SHA-256 re-verification, and a tracked Suricata drop-in directory.
- Added actual sysusers and tmpfiles application followed by numeric UID/GID, sticky-bit, private-directory, and operator-separation verification.
- Added installed CLI execution as the unprivileged `meercata` user, helper operation-surface verification, and real sudo authorization inspection proving health-only access.
- Added installed systemd unit/drop-in verification and protected configuration/state/log ownership exclusion.
- Added `container-qualification-v1`, environment-guard tests, pinned platform evidence, and explicit remaining limitations.
- Advanced the development version to `2.0.0.dev9`.

### Production requirements addressed

- Root-owned installed artifact integrity, real identity/directory materialization, exact sudo authorization, installed launcher execution, container-root safety gating, pinned Debian baseline, package/data separation, and machine-readable qualification evidence.

### Verification

- The official `debian:13-slim` image was pinned at digest `sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258` on `linux/amd64`.
- Root-controlled qualification passed all nine checks with networking disabled and bounded container resources.
- The final report verifies 58 installed payload files, nine owned directories, 59 root-owned artifacts including the manifest, six runtime directories, five helper operations, health-only service-user sudo access, three systemd units, and three preserved data roots.
- Combined v2 suite: 219 tests passed; frozen v1 suite: 44 tests passed; six JSON schemas, sudoers policy, package manifest, container evidence, and the 20-file v1 reference manifest passed final verification.

### Compatibility and rollback

- Only a disposable provisioning container and temporary derived image were created; both were deleted after qualification. The official pinned Debian base remains in the local Docker cache.
- The source tree was mounted read-only, container networking was disabled during qualification, no host path except that read-only source mount was exposed, and no live host package, user, sudoers, systemd, Suricata, rule, or firewall state was changed.
- Systemd was not PID 1 and a minimal Suricata fixture was used, so no live readiness, reload, traffic, restart, crash, or reboot claim is made.
- No v1 source or behavior was changed.

## 2026-08-13 — Phase 4 disposable-root staged qualification implemented

### Added

- Added a Python-only staged-image qualifier that copies only hash-verified package payload into an automatically removed temporary filesystem root.
- Added isolated staged imports for the package, CLI, health, package builder, and privileged helper with version identity verification.
- Added real `visudo` policy parsing and `systemd-analyze --root` verification for the health service/timer and Suricata override.
- Added disposable `systemd-sysusers --root` identity materialization with explicit proof that the monitoring user is not a RuleOps operator.
- Added `systemd-tmpfiles --root --create --dry-run` validation after resolving the disposable identities.
- Added the versioned `qualification-v1` JSON result schema, fixed check order, bounded reports, fail-closed tool handling, and explicit limitation records.
- Added fault injection for tampered artifacts, broken staged Python, invalid sudoers/systemd, forbidden group membership, omitted tmpfiles paths, and external-validator failure.
- Added the staged qualification runbook and clarified the boundary between `staged-qualified`, installed-host qualification, and production qualification.
- Advanced the development version to `2.0.0.dev8`.

### Production requirements addressed

- Artifact immutability during qualification, installed-code importability, real policy parser compatibility, systemd dependency construction, service/operator identity separation, runtime-directory resolution, bounded external validation, machine-readable qualification evidence, and truthful recording of untested gates.

### Verification

- Combined v2 suite: 204 tests passed at implementation completion.
- Thirty-one focused packaging and qualification tests passed, including positive disposable-root execution and negative policy/failure injection.
- The emitted report conforms to `qualification-v1`; all staged checks passed on Python 3.13, sudo 1.9.17p2, and systemd 261 in the development environment.
- Re-ran all JSON schema parsing, bytecode compilation, sudoers validation, package staging/verification, the frozen v1 suite, and reference-manifest verification.

### Compatibility and rollback

- Qualification created identities and fixtures only inside automatically removed temporary roots owned by UID 1000. It did not invoke sudo, apply root ownership, modify the staged artifact, install files, reload systemd, start Suricata, connect to its socket, or change rules/firewall state.
- Every successful report states that root ownership, live Suricata behavior, and native package lifecycle remain untested.
- No v1 source or behavior was changed; removing the qualifier, report schema, tests, and runbook restores the earlier staged-image-only state.

## 2026-08-13 — Phase 4 deterministic production image packaging implemented

### Added

- Added a Python-only `stage`, `verify`, and read-only `removal-plan` package-image interface that refuses the live filesystem root.
- Added a fixed inventory for Python modules, CLI/helper launchers, sudoers, sysusers, tmpfiles, systemd templates, configuration example, schemas, and operating documentation.
- Added deterministic `package-manifest-v1` output with version, intended root ownership, exact modes, roles, and SHA-256 values.
- Added pre-write rejection for source/staging overlap, symlinks, unsafe or oversized sources, unowned collisions, modified managed files, malformed prior manifests, and unowned installed code.
- Added Python-only installed launchers using the fixed root-owned module path with bytecode writes disabled.
- Added hash/mode image verification and removal planning that preserves changed files, configuration, state, recovery receipts, and audit roots.
- Preserved existing modes on shared non-package-owned parent directories.
- Added the production packaging and installed-host qualification contract.
- Advanced the development version to `2.0.0.dev7`.

### Production requirements addressed

- Deterministic artifact inventory, fixed installed-code provenance, package-owned path enforcement, upgrade collision protection, change-preserving removal planning, versioned machine-readable metadata, and separation of package payload from administrator configuration and runtime data.

### Verification

- Combined v2 suite: 193 tests passed at implementation completion.
- Focused tests cover deterministic images, complete inventory, schema inclusion, exact modes, shared-parent preservation, root/source-overlap rejection, source and destination symlinks, unowned collisions/code, modified-file upgrade refusal, hash/mode/missing-file verification, manifest path confinement, removal preservation, and JSON CLI behavior.
- Re-ran schema parsing, sudoers validation, bytecode compilation, package CLI smoke checks, the frozen v1 suite, and reference-manifest verification.

### Compatibility and rollback

- The builder wrote only to test-managed temporary staging directories. Nothing was installed under the live filesystem root, and no user, sudoers entry, systemd unit, configuration, rule, service, or timer was changed.
- The staged image contains only a configuration example and never overwrites `/etc/meercata/meercata.toml`.
- Removal planning is read-only and explicitly preserves configuration, state, logs, modified managed files, and the package manifest until last.
- No v1 source or behavior was changed; deleting the builder, manifest schema, packaging launcher, tests, and packaging contract restores the prior template-only state.

## 2026-08-13 — Phase 4 socket mediation and supervision templates implemented

### Added

- Added exact `rules.reload TRANSACTION_UUID` and no-argument `health.socket-snapshot` privileged-helper operations.
- Bound applied and rollback reloads to the active transaction state, activation or rollback receipt, and expected active-rules hash, with distinct idempotent receipts.
- Routed production health socket reads through a bounded, typed helper snapshot while retaining direct injected sockets for isolated tests.
- Added a dedicated unprivileged `meercata` health identity with authorization only for the exact read-only snapshot command and no RuleOps group membership.
- Moved privileged audit output into a root-only log directory.
- Added readiness-aware Suricata override, bounded restart policy, and periodic CLI health service/timer templates.
- Added the supervision installation, monitoring, qualification, and removal contract.
- Rejected truncated helper output, non-finite or negative uptime, malformed snapshot identity fields, and group-writable packaging policy templates.
- Advanced the development version to `2.0.0.dev6`.

### Production requirements addressed

- Transaction-bound Suricata reload, least-privilege read-only socket access, separation of operator and monitoring identities, accurate privileged audit operation labels, readiness signaling, bounded restart behavior, and periodic health execution.

### Verification

- Combined v2 suite: 180 tests passed at implementation completion.
- Focused tests cover helper dispatch, transaction/hash/receipt authorization, applied and rollback idempotency, recovery retry, socket command allowlisting and response bounds, exact sudo argv, identity separation, root-only audit policy, readiness, restart-limit, and timer templates.
- The sudoers template passes `visudo -cf`; systemd templates parse in the development environment, where the intentionally uninstalled `/usr/bin/meercata` executable is expected to be absent.
- Re-ran the frozen v1 suite and reference-manifest hash verification.

### Compatibility and rollback

- No helper, user, sudoers, tmpfiles, or systemd template was installed; no daemon reload, service action, socket mutation outside tests, or live rule change occurred.
- Public production promotion remains disabled pending installed-host qualification, monitoring integration, retention policy, and a reviewed PCAP corpus.
- No v1 source or behavior was changed.
- Package rollback must disable the health timer, remove sudo authorization before helper code, preserve recovery/audit state, remove the units and override, and reload/restart systemd only under an approved rollback plan.

## 2026-08-12 — Initial Phase 4 privileged RuleOps helper implemented

### Added

- Added a Python-only `meercata-helper` with only `rules.snapshot`, `rules.activate`, and `rules.rollback` operations.
- Added transaction UUID, active lock, operation, state, and candidate-binding authorization independent of CLI arguments.
- Added root-private candidate sealing followed by independent strict Suricata validation and approved PCAP regression replay.
- Added active-rule snapshots, hashes, bounded qualification records, a durable pre-replace activation intent, atomic replacement, file/directory synchronization, and recovery receipts.
- Added rollback ownership checks that restore/remove only the transaction candidate and refuse unrelated active-rule changes.
- Added a fixed non-interactive sudo client implementing the existing promotion activator boundary.
- Added anchored sudoers, tmpfiles, and Python launcher templates plus the privileged-helper security and installation contract.
- Added production ownership/mode checks for configuration, privileged state, regression packs, and active rule targets.
- Advanced the development version to `2.0.0.dev5`.

### Production requirements addressed

- Least-privilege RuleOps filesystem mutation, independent privileged validation, TOCTOU-resistant candidate sealing, exact transaction authorization, atomic activation, durable rollback evidence, and deny-by-default command/path handling.

### Verification

- Combined v2 suite: 161 tests passed at implementation completion.
- Focused tests cover fixed dispatch/argv, lock and transaction state, candidate/pack tampering, sealed-byte activation, privileged validation/regression failure, active-state races, first installation, rollback restoration/removal, unrelated changes, audit failure, helper JSON, and policy templates.
- The sudoers template passes `visudo -cf` on sudo 1.9.17p2.
- Re-ran the frozen v1 suite and reference-manifest hash verification.

### Compatibility and rollback

- The helper and policy files were not installed, no sudo authorization was changed, and no live active rules were touched.
- Public production promotion remains disabled.
- No v1 source or behavior was changed.
- Package rollback must remove sudo authorization before helper code, then retain privileged transaction snapshots until recovery/retention policy permits removal.

## 2026-08-12 — Phase 3 PCAP regression gate implemented

### Added

- Added `meercata rules regress CANDIDATE_ID PACK_ID` with human and JSON output.
- Added strict regression-pack-v1 manifests under the fixed installed package root, safe identifiers, basename-only PCAP references, pinned SHA-256 values, bounded cases, and required or forbidden alert-count oracles.
- Added fixed-argv, single-runmode offline Suricata replay with candidate-exclusive rules and isolated per-run output directories.
- Added bounded EVE JSONL parsing and `(gid, sid)` evaluation without persisting packet data, alert payloads, or signature text.
- Added candidate-manifest and audit results bound to both the candidate SHA-256 and pack-manifest SHA-256.
- Made the internal promotion workflow reject missing, failed, mismatched, or stale PCAP regression evidence.
- Added a handling guide for building a reviewed production corpus without committing sensitive or unlicensed captures.
- Advanced the development version to `2.0.0.dev4`.

### Production requirements addressed

- PCAP pre-promotion regression, deterministic alert expectations, negative tests, immutable input identity, bounded evidence, audit traceability, and stale-evidence rejection.
- CLI callers cannot provide executable, configuration, output, or PCAP paths.

### Verification

- Combined v2 suite: 139 tests passed at implementation completion.
- Verified pack/schema/path/hash rejection, symlink denial, expected and forbidden alerts, malformed EVE, offline command failure, audit outcomes, manifest transitions, candidate mutation, and stale pack evidence.
- Re-ran the frozen v1 suite and reference-manifest hash verification.

### Compatibility and rollback

- No production PCAP corpus, live replay, active rule mutation, or Suricata reload was performed.
- No v1 source or behavior was changed.
- Removing the regression module, schema, CLI command, tests, and manifest requirement restores the earlier validation-only promotion precondition.

## 2026-08-10 — Phase 3 RuleOps development pipeline implemented

### Added

- Added CLI-only `rules status`, `stage`, `diff`, `validate`, and deliberately gated `promote` commands.
- Added strict ET/Open source policy, fixed Suricata path configuration, numeric bounds, and unknown-key rejection.
- Added UUID candidate storage, atomic manifests, SHA-256, bounded rule parsing, active/disabled/action counts, duplicate identity rejection, and quoted-option handling.
- Added bounded rule differences with exact totals, minimum count, and maximum reduction enforcement.
- Added fixed-argv `suricata-update` staging with reload/test disabled and explicit strict Suricata candidate validation.
- Added required audit events for stage and validation requests, results, rejections, and failures.
- Added a narrow Suricata RuleOps socket client, non-blocking reload polling, ruleset statistics, and failed-rule verification.
- Added transaction-backed promotion orchestration with candidate re-hash, policy recheck, post-reload health verification, rollback reload, and recovery-failure state.
- Added the rule-candidate-v1 schema and RuleOps operational contract.

### Production requirements addressed

- Allowlisted rule management, source/version and hash traceability, strict validation, bounded differences, reduction protection, audit, reload verification, rollback, and durable recovery classification.
- No arbitrary URL, executable, command, destination, or active rules path is accepted from the CLI.

### Verification

- Combined v2 suite: 122 tests passed at implementation completion.
- Verified malformed, duplicate, quoted, continued, invalid UTF-8, reduced, and oversized-difference behavior.
- Verified update and validation command construction/failure, manifest/state safety, symlink rejection, reload completion/timeout/failed rules, successful commit, unhealthy rollback, and rollback failure.
- Re-ran the frozen v1 suite and reference-manifest hash verification.

### Compatibility and rollback

- No v1 source or runtime behavior was changed.
- No live Suricata rules were updated or reloaded during development verification.
- The production CLI refuses promotion until the Phase 4 helper is installed; removing the RuleOps modules, schema, configuration table, CLI commands, tests, and documentation restores the Phase 2 surface.

## 2026-08-10 — Phase 2 read-only health implemented

### Added

- Added `meercata health`, `health --json`, and `health --watch` with stable exit codes and JSONL watch output.
- Added strict TOML health configuration with schema, key, type, threshold, interface, queue, managed-path, size, and symlink validation.
- Added the formal health-v1 JSON Schema and example controller configuration.
- Added systemd readiness, Suricata process, Linux interface, EVE freshness, packet progress, packet loss, TCP gap, memcap, disk, host memory, process RSS, and sampled CPU checks.
- Added a bounded Suricata 8 Unix-socket client restricted to read-only health commands.
- Added IDS AF_PACKET and IPS NFQ capture-mode/interface verification.
- Added IPS inspection of the fixed Meercata nftables table and kernel NFQUEUE listener/drop state.
- Added the health contract documenting checks, permissions, sampling semantics, exit behavior, and the installed-host qualification boundary.

### Production requirements addressed

- Read-only health and diagnostics, stable machine output, service readiness, capture correctness, EVE continuity, packet progress and loss, memcap/resource pressure, and IPS hook/listener visibility.
- Health never invokes a shell, never accepts a caller-controlled executable/unit/table, and denies mutating Suricata socket commands.

### Verification

- Combined v2 suite: 89 tests passed.
- Verified healthy simulated IDS and fail-open IPS reports.
- Verified critical/degraded/unknown behavior for every Phase 2 acceptance signal, including repeated-sample packet stall detection.
- Verified health-v1 report/schema alignment, human rendering, JSON output, watch reuse, interval bounds, and exit-code mapping.
- Verified the real CLI emits a schema-v1 unknown/configuration report with exit code 3 when production configuration is absent.

### Compatibility and rollback

- No v1 files or runtime behavior were changed.
- Phase 2 is read-only and does not start/stop Suricata, alter configuration/rules, install hooks, reload rules, or mutate system state.
- Removing the health modules, schema, example, CLI subcommand, and tests returns v2 to the Phase 1 foundation.

## 2026-08-10 — Phase 1 transaction foundation implemented

### Added

- Added the Python `meercata` package and CLI entry point. The implemented CLI is read-only and exposes version, fixed-path, transaction-list, recovery-required, and transaction-detail inspection.
- Added typed transaction, actor, history, command-result, and error models.
- Added fixed production paths and isolated test path construction.
- Added a non-blocking `flock` controller lock with durable owner metadata and symlink rejection.
- Added structured JSONL controller audit records with append, size, serialization, regular-file, and durability checks.
- Added an allowlisted fixed-argv command runner using `shell=False`, an allowlisted environment, fixed working directories, bounded stdout/stderr, timeouts, and process-group termination.
- Added atomic JSON transaction storage, schema and size validation, last-known-good pointers, and recovery-required discovery.
- Added the transaction engine for snapshot, stage, validate, apply, verify, commit, rollback, and explicit recovery.
- Added Phase 0 threat model, privileged-operation inventory, and hashed v1 reference manifest.
- Recorded CLI-only scope and the requirement to obtain operator approval before introducing another implementation language.

### Production requirements addressed

- Transaction locking, durable state, audit, rollback, bounded command execution, input/path constraints, recovery discovery, and change-control traceability.
- The design preserves Python as the control plane and leaves Suricata/kernel packet processing unchanged.

### Verification

- Phase 1 suite: 56 tests passed.
- Frozen v1 reference suite: 44 tests passed.
- Simulated interruption recovery passed after `LOCKED`, `SNAPSHOTTED`, `STAGED`, `VALIDATED`, `APPLIED`, `VERIFIED`, `COMMITTED`, and `ROLLING_BACK` persistence points.
- Verified command timeout, process-group termination, output bounds, environment isolation, unknown-command denial, lock contention, symlink rejection, audit append and failure blocking, atomic state round-trip, rollback failure classification, and last-known-good repair.
- Verified all files in `V1-REFERENCE-MANIFEST.json` against their SHA-256 hashes.
- Verified the module entry point and current read-only CLI commands locally.

### Compatibility and rollback

- No v1 IDS, IPS, Suricata, systemd, YAML, rule, or firewall runtime behavior was changed or migrated.
- Phase 1 does not expose a mutation command and does not alter production system state.
- Removing the v2 Python package, tests, and packaging file rolls back this implementation without affecting v1.

## 2026-08-10 — Phase 0 architecture baseline recorded

### Added

- Added `ARCHITECTURE-DECISIONS.md` with the initial production platform, Suricata, firewall, topology, fail-policy, audit, authorization, configuration, metrics, RuleOps, and retention decisions.
- Recorded Debian 13 on amd64 as the first production qualification target and Suricata 8.0.x with 8.0.6 as the development baseline.
- Limited the first v2 IPS implementation to Meercata-owned nftables objects and fail-open operation.

### Production requirements addressed

- Defined the compatibility and platform boundary for implementation and qualification.
- Defined initial access-control, audit, configuration-schema, health-integration, rule-promotion, recovery-retention, privacy, and fail-policy constraints.
- Closed the documented Phase 0 decision list for the Phase 1 development baseline.

### Verification

- Inspected the development environment: Kali GNU/Linux 2026.3, systemd 260, Suricata 8.0.6, nftables 1.1.6, and Python 3.13.14.
- Confirmed the local Suricata build exposes AF_PACKET, NFQUEUE, Unix socket, detection, and systemd support.
- Re-ran the frozen v1 reference suite: 44 tests passed.
- Documentation-only change; no v2 runtime behavior or production system state was introduced.

### Compatibility and rollback

- V1 behavior and source remain unchanged by this architecture record.
- Reverting this documentation entry restores the prior open-decision state; future implementation changes must use a superseding decision record instead of silently changing the baseline.

## 2026-08-10 — Production track initialized

### Added

- Created the separate `Meercata v2.00` development directory.
- Added `README.md` defining the v2 production objective, control-plane boundary, filesystem layout, safety principles, and change discipline.
- Added `PRODUCTION-ROADMAP.md` defining the v1 baseline, production requirement matrix, transaction model, phased implementation plan, acceptance gates, compatibility policy, and pending architecture decisions.
- Recorded official Suricata references for rule management, reload, health counters, privileges, systemd readiness, and testing.

### Production requirements addressed

- Change control and documented acceptance criteria.
- Separation of the production redesign from the working v1 baseline.
- Architecture planning for health, fail-safe behavior, rollback, validation, RuleOps, auditing, resources, access control, supervision, recovery, and testing.

### Verification

- Confirmed v2 was empty before initialization.
- Confirmed v1 remained the reference implementation with 44 tests recorded as passing.
- Documentation-only phase; no v2 runtime code or production system state was created.

### Compatibility and rollback

- No v1 files were copied, edited, or removed.
- Removing the three v2 documentation files would fully roll back this documentation-only initialization; no runtime behavior is affected.
