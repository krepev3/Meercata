# Meercata v2.00 Production Roadmap

## 1. Purpose

This document controls the evolution of Meercata from a working Suricata IDS/IPS utility into a production controller. It defines the target architecture, production requirements, implementation phases, acceptance gates, and compatibility boundary before runtime code is introduced.

## 2. Reference baseline

Meercata v1.00 is the behavioral reference, not the production architecture.

Verified v1 capabilities include:

- foreground IDS on a selected interface;
- fail-open NFQUEUE IPS through nftables;
- managed iptables/ip6tables and nftables cleanup;
- requirement and configuration checks;
- Suricata YAML and rule-file state inspection/editing;
- firewall backup and restore helpers;
- optional systemd inline service;
- readable alert/drop evidence collection and continuous evidence viewing;
- restoration of Meercata-owned runtime state after foreground exit;
- 44 passing automated tests at the v2 project-creation baseline.

Known production gaps include continuous health alerting, structured controller audit, transactional mutation, least-privilege separation, official rule-update staging, controlled rule reload, resource thresholds, durable recovery state, and PCAP/load/failure testing.

## 3. Scope boundary

### Python control plane

Meercata may:

- validate typed configuration and operator requests;
- acquire a single-controller lock;
- stage configuration and rules;
- execute fixed allowlisted commands with bounded timeouts;
- communicate with the Suricata Unix socket;
- manage only Meercata-owned firewall objects;
- collect health metrics and controller audit records;
- verify deployments and perform bounded recovery.

### Packet-processing data plane

Meercata must not process production packets in Python. Packet inspection, NFQUEUE handling, stream tracking, detection, and blocking remain the responsibility of Suricata and the kernel.

## 4. Target transaction model

Every mutating operation follows the same state machine:

```text
REQUESTED
    |
    v
LOCKED -> SNAPSHOTTED -> STAGED -> VALIDATED -> APPLIED -> VERIFIED -> COMMITTED
                 |           |          |           |
                 +-----------+----------+-----------+
                                         failure
                                            |
                                            v
                                      ROLLING_BACK
                                            |
                               +------------+------------+
                               v                         v
                         ROLLED_BACK                RECOVERY_FAILED
```

Each transaction records:

- unique transaction ID;
- UTC and local timestamps;
- actor UID/GID and invocation source;
- requested operation and redacted arguments;
- pre-change state and hashes;
- staged artefact hashes;
- validation results;
- executed commands and bounded results;
- post-change health verification;
- commit or rollback outcome;
- last-known-good reference.

## 5. Production requirement matrix

| Requirement | Mandatory acceptance criterion |
|---|---|
| Health monitoring | Detect process, systemd readiness, Suricata socket, capture mode, interface, NFQUEUE hooks/counters, EVE freshness, packet progress, disk, CPU, memory, memcap, and packet-drop degradation. |
| Fail-safe | Declare and test behavior for missing listener, controller crash, Suricata crash, queue overload, internal exception, boot failure, and recovery failure. |
| Rollback | Restore the last-known-good Meercata-owned firewall/config/rule/service state without overwriting unrelated host changes. |
| Config validation | Validate staged configuration with Suricata before activation and reject warnings designated fatal by policy. |
| Rule validation | Reject failed, duplicate-policy, unsupported, or unexpectedly reduced rulesets before activation. |
| Rule management | Stage and audit updates through `suricata-update` with allowlisted sources and version metadata. |
| Rule reload | Use controlled non-blocking reload, poll completion, verify rule statistics, and rollback when health checks fail. |
| Control logging | Record every start, stop, mode, fail-policy, firewall, config, rule, reload, rollback, and recovery operation. |
| Resource monitoring | Measure CPU, RSS, disk, kernel/NIC/NFQUEUE drops, reassembly gaps, flow emergency, memcap failure, and queue pressure. |
| Access control | Separate unprivileged control from restricted privileged execution; deny unknown operations and unsafe paths. |
| Input validation | Use schemas, canonical paths, fixed argv arrays, `shell=False`, absolute tools, allowlisted environment, timeouts, and bounded output. |
| Process supervision | Use readiness-aware systemd supervision, restart limits, timeouts, dependency ordering, and operator-visible failure state. |
| Recovery | Persist enough state to recover after SIGINT, SIGTERM, exception, process kill, reboot, partial apply, or failed rollback. |
| Change control | Keep versioned immutable snapshots, manifests, hashes, actor/reason metadata, retention, and approval references. |
| Testing | Pass unit, integration, PCAP, functional, failure-injection, reboot, load, soak, fail-open, and fail-closed tests. |

## 6. Implementation phases

### Phase 0 — Design and baseline freeze

Status: **completed for the development baseline on 2026-08-10.**

Deliverables:

- production charter and roadmap;
- v1 capability/gap inventory;
- compatibility contract;
- threat model and privileged-operation inventory;
- acceptance criteria for every production requirement;
- v1 reference manifest excluding caches, logs, evidence, and user data.

Gate:

- no runtime v2 implementation;
- v1 remains unchanged;
- architecture and production priorities are explicitly approved.

### Phase 1 — Transaction foundation

Status: **initial Python implementation completed on 2026-08-10; production integration and later qualification gates remain pending.**

Planned modules:

```text
meercata/
  models.py             typed state, policy, and result models
  paths.py              fixed development and production paths
  locking.py            single-controller lock
  audit.py              structured controller audit
  command_runner.py     safe subprocess execution
  transaction.py        stage/validate/apply/verify/rollback engine
  state_store.py        durable transaction and last-known-good state
```

Acceptance gate:

- concurrent mutation is rejected cleanly;
- commands use fixed argv with timeout and structured results;
- audit records are produced for success and failure;
- process termination at each state transition is recoverable;
- no IDS/IPS behavior is migrated yet.

Initial verification: 56 Phase 1 tests pass, including lock contention, audit and state failures, command timeout/output bounds, rollback failure, symlinked-directory rejection, and simulated interruption at each transaction state. The gate must be re-run in the installed production filesystem and failure-injection environments before release.

### Phase 2 — Read-only health and diagnostics

Status: **initial Python implementation completed on 2026-08-10; installed least-privilege and live traffic qualification remain pending.**

Commands:

```text
meercata health
meercata health --json
meercata health --watch
```

Required health states:

```text
0 healthy
1 degraded
2 critical
3 unknown or configuration error
```

Acceptance gate:

- health detects stale EVE, stopped process, missing hook, wrong queue/interface, failed socket, packet counter stall, resource threshold, and disk pressure;
- JSON schema is stable and tested;
- read-only health works without unrestricted root access.

Initial verification: health-v1 schema and CLI exit behavior are tested; simulated healthy IDS/IPS and stopped process, stale EVE, socket failure, capture mismatch, interface mismatch, missing/wrong hook or queue, listener loss, packet stall/loss, TCP gaps, memcap emergency, disk, memory, RSS, and CPU pressure are covered. Live installed-host permissions, real traffic counter progression, and alert-threshold baselining remain part of the Phase 4 and Phase 6 gates.

### Phase 3 — RuleOps pipeline

Status: **Python pipeline, privileged activation, installed IDS live-reload/rollback, and the seven-case redistribution-safe production baseline completed through dev14; environment-specific corpus extensions and later production gates remain pending.**

Workflow:

```text
download to staging
  -> record source/version
  -> build candidate with suricata-update
  -> strict configuration/rule validation
  -> show diff and rule-count change
  -> snapshot active rules
  -> atomic activation
  -> non-blocking reload
  -> poll reload completion
  -> verify loaded/failed rules and packet health
  -> commit or rollback
```

Acceptance gate:

- invalid and unexpectedly reduced rulesets never become active;
- reload failure restores the previous ruleset;
- update, validation, reload, and rollback are fully audited;
- a PCAP regression pack verifies expected alerts before promotion.

Initial verification: isolated ET/Open candidate storage, hashing, parsing, duplicate rejection, bounded differences, rule-count/reduction policy, fixed update/validation argv, audit, immutable PCAP pack parsing and hash checks, bounded offline EVE evaluation, required/forbidden alert oracles, regression evidence binding, non-blocking reload polling, loaded/failed-rule verification, transactional promotion, post-reload health gating, rollback reload, and recovery-failure classification are automated. Dev13 additionally passed installed live mutation and rollback against full ET/Open rules. Dev14's original seven-case baseline passed positive DNS/HTTP/TCP/UDP and benign DNS/HTTP/TLS replay against the same 52,322-rule snapshot. The production CLI intentionally remains blocked until the remaining Phase 4 gates close.

### Phase 4 — Privilege separation and supervision

Status: **RuleOps helper, socket mediation, supervision templates, deterministic native Debian packaging, staged/root-owned qualification, pinned lifecycle qualification, official Debian Backports Suricata 8.0.6 qualification, live Debian 13 KVM systemd/readiness/IDS health, guarded activation/reload/rollback, the synthetic production regression baseline, signed/pinned local-APT delivery, crash/restart-limit/reboot recovery, fail-open nftables/NFQUEUE behavior, bounded load/overload, the installed IPS lifecycle, dev22 local transitions, the dev23 durable HTTPS-delivery foundation, and dev24 loopback TLS/rotation/outage/delivery-pressure behavior are qualified. Production key custody/network delivery, deployment-specific NFQUEUE capacity/multi-queue/NIC/soak, real external collector/credential availability, environment-specific corpus extensions, and operational availability remain pending.**

Deliverables:

- installed package and production filesystem layout;
- unprivileged CLI and narrowly scoped privileged operations;
- root-owned configuration with explicit group access;
- readiness-aware systemd unit;
- bounded restart and recovery policy;
- log rotation and retention;
- central monitoring integration points.

Acceptance gate:

- unknown commands and paths are denied;
- the UI cannot execute arbitrary privileged commands;
- startup is not considered successful before Suricata readiness;
- restart loops stop at the configured threshold and notify the operator.

Initial helper, packaging, and qualification verification includes all earlier fixed-operation, transaction, package-integrity, ownership, sudoers, and static-systemd checks. Dev12 additionally passed under real systemd PID 1 with official Suricata: notification readiness, one supervised process, root-owned socket mediation, live AF_PACKET traffic, fresh EVE, 15/15 healthy checks, the sandboxed service identity, and timer execution. Dev13's fail-closed six-check run passed real helper activation, non-blocking reload, forced post-reload failure, rollback reload, final 15/15 health, root-only receipts, and dual audit evidence. Dev15 passed ten signed-repository checks. Dev16 passed automatic restart, bounded start-limit lockout, explicit recovery, reboot, timer execution, 15/15 health, and protected-file integrity. Dev21 passed the private installed IPS target, ordered fail-open lifecycle, failure injection, reboot, 17/17 health, protected integrity, and cleanup. Production key custody and network delivery remain untested; public promotion remains gated.

Dev22 adds the local monitoring integration point: condition fingerprints, deduplicated transition/recovery events, crash repair, a systemd journal producer, bounded state/history, service-user ownership, and logrotate policy passed deterministic qualification. External collector authentication/delivery/retry, stale-timer alerting, and long-duration retention execution remain environment-specific gates.

Dev23 adds an independently scheduled three-minute freshness watchdog plus a root-configured verified-HTTPS connector, deterministic event IDs, bounded durable outbox, at-least-once idempotency contract, exponential retry, receipt-first crash reconciliation, and dead letters. All eight deterministic delivery checks passed without external credentials or network access. A deployment must still qualify its real collector identity, token lifecycle, certificates, availability, proxy path if any, and long-duration retention/response behavior.

Dev24 adds twelve passing real loopback TLS and delivery-health checks: verified trust and hostname refusal, token retirement/acceptance, duplicate processing suppression, retry persistence across worker restart, collector recovery, CA rotation, and healthy/degraded/critical delivery pressure. The ordinary config/token/CA loader is exercised; the independent watchdog requires no credentials or network. The remaining real-collector, installed timer execution, retention/soak, and deployment availability gates remain mandatory.

### Phase 5 — Transactional IDS/IPS lifecycle

Deliverables:

- v1 IDS behavior migrated through the transaction engine;
- Meercata-owned nftables/NFQUEUE state managed atomically;
- explicit end-to-end fail policy;
- durable pre-run and last-known-good state;
- bounded automatic recovery;
- emergency bypass and operator runbook.

Dev17 progress: strict fail-open gateway-forward configuration, deterministic native nftables batches, complete owned-table inspection, foreign/drift refusal, atomic replacement, and unrelated-table preservation passed a live disposable Debian 13 network-namespace gate. Privileged helper orchestration, durable pre-run/LKG receipts, live Suricata NFQUEUE traffic, listener-loss behavior, and recovery remain pending.

Dev18 progress: UUID/state/lock-bound helper orchestration, durable snapshot/prepared/applied/rollback receipts, root activation ownership proof, exact verify, forced post-apply rollback, dual audit, emergency bypass, and unrelated-table preservation passed a live disposable namespace gate. Live Suricata listener/verdict behavior, overload/capacity/latency, service lifecycle, and reboot recovery remain pending.

Dev19 progress: the Python-only guarded qualifier constructed a disposable routed client/gateway/server topology, committed the real dev18 policy, validated Suricata NFQ, proved queue attachment and counter progress, passed a SHA-256-verified accepted transfer, blocked private SID 9900019 with EVE action `blocked`, stopped the listener, and delivered the formerly blocked path through mandatory nftables bypass. The recorded five-transfer 197.75 Mbit/s sample is explicitly non-capacity evidence; overload/capacity/soak remains pending.

Dev20 progress: a CPU/RAM/PID-bounded, read-only disposable run passed mixed accept/drop correctness, zero normal NFQUEUE transport drops and degradation counters, process-resource sampling, abrupt listener loss during active traffic, controlled listener-present saturation detection, exact emergency bypass, and post-bypass payload recovery. Its 303.951 Mbit/s synthetic result is profile evidence only; deployment-specific capacity, multi-queue/NIC behavior, 24–72 hour soak, and installed systemd IPS recovery remain pending.

Dev21 progress: the installed private systemd target passed listener-first activation, guard and engine `SIGKILL` fail-open removal, reverse-order normal shutdown, a changed boot ID, automatic listener/policy/guard recovery, 17/17 least-privilege IPS health, unchanged protected files, and disabled/inactive cleanup in a hash-pinned Debian 13 KVM guest. Package installation still does not enable the target and the public CLI remains gated. Deployment-specific capacity, multi-queue/NIC behavior, 24–72 hour soak, central monitoring/alert delivery, and operational release controls remain pending.

Acceptance gate for production IDS:

- passive traffic visibility and evidence continuity verified under sustained load;
- controller/Suricata restart and reboot recovery verified;
- packet-loss thresholds and alerts established.

Additional gate for production IPS:

- NFQUEUE capacity and latency benchmarked;
- queue overload and listener-loss behavior verified;
- firewall rollback cannot alter unrelated UFW/Docker/admin state;
- fail-open pilot completed before fail-closed consideration;
- fail-closed requires an approved HA or bypass design.

### Phase 6 — Production qualification

Required test families:

- Python unit and property tests;
- namespace-based nftables integration tests;
- Suricata-Verify/PCAP regression tests;
- configuration and malformed-rule tests;
- failure injection at every transaction state;
- SIGINT, SIGTERM, SIGKILL, crash, and reboot tests;
- disk-full, permission, timeout, and corrupted-state tests;
- NFQUEUE load and latency tests;
- 24–72 hour soak tests;
- upgrade and downgrade tests;
- disaster-recovery rehearsal.

Release gate:

- all P0/P1 requirements pass;
- no unresolved critical security or data-loss defect;
- rollback and emergency bypass are demonstrated;
- operator runbook and monitoring alerts are complete;
- production deployment begins as passive IDS, then fail-open IPS pilot, never directly as untested fail-closed IPS.

## 7. Compatibility policy

- Preserve familiar high-level concepts: `check`, `diag/health`, `ids`, `ips`, `monitor`, rules, backup, and systemd management.
- CLI flags may be deprecated only with a documented replacement and transition period.
- v1 interactive defaults under a home directory are not a production state store.
- v1 threat evidence remains readable but is not automatically imported as controller state.
- Full firewall backup remains a disaster-recovery artefact, not an automatic transactional rollback mechanism.

## 8. Phase 0 architecture decisions

The initial decisions are recorded in [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md). They establish the Phase 1 development baseline without waiving any later production acceptance gate.

1. Supported production Linux distributions and systemd versions.
2. Supported Suricata major/minor versions.
3. nftables-only production scope or continued iptables compatibility.
4. Production IDS/IPS topology and high-availability expectation.
5. Audit destination: journald, JSONL, remote collector, or a combination.
6. Operator authorization model: sudoers, polkit, group membership, or service API.
7. Configuration format and schema versioning policy.
8. Metrics integration target and alert thresholds.
9. Rule sources, update schedule, approval workflow, and retention.
10. Evidence retention, privacy, integrity, and chain-of-custody requirements.

## 9. Official technical references

- Suricata 8.0.6 documentation: <https://docs.suricata.io/en/suricata-8.0.6/>
- Suricata-Update: <https://docs.suricata.io/en/suricata-8.0.6/rule-management/suricata-update.html>
- Rule reloads: <https://docs.suricata.io/en/suricata-8.0.6/rule-management/rule-reload.html>
- Unix socket commands: <https://docs.suricata.io/en/suricata-8.0.0/unix-socket.html>
- Statistics and packet loss: <https://docs.suricata.io/en/suricata-8.0.6/performance/statistics.html>
- Security and privilege dropping: <https://docs.suricata.io/en/suricata-8.0.6/security.html>
- systemd readiness notification: <https://docs.suricata.io/en/suricata-8.0.6/configuration/systemd-notify.html>
- Suricata testing guidance: <https://docs.suricata.io/en/latest/devguide/codebase/testing.html>
