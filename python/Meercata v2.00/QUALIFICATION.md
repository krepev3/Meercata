# Meercata staged-image qualification contract

## Meaning of staged-qualified

`staged-qualified` means a hash-verified Meercata production image passed bounded static and disposable-root checks using the host's real Python, sudo, and systemd tooling. It does not mean installed-host, live Suricata, IDS, IPS, or production qualification has completed.

The qualifier is Python-only and writes only to an automatically removed temporary filesystem root. It reads but does not modify the supplied staged image. It never invokes `sudo`, targets `/`, reloads systemd, creates a live user, starts a service, connects to Suricata, installs rules, or changes firewall state.

## Interface

Build and verify the staged image first:

```text
python3 -m meercata.package_builder stage /absolute/path/to/stage
python3 -m meercata.package_builder verify /absolute/path/to/stage
python3 -m meercata.package_qualifier /absolute/path/to/stage
```

The qualifier emits one `qualification-v1` JSON object and returns zero only when every check passes. Expected package or qualification failures return exit code 3 without emitting a successful report.

## Qualification checks

The current fixed sequence is:

1. `package.manifest` — verify every managed file SHA-256 and file/directory mode before invoking host tools;
2. `python.imports` — import the staged package, CLI, health, package builder, and privileged helper in Python isolated mode using only the staged module root;
3. `sudoers.syntax` — parse the copied exact policy with `/usr/sbin/visudo -c -f`;
4. `systemd.units` — verify all health/monitor/freshness/delivery/delivery-health services and timers, the private IPS units, and the Suricata override with `/usr/bin/systemd-analyze --root`;
5. `sysusers.materialize` — apply the copied sysusers file inside the disposable root and verify the `meercata` account remains outside `meercata-operators`;
6. `tmpfiles.dry-run` — resolve the generated identities and verify all twelve managed runtime directories using `/usr/bin/systemd-tmpfiles --root --create --dry-run`.

The systemd check adds minimal target, Suricata unit, and executable placeholders only inside the disposable root. These fixtures are not package files and do not claim to validate the distribution Suricata unit's runtime behavior.

All subprocesses use absolute executable paths, fixed arguments derived internally, clean environment, no shell, bounded output, and 30-second timeouts. Reports contain check results and counts, not temporary paths or raw command output.

## Fail-closed behavior

Qualification fails before returning a success report when it detects:

- missing, changed, oversized, wrong-mode, or non-regular package files;
- staged import failure or package version mismatch;
- invalid sudoers syntax;
- invalid or incomplete systemd units;
- sysusers failure or monitoring-user membership in the operator group;
- tmpfiles failure or omission of a managed directory;
- unavailable validator tools, nonzero results, timeouts, or truncated output.

The supplied staged image is fingerprint-tested before and after qualification to ensure the process is read-only with respect to the artifact.

## Explicit limitations

This development environment runs as UID 1000. Consequently, the current qualifier deliberately performs a tmpfiles dry run and records these limitations in every successful report:

- package and runtime `root:root` ownership/chown are not applied;
- live Suricata readiness, socket, reload, traffic, restart throttling, crash, and reboot behavior are not exercised;
- native package signature, install, upgrade, downgrade, removal, and purge are not exercised.

Those are mandatory gates for a root-controlled disposable Debian 13 qualification host. A report must never be relabeled `installed-qualified` or `production-qualified` while any of these limitations remain.

## Root-owned disposable Debian 13 layer

The next qualification layer is implemented as `meercata.container_qualifier`. It is deliberately double-guarded and refuses execution unless all of these are true:

- effective UID and GID are zero;
- `/.dockerenv` is a regular file;
- `/etc/os-release` identifies Debian version 13;
- `/run/systemd/system` is absent, preventing use against a running systemd container host;
- the exact confirmation phrase is passed;
- the official Debian `13-slim` image digest equals `sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258`.

The orchestration pins that digest, provisions Python 3, sudo, and systemd in a temporary derived image, then runs with networking disabled, no-new-privileges, bounded CPU/memory/PIDs, and only the capabilities needed to apply root ownership and create identities. The source tree is mounted read-only. The provisioning container and derived image are deleted after qualification; only the official base-image cache remains.

The `container-qualification-v1` report proves:

1. the Debian 13/container/root guard passed;
2. a deterministic image was built and installed without destination collisions;
3. the service and operator identities were actually created and remain separate;
4. tmpfiles actually created twelve runtime directories with exact numeric ownership and modes, including five service-owned monitor paths and the root-controlled credential directory;
5. every package file and manifest is `root:root`, has the declared mode, and retains its SHA-256;
6. the CLI runs as the unprivileged service user and the helper exposes only its fixed operation allowlist;
7. the service user receives only the health helper sudo authorization;
8. installed systemd units and the Suricata drop-in parse together;
9. active configuration is not installed and the configuration/state/log roots remain outside package ownership.

The pinned Debian 13 execution passed all nine checks. Its versioned report is retained under `qualification-evidence/` and validated against its schema.

The native `.deb` lifecycle layer builds three ordered package revisions and exercises clean install, repeated configure, upgrade, modified-file rejection before unpack, removal, and protected-data preservation. See [NATIVE-DEBIAN.md](NATIVE-DEBIAN.md). A successful report is `debian-lifecycle-qualified`, not production-qualified.

The Suricata package layer uses official Debian 13 Backports packages provisioned at exact reviewed versions. During the network-disabled qualification run it authenticates the cached InRelease with the Debian keyring, verifies release freshness and signed package metadata, checks installed package files, exercises the required Suricata 8.0.6 build capabilities and strict configuration test, and installs Meercata without ignored dependencies. Normal Meercata removal must preserve Suricata. See [SURICATA-PACKAGES.md](SURICATA-PACKAGES.md). A successful report is `suricata-package-qualified`, not production-qualified.

## Debian 13 KVM readiness layer

Dev12 adds `meercata.systemd_vm_qualifier`. It is guarded by the exact disposable-VM confirmation phrase, root identity, Debian 13, systemd as PID 1, KVM/QEMU virtualization, x86-64, and the SHA-512 of the official Debian genericcloud image. The host verified that downloaded image against Debian's published SHA-512 before creating a disposable qcow2 overlay.

The qualifier checks exact Meercata, Suricata, and suricata-update package versions; real Suricata `active/running` notification readiness; its main PID, result, drop-in, and root-owned socket; a fully healthy CLI run under the dedicated `meercata` identity; and successful execution of the hardened oneshot and timer. It starts only the read-only health oneshot and timer. It does not change configuration, rules, firewall state, Suricata lifecycle, package state, or network policy.

The recorded report is `systemd-vm-readiness-qualified`, not production-qualified. It proves the five bounded dev12 checks and preserves these limitations: direct unsigned `.deb` installation, IDS-only traffic, no live rule mutation/rollback, and no crash/reboot recovery.

## Debian 13 KVM live RuleOps layer

Dev13 adds `meercata.ruleops_vm_qualifier`, guarded independently by its exact disposable-VM confirmation phrase, the same approved cloud-image SHA-512, root identity, Debian 13, systemd PID 1, KVM/QEMU, x86-64, and exact dev13/Suricata package versions.

The package now includes the original synthetic `dev13-ruleops-v1` PCAP pack, its reproducible source, and two hash-pinned alert-only overlays. A separately guarded preparation mode builds candidates from the active ET/Open rules and passes both through the ordinary policy, strict validation, and PCAP regression gates. Their UUIDs and hashes must differ, and both must differ from the initial active rules. The first transaction must commit after helper activation, non-blocking reload, and healthy runtime verification. The second must activate and reload, pass genuine health collection, then enter a deliberate critical qualification result; it must restore and reload the first ruleset. The final report verifies transaction states, active hashes, root-only receipts, final health, and both audit streams.

The exact dev13 artifact recorded in `qualification-evidence/deb-build-dev13.json` passed all six checks in the approved Debian 13 KVM guest. The first transaction reached `COMMITTED`; the deliberately failed second transaction reached `ROLLED_BACK`; the final active SHA-256 matched the committed candidate; all 15 runtime checks were healthy; and both receipt and audit streams were present. The schema-valid report is retained as `qualification-evidence/ruleops-vm-dev13.json`. This is `ruleops-vm-qualified`, not production-qualified, and public promotion remains disabled. See [RULEOPS-VM.md](RULEOPS-VM.md).

## Production regression corpus layer

Dev14 adds the original synthetic `production-baseline-v1` corpus. Seven deterministic captures cover positive DNS, HTTP, raw TCP, and raw UDP detection plus benign-negative DNS, HTTP, and TLS behavior. Every packet uses documentation-only addresses and locally administered MAC addresses; no user traffic, credentials, exploit binary, executable payload, or third-party capture is included.

The pack was replayed case-by-case with Suricata 8.0.6 against the exact 52,322-active-rule ET/Open snapshot used by dev13. Each positive case produced exactly one intended alert and none of the other three protected identities; all benign cases produced zero alerts. The generator reproduced every PCAP byte-identically, the manifest pins each SHA-256, and the schema-valid result is retained as `qualification-evidence/regression-corpus-dev14.json`. This is a qualified redistribution-safe baseline, not proof that it represents a deployment's traffic diversity or false-positive history.

## Signed APT repository layer

Dev15 adds `meercata.apt_repository_qualifier`. It inherits the exact root, disposable-container, Debian 13, and approved-image-digest guard and adds a strict no-network condition: loopback is the only interface and the route table is empty. Debian and the exact qualified Suricata dependencies are authenticated and provisioned before that decisive run.

Inside the isolated container, the qualifier builds revisions 1 and 2, generates an expiring qualification-only RSA-3072 key, publishes SHA-256-bound `Packages`, by-hash, `Release`, `Release.gpg`, and `InRelease` metadata, and independently verifies the signer and authenticated release bytes with `sqv`. APT uses only that local source and its explicit `Signed-By` keyring, with insecure and unauthenticated modes disabled.

The gate proves rejection of an unpinned key, modified signed metadata, and modified package bytes. It then installs `2.0.0~dev15-1`, upgrades through signed metadata to `2.0.0~dev15-2`, and removes Meercata while preserving protected data. All ten checks passed; the schema-valid report is retained as `qualification-evidence/apt-repository-dev15.json`. This is `apt-repository-qualified`, not production-qualified. See [APT-REPOSITORY.md](APT-REPOSITORY.md).

## Fail-open nftables namespace layer

Dev17 adds `meercata.nftables_namespace_qualifier`, guarded by root identity, Docker isolation, Debian 13, the pinned base-image digest, absence of systemd PID 1, `--network none`, a fixed nft executable, and an exact mutation confirmation phrase. The decisive run used only `CAP_NET_ADMIN` with read-only source/root filesystems and temporary scratch space.

The live gate rejected a foreign `inet meercata` table, syntax-checked and applied the initial policy, atomically replaced it with a second transaction identity, rejected an injected foreign rule, and removed only the Meercata table. A separate operator table retained its semantic fingerprint throughout. The schema-valid seven-check result is retained as `qualification-evidence/nftables-namespace-dev17.json`; see [NFTABLES-NAMESPACE.md](NFTABLES-NAMESPACE.md).

This qualifies the policy compiler and namespace ownership boundary, not production IPS. No Suricata NFQUEUE listener, packet verdict, listener-loss path, capacity/latency benchmark, privileged transaction helper, service recovery, or reboot was exercised.

## Transactional nftables helper layer

Dev18 adds `meercata.nftables_transaction_qualifier` under the same pinned Debian 13, root, Docker, no-systemd, no-network, fixed-nft, and exact-confirmation guards. The source and container root were read-only; only temporary state and the container network namespace were writable, with `CAP_NET_ADMIN` as the only added capability.

The gate committed one real transaction, applied a second policy and forced post-apply verification failure, restored the first receipted policy, verified five mode-0600 receipts and both controller/privileged audit streams, then removed the policy through the explicit emergency bypass. An unrelated operator table retained the same semantic SHA-256 throughout.

The seven-check schema-valid result is retained as `qualification-evidence/nftables-transaction-dev18.json`; see [NFTABLES-TRANSACTIONS.md](NFTABLES-TRANSACTIONS.md). It qualifies the helper transaction boundary, not Suricata NFQUEUE packet handling or public IPS activation.

## Live NFQUEUE functional layer

Dev19 implements `meercata.nfqueue_functional_qualifier` under the pinned Debian 13, root, Docker, no-systemd, no-network, and exact-confirmation guards. It additionally requires explicit IPv4 forwarding, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN` in an unconfined disposable container because it creates two child network namespaces. The source is read-only and the harness does not load kernel modules or modify host firewall state.

The nine-check gate creates a routed client → Meercata gateway → server topology, validates Suricata NFQueue support and an exclusive private drop rule, commits the exact dev18 policy on queue 42, proves listener attachment, verifies an accepted 1 MiB payload and a blocked flow with EVE evidence, records a five-transfer bounded functional timing sample, then stops Suricata and requires the formerly blocked flow to pass through nftables `bypass`. See [NFQUEUE-FUNCTIONAL.md](NFQUEUE-FUNCTIONAL.md).

The final guard requires the kernel NFQUEUE status backend to exist before any topology or Suricata process is created. The decisive run passed all nine checks: queue 42 attached with zero initial kernel/userspace drops, the accepted 1 MiB payload matched its SHA-256, private SID 9900019 blocked port 9090 with EVE action `blocked`, both directional queue counters progressed, and the same port delivered the complete payload after listener loss. The five-transfer sample recorded 39.988/42.277/44.485 ms minimum/median/maximum and 197.75 Mbit/s aggregate throughput. The schema-valid report is retained as `qualification-evidence/nfqueue-functional-dev19.json`.

This is `nfqueue-functional-qualified`, not production-capacity-qualified. The sample does not qualify overload, packet loss, queue saturation, multi-queue scaling, resource ceilings, or soak behavior.

## Bounded NFQUEUE load and overload layer

Dev20 adds `meercata.nfqueue_load_qualifier`, inheriting the dev19 isolation/pre-existing-backend guards and adding mandatory CPU, memory, and PID cgroup ceilings. The decisive container used a read-only root/source, temporary `/tmp` and `/run`, no external network, no-new-privileges, 1 GiB memory/swap, two CPUs, and 512 PIDs. See [NFQUEUE-LOAD.md](NFQUEUE-LOAD.md).

The normal six-second mixed profile passed 227 deterministic 1 MiB accepted transfers and 68 intended blocked flows with zero accepted failure, corruption, unexpected accept, kernel queue drop, or userspace queue drop. Measured synthetic goodput was 303.951 Mbit/s with 206.656 ms median and 310.134 ms p95 transfer latency. Suricata peaked at 69,922,816 bytes RSS and 117.8% of one CPU core; NFQ errors, flow emergency, TCP reassembly gaps, TCP session/segment memcap drops, and alert overflow remained zero.

During a second six-second accepted-load phase, a bounded `SIGKILL` removed the listener; all 1370 completed attempts remained successful and uncorrupted, and the formerly blocked port delivered through nftables bypass. A final controlled phase kept the listener attached but paused verdict processing, generating three kernel queue drops. This proved that listener-present saturation is not covered by listener-absence bypass. The existing `queue-overload` emergency operation removed the exact owned table and restored the full payload.

All ten checks passed and the strict result is retained as `qualification-evidence/nfqueue-load-dev20.json`. This is a fixed synthetic profile, not production capacity or a lossless-overload claim. Multi-queue/NIC behavior, deployment traffic/rules, 24–72 hour soak, installed IPS lifecycle, monitoring-driven response, and reboot remain gated.

## Installed IPS systemd and reboot layer

Dev21 adds `meercata.ips_systemd_vm_qualifier`, guarded by root identity, Debian 13, systemd PID 1, KVM/QEMU, x86-64, an exact destructive-test confirmation phrase, and the SHA-512 of the approved official genericcloud image. It requires the exact dev21 package plus Debian Backports Suricata `1:8.0.6-1~bpo13+1` and suricata-update `1.3.8-1~bpo13+1`.

Preparation starts the private target and requires the engine, activation service, and guard to be active in listener-first order with an exactly owned policy and zero queue drops. It injects bounded `SIGKILL` into the systemd-tracked guard and engine separately and requires each failure to remove the policy. It rearms between cases, then stops the target, waits for all component units to become inactive, proves fail-open absence, starts a final transaction, and seals exact package/protected-file/boot state in a root-only reboot marker.

Verification refuses the unchanged boot ID, package drift, or protected-file drift. It waits for automatic target, listener, policy, and guard recovery; runs all 17 health checks under the dedicated `meercata` identity; then disables/stops the target and requires all components inactive with no owned table. The eleven-check schema-valid report is retained as `qualification-evidence/ips-systemd-vm-dev21.json`; see [IPS-SYSTEMD.md](IPS-SYSTEMD.md).

This qualifies the installed single-node fail-open lifecycle, not a deployment's capacity or operational readiness. The package does not enable the target. Multi-queue/NIC behavior, deployment rules and traffic, long-duration soak, central alert delivery, HA/hardware bypass, disk exhaustion, signed release delivery, and public CLI activation remain outside this gate.

## Durable monitoring transition layer

Dev22 adds `meercata.monitor_qualifier`, a non-root disposable-local gate for the transport-neutral monitoring boundary. It uses fixed synthetic health reports and automatically removed state to exercise a critical baseline, identical-observation suppression, a changed condition at the same severity, recovery, and repair after the atomic state snapshot is removed while the synchronized transition remains.

Separate fixtures require malformed state and an active transition log above 8 MiB to fail closed. All seven checks passed; the strict report is retained as `qualification-evidence/monitoring-dev22.json` and validated against `monitor-qualification-v1`. Staged qualification separately verifies both monitor systemd units, nine tmpfiles paths, the service identity boundary, package hashes/modes, and logrotate payload.

This is `monitoring-qualified`, not central-delivery or soak-qualified. It does not exercise external credentials, network delivery, retries/dead letters, collector availability, stale-timer alerts, installed logrotate execution, or long-duration disk behavior. See [MONITORING.md](MONITORING.md).

## Durable monitor delivery layer

Dev23 adds `meercata.monitor_delivery_qualifier`, an eight-check disposable-local gate. It proves transition enqueue and duplicate suppression, retry deferral, eventual acceptance, permanent rejection and dead-lettering, receipt-first crash reconciliation without a second transport call, fixed-threshold stale scheduling, and refusal of non-HTTPS endpoints. The strict report is retained as `qualification-evidence/monitor-delivery-dev23.json` and validated against `monitor-delivery-qualification-v1`.

The qualifier injects transport results and a disposable token; it performs no external network call. Unit coverage separately verifies strict root-controlled configuration, credential paths/modes, schema-bound CLI results, bounded queries, and corrupt-envelope refusal. Staged qualification covers thirteen units and twelve tmpfiles directories. This is `monitor-delivery-qualified`, not real-collector or operational-availability qualified.

## Loopback TLS and delivery-health layer

Dev24 adds `meercata.monitor_tls_qualifier`: twelve real loopback HTTPS checks
using automatically removed certificates, tokens, and monitor state. It proves
trusted delivery, hostname refusal before HTTP, retired-token rejection and
current-token acceptance, collector deduplication, persisted retry after worker
restart, recovery, CA rotation, and healthy/degraded/critical delivery pressure.
The strict schema requires every distinct check and its successful oracle. The
report is retained as `qualification-evidence/monitor-tls-dev24.json`.

The generated test CA explicitly includes the key-usage and CA extensions
required by strict TLS validation. Verification is never disabled. All collector
lifetimes are bounded and close on exceptions. The ordinary production
configuration/token/CA loader is used with isolated filesystem paths.

The package includes the fixed qualification launcher and schema plus the
independent delivery-health timer. Staged qualification now checks fifteen units
and twelve runtime directories. Historical dev22/dev23 evidence remains intact;
the local monitoring qualifiers report the actual executing package version.
Real external collector identity, production token/certificate rotation, proxy
paths, installed monitor timers, long-duration retention, and operator response
remain deployment gates. See [MONITORING.md](MONITORING.md).

## Remaining qualification layers

Dev16 adds the next disposable-VM layer as a guarded two-phase crash and reboot qualifier. The exact artifact passed automatic restart, the three-in-five-minute start limit, rejected-start proof, explicit recovery, a changed boot ID, ready services, an enabled timer that executed successfully after reboot, 15/15 healthy IDS checks, and protected-file hashes. The schema-valid report is retained as `qualification-evidence/recovery-vm-dev16.json`; see [RECOVERY-VM.md](RECOVERY-VM.md).

Later disposable gates must cover explicit purge behavior, deployment-specific NFQUEUE capacity/multi-queue/NIC behavior, 24–72 hour soak, disk exhaustion, and central monitoring-driven response. Production repository work must separately qualify signing-key custody/rotation, the release builder, HTTPS/mirror delivery, access control, monitoring, and availability. Environment-specific qualification must extend the synthetic corpus with reviewed local protocols and privacy-scrubbed false-positive cases. These gates must not target a production machine first.
