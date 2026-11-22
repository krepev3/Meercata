# Installed monitoring and retention VM qualification

Dev25 adds a two-stage, Python-only qualification of the installed producer,
freshness watchdog, HTTPS delivery worker, delivery-health watchdog, and
logrotate policy under real systemd PID 1. Run it only in a disposable Debian
13 x86-64 QEMU/KVM guest. It deliberately stops Suricata, pauses monitoring,
rotates qualification logs, and fills a 64 KiB tmpfs mounted over the guest
monitor log directory. It is not an operator recovery command.

## Preconditions

- Verify the official Debian genericcloud image before boot. The dev25 gate is
  pinned to build `20261116-2664` and SHA-512
  `37cb32b320820417eb04b335afcf489bfb4cecce4a957190d09cb2bffbe02b56a1cadd62d78c6ead92aa7839d5ea65e4260f994bbb4b54490df59fdf11ee1d97`.
- Install `meercata` version `2.0.0~dev25-1`, its declared dependencies, and
  OpenSSL. Retain the exact installed versions in the resulting report.
- Configure an ordinary healthy IDS with a real Suricata notification service,
  active rules, readable EVE statistics, the privileged read-only socket helper,
  and continuous synthetic traffic. No production traffic or credentials.
- Use a controller configuration without a delivery table, empty monitor state
  and logs, and all five monitor/legacy-health timers disabled. The gate refuses
  to replace existing delivery configuration, qualification credentials, or an
  existing qualification workspace.
- Both stages independently require root, Debian 13, systemd PID 1, QEMU/KVM,
  the pinned image hash, and the exact confirmation phrase below. The caller
  supplies the image identity after independently hashing the downloaded image;
  the in-guest guard cannot attest to the host's original image download.

## Prepare, reboot, verify

```text
/usr/lib/meercata/bin/meercata-monitor-systemd-vm-qualifier prepare \
  --confirmation 'QUALIFY DISPOSABLE MEERCATA DEBIAN 13 MONITOR SYSTEMD VM' \
  --image-sha512 APPROVED_SHA512
```

The prepare phase exercises the stock installed services and timers without
changing their schedules. JSON observations are read from the current boot and
the exact service invocation. Manual probes restart only the fixed oneshots
and reset their start accounting between probes; timer-only verification uses
the stock schedules and settings. It checks the service identity and privilege
policy, root-owned service-readable credentials, denied access to privileged
state, real verified HTTPS, token retirement/rotation, real elapsed producer
staleness and recovery, fourteen forced log rotations with twelve retained
generations, installed writers after rotation, bounded ENOSPC with unchanged
durable state, process restart deduplication, CA distrust/rotation, and pending
outage retry state.

A create-only root-owned mode-0600 marker records package identities, the boot
ID, completed checks, durable sequence, and protected-file hashes below
`/var/lib/meercata/qualification/monitor-systemd-v1`. Temporary delivery
configuration and credentials remain only for the reboot test. Save the
`reboot-required` report, then reboot the disposable guest normally.

```text
/usr/lib/meercata/bin/meercata-monitor-systemd-vm-qualifier verify \
  --confirmation 'QUALIFY DISPOSABLE MEERCATA DEBIAN 13 MONITOR SYSTEMD VM' \
  --image-sha512 APPROVED_SHA512
```

Verification rejects an unchanged boot ID, changed packages, or changed
protected files. All four stock timers must fire in the new boot, their
services must succeed, the ordinary durable outbox must drain, and monitoring
must preserve its sequence. The test then disables/stops its timers, restores
the original configuration, removes generated token/CA files and private keys,
recovers Suricata, and compares protected hashes. It preserves monitor data.
A failed guarded run attempts the same bounded cleanup.

The successful final report uses `monitor-systemd-vm-qualification-v1` and
contains fifteen ordered checks. Standard output contains one JSON report;
progress goes to standard error. A fresh guest is required for a repeat run.

## Limits

This gate uses a loopback collector, disposable credentials, and synthetic
traffic. Forced rotation establishes generation limits, compression, ownership,
and writer recovery; it does not establish elapsed weekly retention or a
24–72-hour soak. ENOSPC covers the bounded monitor-log filesystem, not whole-root
exhaustion or hardware failure. Production collector/DNS/proxy behavior,
deployment capacity, NIC/multi-queue performance, abrupt power loss, release-key
custody, and public promotion/IPS command gates remain separate requirements.
