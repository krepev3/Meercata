# Meercata crash and reboot recovery VM qualification

## Scope

Dev16 adds a two-phase qualification gate for the installed Suricata supervision policy and Meercata health timer. It deliberately kills the Suricata main process, proves systemd automatic restart, drives the unit into its configured start-limit lockout, performs an explicit recovery, reboots the disposable VM, and verifies service/timer recovery plus protected-file integrity.

This gate is destructive to service availability and must run only in a disposable hash-pinned Debian 13 KVM/QEMU guest. It is not a production recovery command.

## Safety guard

Both phases independently require:

- effective UID and GID zero;
- systemd as PID 1;
- Debian 13 on x86-64;
- KVM or QEMU virtualization;
- the approved Debian genericcloud SHA-512;
- the exact confirmation phrase `QUALIFY DISPOSABLE MEERCATA DEBIAN 13 RECOVERY VM`;
- exact Meercata, Suricata, and suricata-update package versions.

The qualifier never invokes a shell. Its service mutations are fixed `systemctl kill`, `reset-failed`, `start`, and `enable --now` argument vectors. If crash injection fails partway through, it makes a bounded best-effort attempt to reset and restart Suricata before returning failure.

## Phase 1: prepare

```text
/usr/lib/meercata/bin/meercata-recovery-vm-qualifier prepare \
  --confirmation 'QUALIFY DISPOSABLE MEERCATA DEBIAN 13 RECOVERY VM' \
  --image-sha512 APPROVED_SHA512
```

The prepare phase:

1. verifies the installed `Type=notify`, `Restart=on-failure`, ten-second restart delay, three-in-five-minutes start limit, bounded timeouts, and `OOMPolicy=stop`;
2. requires healthy Suricata readiness and all service-user health checks before mutation;
3. sends `SIGKILL` to only the systemd-tracked Suricata main process and requires a new ready PID plus an increased restart counter;
4. repeats bounded failures until the configured threshold is reached, then proves a new start is rejected without changing the failed service state;
5. resets the failed state, starts Suricata explicitly, and requires readiness and healthy runtime state;
6. enables and explicitly restarts `meercata-health.timer`, avoiding an already elapsed `OnBootSec` state;
7. hashes the active configuration, active rules, and installed package manifest;
8. creates one root-owned mode-0600, create-only reboot marker below `/var/lib/meercata/qualification`.

A successful prepare report has status `reboot-required`. Reboot the disposable guest normally before phase 2.

## Phase 2: verify

```text
/usr/lib/meercata/bin/meercata-recovery-vm-qualifier verify \
  --confirmation 'QUALIFY DISPOSABLE MEERCATA DEBIAN 13 RECOVERY VM' \
  --image-sha512 APPROVED_SHA512
```

The verify phase rejects the run unless the kernel boot ID changed. It then requires the same packages and policy, ready/running Suricata, an enabled and active health timer, a successful timer-triggered health oneshot in the new boot, fully healthy service-user output, and byte-identical protected files.

The final report follows `recovery-vm-qualification-v1` and contains ten checks. The exact dev16 artifact passed both phases in the approved disposable VM; its schema-valid report is retained as `qualification-evidence/recovery-vm-dev16.json`. This is `recovery-vm-qualified`, not production-qualified.

## Limitations

The gate covers bounded `SIGKILL` failures and a normal reboot in IDS mode. It does not cover OOM, kernel panic, disk failure, abrupt power loss, IPS/NFQUEUE behavior, interrupted RuleOps transactions, HA failover, retention, removal, or purge.
