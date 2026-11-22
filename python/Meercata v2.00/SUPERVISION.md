# Meercata production supervision contract

## Safety state

The files under `packaging/systemd/` remain release-gated templates and are not applied to the development host. Dev12 installed them only inside a disposable hash-pinned Debian 13 KVM guest, where systemd was PID 1 and real Suricata 8.0.6 ran. This proves readiness and monitoring behavior for that gate; it is not authorization for production deployment.

## Suricata override

`suricata.service.d/50-meercata-production.conf` retains the distribution unit's executable and capture mode while tightening supervision:

- `Type=notify` and `NotifyAccess=main` require Suricata readiness notification before startup succeeds;
- strict configuration testing runs before every service start;
- `systemctl reload` is disabled because rule reload must carry a Meercata transaction UUID;
- failures restart after 10 seconds, with at most three attempts in five minutes;
- startup and shutdown have bounded timeouts;
- OOM policy stops the unit instead of leaving an ambiguous partial state;
- conservative filesystem, kernel, namespace, personality, realtime, task, and descriptor restrictions are applied.

The override does not replace `ExecStart`, choose IDS/IPS mode, create NFQUEUE hooks, or enable fail-closed behavior. Those lifecycle choices remain Phase 5 transactions.

The staged-image qualifier validates this override together with the health service/timer using `systemd-analyze --root` and disposable base-unit fixtures. This proves unit syntax and dependency construction only; it does not prove the distribution Suricata unit, readiness notification, or restart behavior on a running host.

The root-owned Debian 13 container layer repeats static unit verification after installing the package with real root ownership and applying sysusers/tmpfiles. The dev12 KVM layer then proved daemon reload, `Type=notify` readiness, a single supervised process, root-owned socket access, all 15 live IDS health checks, a successful sandboxed oneshot, and timer scheduling. Dev13 separately proved transaction-bound reload and rollback. Dev16 passed the remaining bounded restart-throttling and enabled-timer reboot-persistence gate, including a rejected start at the rate limit, explicit recovery, a changed boot ID, successful timer execution, and 15/15 post-reboot health. IPS remains separate.

## Health and transition timers

`meercata-health.timer` runs the CLI health report approximately once per minute under the dedicated unprivileged `meercata` system user. It is not automatically enabled by the templates.

Dev22 adds `meercata-monitor.timer` as the preferred scheduled integration. It
runs `monitor run`, persists only changed conditions/recovery, and emits the full
structured observation to journald. The monitor timer conflicts with the raw
health timer so both do not schedule duplicate collection. Installation enables
neither timer.

Dev23 couples monitor-timer enable/disable to the independent
`meercata-monitor-freshness.timer`, which fails when the latest observation is
more than three minutes old. The separately enabled
`meercata-monitor-delivery.timer` drains the durable outbox over verified HTTPS.
It does not use sudo, has an empty capability set plus `NoNewPrivileges`, and
can write only the monitor roots. Package installation still enables no timer.

The health and monitor services receive no ambient capabilities and an otherwise read-only filesystem view. `NoNewPrivileges` and `RestrictSUIDSGID` are intentionally not set because the process must invoke the exact `health.socket-snapshot` sudo helper command. Their bounding sets contain only identity/read/audit capabilities plus `CAP_NET_ADMIN` for the fixed read-only nftables query. Sudoers grants that service user no RuleOps, service, mutable firewall, shell, executable, or caller-selected socket command. The monitor service additionally receives write access only to `/var/lib/meercata/monitor`, `/var/log/meercata/monitor`, and `/run/meercata/monitor`.

A non-healthy or stale CLI exit makes the corresponding oneshot fail, which is visible in systemd and journald. A timer continues to schedule later checks. A dead-letter result fails the delivery oneshot while retaining the bounded envelope for inspection. Production deployment must still qualify its real collector, secret/certificate lifecycle, and availability.

## Installation and qualification order

1. Create system users/groups from the reviewed sysusers file.
2. Create ownership boundaries from the tmpfiles policy.
3. Install immutable Python/package assets and validate sudoers.
4. Install the Suricata override, health units, and monitor units/retention policy.
5. run `systemctl daemon-reload`;
6. run strict Suricata validation and an offline PCAP regression;
7. start Suricata and verify `ActiveState=active`, `SubState=running`, and `Type=notify`;
8. run `meercata health --json` as the service user;
9. enable the monitor timer and freshness watchdog after local journal alerting is ready;
10. provision the root-controlled endpoint/token, qualify the real collector, then explicitly enable the delivery timer;
11. test restart throttling and recovery in a disposable qualification host.

Dev16 implements step 10 through `meercata.recovery_vm_qualifier`. See [RECOVERY-VM.md](RECOVERY-VM.md) for its exact destructive-test boundary and two-phase reboot protocol.

Package removal must stop delivery, freshness, transition monitoring, and legacy health in that order, remove sudo authorization, preserve recovery/monitor state and logs, remove unit files/override, reload systemd, and restart Suricata only under an approved rollback plan.
