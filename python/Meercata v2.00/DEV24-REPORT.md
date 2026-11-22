# Meercata v2.00 — dev24 completion report

Date: 2026-10-09. Package version: `2.0.0.dev24`.

## Delivered

Dev24 completes the local HTTPS delivery and delivery-health milestone. It adds
real TLS qualification for trusted CA delivery, hostname refusal, retired/current
tokens, duplicate processing suppression, persistent retry across a worker restart,
collector recovery, and CA rotation. Four additional checks prove delivery-health
transitions for healthy pending work, retries, excessive age, and dead letters.
The qualifier uses disposable loopback listeners and removes temporary credentials,
certificates, and state even when delivery fails.

The independent `monitor delivery-health` watchdog reports queue depth, oldest
pending age, retry pressure, failed deliveries, and the latest receipt. Its
one-minute timer requires no token or network access. Invalid timestamps and
corrupt dead letters fail visibly. An optional private CA bundle is restricted
to the credential directory; strict TLS verification remains enabled.

The package includes the new launcher, evidence schema, watchdog units, safe
removal ordering, updated CLI manual and operating contracts. Local monitoring
qualifiers now identify the executing version while preserving historical evidence.

## Verification

| Check | Result |
|---|---|
| Complete v2 regression suite | 444 passed, no failures or skips |
| Frozen v1 reference suite | 44 passed |
| Real loopback HTTPS and delivery-health gate | 12/12 passed |
| Installed TLS qualifier launcher on Debian 13 | 12/12 passed |
| Durable local monitoring regression gate | 7/7 passed |
| Durable outbox/delivery regression gate | 8/8 passed |
| Staged filesystem image qualification | 6/6 passed |
| Root-owned disposable Debian 13 installation | 9/9 passed |
| systemd unit syntax / runtime directories | 15 units / 12 directories validated |
| Native Debian package reproducibility | Two builds produced identical bytes |

Regression commands:

```text
python -m pytest -q
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider --basetemp=/tmp/meercata-v1-dev24-tests
```

The second command was run from the frozen v1 directory. Socket and systemd
validation needed execution outside the restricted sandbox. No host Suricata,
firewall, service, or active configuration was changed. Package installation was
confined to automatically removed containers with networking disabled and the
project mounted read-only.

Package: `meercata_2.0.0~dev24-1_all.deb` (157 payload files).

SHA-256: `e826b9dbb5c6114a7d0d5a5ad430f60605b124cc5582b10df99ac44b240027ca`.

Evidence:

- [Validation summary and tool versions](qualification-evidence/dev24-validation-summary.json)
- [TLS and delivery-health gate](qualification-evidence/monitor-tls-dev24.json)
- [Installed Debian 13 TLS gate](qualification-evidence/monitor-tls-debian13-dev24.json)
- [Debian 13 installation](qualification-evidence/debian13-container-dev24.json)
- [Staged image](qualification-evidence/staged-dev24.json)
- [Native package build](qualification-evidence/deb-build-dev24.json)
- [Monitoring regression](qualification-evidence/monitoring-dev24.json)
- [Outbox/delivery regression](qualification-evidence/monitor-delivery-dev24.json)

## Overall readiness

**Approximately 80% of the engineering work toward an initial production release
is complete.** This is a planning estimate based on completed controller,
RuleOps, health, fail-open IPS, packaging, and local delivery milestones. The
roadmap does not define weighted percentage scoring, so the estimate is not a
measured release acceptance result or a calendar forecast. Unfinished environment
and operational work can still expose changes that affect the remaining effort.

Meercata v2 is suitable for controlled lab qualification now. Production use
remains gated; public IPS activation and live rule promotion are still disabled.

| Remaining area | Required evidence before production use |
|---|---|
| Installed monitoring operations | Run producer, freshness, delivery, watchdog, credential/CA rotation and logrotate under real systemd PID 1; verify service-user access, restart and reboot behavior. |
| Deployment collector | Confirm real endpoint identity, token lifecycle, certificates, deduplication, outages, DNS/proxy behavior and operator notification. |
| Deployment traffic and hardware | Benchmark the actual rules and protocols, NFQUEUE capacity and latency, packet loss, multi-queue/NIC behavior and application impact. |
| Endurance and failure recovery | Complete 24–72-hour soak, disk exhaustion/retention, operational recovery rehearsal and deployment-specific regression traffic. |
| Release and rollout | Qualify signing-key custody/rotation, release builder and repository delivery; complete operator runbooks and approval of the remaining public command gates. |

The next bounded development milestone should qualify installed monitoring and
retention under real systemd in a disposable Debian 13 VM. Deployment testing
then begins with passive IDS, followed by a controlled fail-open IPS pilot.
Fail-closed IPS needs a separately approved HA or bypass design.
