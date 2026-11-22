# Durable health-transition monitoring

Meercata v2.00 monitoring is CLI-only. Dev22 added durable local transitions;
Dev23 adds scheduled-run freshness and an opt-in, crash-safe HTTPS delivery
outbox. No GUI, generic executable hook, caller-selected URL, or token argument
is exposed.

## CLI

```text
meercata monitor run [--json]
meercata monitor status [--json]
meercata monitor events [--json] [--limit 1..100]
meercata monitor freshness [--json]
meercata monitor deliver [--json]
meercata monitor delivery-status [--json]
meercata monitor dead-letters [--json] [--limit 1..100]
```

`monitor run` performs the ordinary read-only health collection, fingerprints
the mode plus every check identity/severity, and updates durable state. It emits
a transition only for the first baseline, a severity change, a changed set of
conditions at the same severity, or recovery. Identical observations increment
the consecutive count without appending another alert.

The command preserves the health exit contract: 0 healthy, 1 degraded, 2
critical, and 3 unknown. Its JSON is `monitor-v1`; it includes the complete
health-v1 observation, the current durable state, sequence, and the transition
when one was emitted. Human status/events output remains bounded and contains
no raw EVE payload or packet content.

## Durability and deduplication

State is stored at `/var/lib/meercata/monitor/state.json`; transitions are
append-only JSONL at `/var/log/meercata/monitor/transitions.jsonl`. Both files
are mode 0600 below mode-0700 directories owned by the dedicated `meercata`
identity. A separate non-blocking lock below `/run/meercata/monitor` rejects
concurrent writers.

The three operator-owned parent roots retain their existing modes. Tmpfiles
adds only a named execute/traversal ACL for `meercata`; it does not grant that
identity directory listing, operator-group membership, or access to sibling
transaction/audit content.

A transition is appended and synchronized before the state snapshot is
atomically replaced and its directory synchronized. If execution stops between
those operations, the next run derives the newer sequence from the durable
event and repairs state without duplicating the alert. Unknown schemas,
symlinks, non-regular files, invalid hashes/statuses, oversized state, more than
10,000 active-log events, or an active log above 8 MiB fail closed.

Every transition is also SHA-256-bound into a deterministic delivery envelope
below `/var/lib/meercata/monitor/outbox`. The last durable transition must be
present in the outbox before a newer transition may be appended. Backpressure
therefore fails closed without silently skipping an intermediate event.

The full health report is SHA-256-bound in state and events. The transition
itself includes only bounded affected-check summaries and remediation text;
metrics remain in the contemporaneous monitor output rather than the durable
transition journal.

## systemd and retention

`meercata-monitor.timer` is the supported scheduler. It runs the hardened
`meercata-monitor.service` once per minute and conflicts with the older raw
`meercata-health.timer`, preventing duplicate scheduled collection. Package
installation does not enable either timer.

The service runs as `meercata`, retains only the capabilities already required
by the fixed no-argument health helper, and can write only its three monitor
directories under the otherwise read-only systemd filesystem sandbox. Each
JSON result is available in the systemd journal for collection. A non-healthy
health result remains a nonzero unit result so existing systemd failure
monitoring cannot silently treat an unsafe condition as success.

Enabling the monitor timer also enables the independent
`meercata-monitor-freshness.timer`. Its fixed three-minute threshold reports
`fresh` with exit 0, `stale` with exit 2, and unknown/uninitialized state with
exit 3. This catches a stopped or persistently failing monitor timer while the
host systemd manager is still able to execute the watchdog.

The packaged logrotate policy rotates both transition and delivery-receipt
logs at 4 MiB or weekly, keeps 12 compressed
generations, and creates a new mode-0600 file as `meercata:meercata`. The
application refuses to grow the active file past 8 MiB, making failed rotation
visible rather than consuming unbounded disk.

## Durable HTTPS delivery

Delivery is at-least-once. `monitor deliver` processes no more than the
configured batch, sends a fixed JSON POST over certificate-verified HTTPS, and
adds the deterministic event ID as `Idempotency-Key`. Redirects are not
followed. HTTP 408, 425, 429, 5xx, TLS, timeout, and network failures receive
bounded exponential retry; other non-2xx results and exhaustion of the attempt
limit move the envelope to the bounded dead-letter directory.

A synchronized receipt is appended before a delivered envelope is removed or
a rejected envelope is moved. On restart, the receipt is reconciled first, so
an interruption in that window does not repeat the send. The collector must
still honor the idempotency key because no distributed system can atomically
commit both the remote acceptance and the local receipt.

The outbox and dead-letter directory each allow at most 1,000 mode-0600
envelopes; the active receipt log allows 10,000 records or 8 MiB. Queries are
limited to 100 items. Unknown entries, symlinks, malformed identities, hashes,
receipts, or oversized files fail closed.

## Configuration and activation

The HTTPS endpoint comes only from the root-controlled `[monitor_delivery]`
table in `/etc/meercata/meercata.toml`. Only HTTPS URLs without embedded
credentials, query strings, or fragments are accepted. The bearer token comes
only from a non-symlink regular file below `/etc/meercata/credentials`; it must
be root-owned in production, group-readable only as required by the `meercata`
service, non-executable, and never appears in argv, TOML, events, receipts, or
error output.

Package installation creates the credential directory but installs neither a
token nor active configuration, and enables no timer. After endpoint approval,
certificate/collector preparation, and secret provisioning, activation is
explicit:

```text
systemctl enable --now meercata-monitor.timer
systemctl enable --now meercata-monitor-delivery.timer
```

The optional `ca_file` must be an absolute path below `/etc/meercata/credentials`.
Its PEM bundle must be a bounded regular file, root-owned in production, not a
symlink, non-executable, and not writable by group or others. Omitting it uses
the operating-system trust store. TLS hostname verification always remains on.
The worker reloads configuration, token, and CA on each invocation, so an
administrator can provision replacements atomically between delivery runs.
Collectors must reject retired tokens and preserve event-ID deduplication
across restarts and credential rotation.

Enabling the delivery timer also enables
`meercata-monitor-delivery-health.timer`. This independent one-minute watchdog
runs `meercata monitor delivery-health --json` without credentials or network
access. It reads bounded durable state and uses only the runtime lock directory
for writes. Its health contract is:

| Condition | Status / exit code |
|---|---|
| No retry, backlog, age, or failed-delivery pressure | healthy / 0 |
| Any retry; at least 100 pending; or oldest pending older than 300 seconds | degraded / 1 |
| Any dead letter; at least 500 pending; or oldest pending older than 1,800 seconds | critical / 2 |
| Unparseable/timezone-less timestamp or an event more than 30 seconds in the future | unknown / 3 |

Critical conditions take precedence over degraded conditions; invalid times
produce unknown. Corrupt or unsafe state fails with exit 3. Equality at an age
threshold stays in the lower severity. A recovered, empty outbox returns healthy;
dead letters remain critical until handled through an approved operator process.
The output includes pending/due/retry counts, oldest age, and the last receipt.
A monitoring collector must ingest the service's journal/nonzero result to
notify an operator; the watchdog cannot notify through an unavailable collector.
A powered-off host needs external availability monitoring.

The delivery worker is a separate hardened oneshot. It has an empty capability
bounding set, `NoNewPrivileges`, no sudo requirement, a read-only system image,
network access limited to Unix/IPv4/IPv6 address families, and write access
only to the three monitor roots. Package removal stops delivery and freshness
before the producer and health authorization are removed.

## Qualification boundary

Dev23 deterministically qualifies enqueue, duplicate suppression, deferred
retry, accepted delivery, permanent rejection, dead-lettering, receipt-first
crash repair, stale scheduling, and unsafe endpoint refusal with an injected
transport. It does not claim a real collector, production credential,
certificate rotation, proxy, collector availability, or long-duration soak;
those remain deployment gates.

## Dev24 loopback TLS and delivery-health qualification

Run `python3 -m meercata.monitor_tls_qualifier` on a disposable test host with
Python and `/usr/bin/openssl`. The installed launcher is
`/usr/lib/meercata/bin/meercata-monitor-tls-qualifier`. The harness binds only
127.0.0.1 on an ephemeral port; temporary certificates, tokens, and state are
removed on success or failure. It never changes host services or firewall rules.

All twelve checks passed. The report is retained in
`qualification-evidence/monitor-tls-dev24.json` and validated against
`monitor-tls-qualification-v1`. It proves strict certificate/hostname verification,
token retirement/acceptance, duplicate suppression, outage retry persistence
across a new worker, recovery, trust rotation, and delivery-health transitions.
It uses the ordinary file configuration and credential loader for queued delivery.

These are real HTTPS connections to a disposable local collector. They do not
qualify a production collector, production secrets, external DNS, proxies,
clustered deduplication, remote availability, or installed watchdog execution
under systemd PID 1. Those and the 24–72-hour retention/soak gate remain open.
