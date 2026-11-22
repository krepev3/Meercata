# Meercata v2.00 Health Contract

## Interface

Health is read-only and CLI-only:

```text
meercata health
meercata health --json
meercata health --watch
meercata health --watch --json [--interval SECONDS]
```

JSON watch mode emits one complete health-v1 object per line. The formal contract is [schemas/health-v1.schema.json](schemas/health-v1.schema.json).

## Exit codes

| Code | State | Meaning |
|---:|---|---|
| 0 | healthy | All required checks are healthy. |
| 1 | degraded | Service remains operational but a required warning threshold or policy condition is present. |
| 2 | critical | A required service, capture, packet, hook, queue, or resource condition is unsafe or unavailable. |
| 3 | unknown | Required evidence cannot be obtained or configuration is missing/invalid, unless another required check is already critical. |
| 130 | interrupted | The operator stopped watch mode with `Ctrl+C`. |

Critical takes precedence over unknown, unknown over degraded, and degraded over healthy. An optional unknown check does not change the overall state.

## Configuration

The controller reads `/etc/meercata/meercata.toml`. It rejects unknown keys, unsupported schema versions, invalid types, non-finite thresholds, unsafe interfaces/queues, symlinked configuration files, and EVE/socket paths outside their fixed Suricata roots.

Use [config/meercata.example.toml](config/meercata.example.toml) as the development template. The live VM gate qualified a root-owned, non-secret configuration on a root-owned `0755` `/etc/meercata` directory with a `0644` regular file, allowing both the dedicated service identity and approved operators to read it. Credentials or other secrets must not be placed in this file; a separate narrower boundary is required if a future feature needs them.

## Required checks

All modes collect:

- `configuration`: schema, mode, interface, queue, paths, and thresholds;
- `service`: systemd active/substate and `Type=notify` readiness policy;
- `process`: exact Suricata process discovery and duplicate detection;
- `interface`: configured Linux interface and operating state;
- `suricata_socket`: bounded Suricata 8 handshake and read-only command availability;
- `capture_mode`: AF_PACKET for IDS or NFQ for IPS;
- `capture_interface`: interface reported by Suricata;
- `eve_freshness`: readable regular EVE file and age thresholds;
- `packet_progress`: cumulative decoder/interface packet counter and watch-mode stall detection;
- `packet_loss`: interface or kernel capture drop rate;
- `stream_gaps`: TCP reassembly-gap rate;
- `suricata_memcap`: TCP memcap drops and flow emergency mode;
- `disk`: free capacity on the EVE filesystem;
- `memory`: host available-memory pressure;
- `process_resources`: Suricata RSS and watch-sampled CPU pressure.

IPS additionally collects:

- `nftables_hooks`: fixed `inet meercata` table, configured queue/interface, counters, and mandatory fail-open bypass flag;
- `nfqueue_listener`: configured kernel queue listener and kernel/userspace queue-drop counters.

## Read-only data boundary

Health uses fixed read-only sources:

- `systemctl show suricata.service`;
- the configured Suricata Unix command socket;
- `nft -j list table inet meercata` in IPS mode;
- `/proc`, `/sys`, EVE file metadata, and filesystem capacity.

It sends only these allowlisted Suricata commands: `command-list`, `version`, `uptime`, `running-mode`, `capture-mode`, `iface-list`, `iface-stat`, and `dump-counters`. Shutdown, reload, memcap mutation, and every other socket command are denied by the health client.

In the production path, the unprivileged CLI does not connect directly to the Suricata socket. It invokes the exact no-argument `health.socket-snapshot` helper command. The root helper reads the fixed root-owned configuration, performs the allowlisted requests, validates and bounds the result to 512 KiB, and returns only the typed snapshot. The helper accepts no socket path, interface, or command from the caller. Isolated tests retain direct injected socket clients.

The dedicated `meercata` health service identity receives sudo authorization only for this read-only snapshot. It is not a member of `meercata-operators` and cannot run RuleOps helper operations.

The health service retains only `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, `CAP_AUDIT_WRITE`, and `CAP_NET_ADMIN` in its capability bounding set. These allow the setuid `sudo` transition, fixed root-owned reads, and the read-only nftables netlink query; sudoers still permits only the exact no-argument snapshot command. Live dev21 qualification proved the service-user CLI returns all 17 IPS checks healthy through this boundary.

The installed access policy must grant the Meercata health identity only the reads required for its configured mode. An unavailable protected source is reported as unknown; the CLI never silently reports healthy and never falls back to unrestricted command execution.

## Sampling semantics

A one-shot command establishes a packet and CPU baseline. Packet-stall and process-CPU rate checks become fully comparative when the same collector remains active in watch mode. A zero packet counter after the configured Suricata uptime threshold is critical even on the first sample.

Counters such as packet drops, TCP gaps, and memcap events are cumulative. A nonzero historical condition remains visible until Suricata restarts; production alerting should additionally evaluate watch-mode deltas and deployment baselines.

For scheduled operation and alert deduplication, use the durable monitor layer
described in [MONITORING.md](MONITORING.md). Direct `health` remains the
read-only diagnostic primitive and `health --watch` remains the in-process
comparative sampling interface.
