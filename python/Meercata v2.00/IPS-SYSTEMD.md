# IPS systemd lifecycle

Meercata v2.00 remains a CLI-only Python application. The installed IPS runtime
is intentionally private to systemd: the dev21 installed-system gate has passed,
but the public CLI still does not expose policy activation while deployment
capacity, soak, monitoring, and release-operation gates remain open.

## Lifecycle boundary

`meercata-ips.target` is the only unit administrators enable or start. It orders
the fixed runtime as follows:

1. `meercata-suricata-ips.service` validates the installed Suricata build and
   configuration, then starts the NFQUEUE listener.
2. `meercata-ips-activate.service` confirms the exact queue listener exists with
   zero prior drops, applies the owned `inet meercata` policy transactionally,
   and verifies its root-only activation receipt.
3. `meercata-ips-guard.service` polls the exact queue every 500 ms. Listener
   loss or any kernel/user queue drop removes only the exactly owned table and
   records an emergency receipt.

Every runtime unit is `PartOf=meercata-ips.target`. Stop ordering is the reverse:
the guard stops first, its `ExecStopPost` runs an emergency fail-open removal,
the lifecycle service performs a second idempotent policy removal, and only then
does the Suricata listener stop. A guard crash also runs the fail-open removal.

The target conflicts with the distribution `suricata.service`, preventing two
supervisors from owning the same engine. The private engine and helper units
have no `[Install]` section, so they cannot be enabled independently through the
supported interface.

## Operator procedure

Do not enable this target on a production gateway solely because the generic
installed-system gate passed. In a disposable or separately qualified host, configure
`health.mode = "ips"`, the approved gateway interface, queue number, fail-open
policy, and gateway-forward scope. Then use:

```console
sudo systemctl enable --now meercata-ips.target
systemctl status meercata-ips.target meercata-suricata-ips.service
sudo /usr/lib/meercata/bin/meercata-ips-bootstrap status
meercata health --json
```

Stop or disable only the target:

```console
sudo systemctl disable --now meercata-ips.target
```

Never start or stop the component units directly. If health reports an inactive
policy after a guard incident, inspect the root audit/receipt and Suricata logs,
correct the cause, stop the target and wait until all three component services
are inactive, then start the target again. Do not use a single `restart` job:
systemd does not generally restart a target's dependency units as one atomic
group. Package removal disables the target before removing its unit and launcher
payloads; configuration, state, receipts, and audit data remain preserved.

## Safety properties

- Policy activation occurs only after listener readiness and exact queue match.
- The nftables table must match the fixed owner comments, chain, interface,
  queue, counter, and `bypass` semantics.
- Normal shutdown, engine failure, guard failure, listener loss, and detected
  overload converge on fail-open policy removal.
- Lifecycle and emergency intent is written before mutation and can be resumed
  idempotently after interruption.
- Root-only helpers accept fixed actions and configuration; no shell, arbitrary
  command, path, table, or rule input is accepted.
- The dedicated health identity uses only the no-argument snapshot helper for
  the fixed Suricata socket, owned nftables table, and kernel NFQUEUE status.
