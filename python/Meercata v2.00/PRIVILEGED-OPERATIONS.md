# Meercata v2.00 Privileged-Operation Inventory

## Policy

The v2 CLI runs unprivileged for parsing, policy, staging, state inspection, and health reporting whenever host permissions allow it. Privileged work is isolated behind fixed operations. There is no general command execution endpoint and no caller-controlled shell text.

Phases 1–3 implement transaction, health, staging, validation, reload orchestration, and the typed activation boundary. Phase 4 includes the Python RuleOps filesystem helper, socket mediation, exact sudo clients, and supervision templates. Dev17 adds the strict fail-open nftables policy compiler; dev18 exposes only transaction/state-bound nftables operations plus a separately constrained emergency bypass and qualifies them in an isolated namespace. The CLI continues to deny live rule promotion and IPS activation until their remaining qualification gates complete.

## Inventory

| Operation ID | Purpose | Expected privilege | Input boundary | Owned targets |
|---|---|---|---|---|
| `suricata.config.validate` | Validate a staged Suricata configuration | Dedicated service identity or root only when file access requires it | Canonical staged config path under `/var/lib/meercata/transactions/` | Read-only staged artefacts |
| `suricata.service.start` | Start the production Suricata unit | Root through fixed sudoers helper | No arbitrary unit name | Approved Meercata Suricata unit |
| `suricata.service.stop` | Stop the production Suricata unit | Root through fixed sudoers helper | No arbitrary unit name | Approved Meercata Suricata unit |
| `suricata.service.restart` | Restart after an approved deployment or recovery | Root through fixed sudoers helper | No arbitrary unit name | Approved Meercata Suricata unit |
| `suricata.socket.command` | Request supported reload/status operations | Suricata control group | Enum command and bounded typed parameters | Approved Suricata Unix socket |
| `health.socket-snapshot` | Return fixed read-only Suricata, owned-table, and NFQUEUE status | Root helper through exact sudoers command | No caller parameters | Approved Suricata Unix socket, `inet meercata`, fixed kernel queue-status file |
| `rules.reload` | Reload and verify the transaction-owned active/restored rules | Root helper through exact sudoers command | Applied or rolling-back transaction UUID | Approved Suricata Unix socket and root-private receipt |
| `nftables.apply` | Atomically install Meercata NFQUEUE hooks | Root or restricted `CAP_NET_ADMIN` helper | Validated generated ruleset only | Dedicated Meercata table |
| `nftables.inspect` | Read hooks, policy, and counters | Prefer unprivileged; otherwise restricted helper | Fixed table and chain names | Dedicated Meercata table |
| `nftables.remove` | Remove Meercata-owned hooks during rollback/bypass | Root or restricted `CAP_NET_ADMIN` helper | Transaction ownership reference | Dedicated Meercata table |
| `config.activate` | Atomically activate validated configuration | Root-owned file helper | Staged hash and canonical destination ID | `/etc/meercata/` and approved Suricata config target |
| `rules.activate` | Atomically activate a validated ruleset | Root-owned file helper | Staged hash and canonical destination ID | Approved Suricata rules directory |
| `rules.snapshot` | Seal and independently qualify the candidate; snapshot active rules | Root-owned file helper | Existing `rules.promote` transaction UUID | Root-private transaction state and approved active rules file |
| `rules.rollback` | Restore or remove only the rules proven to belong to the transaction | Root-owned file helper | Existing rolling-back transaction UUID | Approved Suricata rules file and root-private receipts |
| `state.recover` | Restore last-known-good owned state | Same privileges as affected fixed operations | Existing audited transaction ID | Meercata-owned state only |
| `emergency.bypass` | Remove Meercata NFQUEUE hooks when normal recovery cannot complete | Root through dedicated explicit command | Reason and incident reference | Dedicated Meercata table |

## Mandatory helper constraints

- resolve an operation identifier through a compiled allowlist;
- reject unknown operation identifiers and extra parameters;
- use absolute executable paths and fixed argument arrays;
- use `shell=False`, a fixed working directory, and an allowlisted environment;
- enforce bounded execution time and captured output;
- canonicalize and verify every path against an operation-specific root;
- reject symlinks and unsafe ownership or mode at privileged boundaries;
- record actor, operation, redacted input, result, and transaction ID;
- never accept a caller-provided systemd unit, executable, nftables table, or destination path;
- expose no interactive shell and no generic file-copy operation.

## Explicitly prohibited operations

- arbitrary command execution;
- arbitrary systemd unit management;
- full nftables, iptables, or ip6tables flush;
- restoration of a whole-host firewall snapshot as automatic rollback;
- writes outside fixed Meercata, Suricata, audit, and service locations;
- direct editing of active config or rules before staging and validation;
- privilege escalation based only on membership in an untrusted environment variable or caller-controlled path.
