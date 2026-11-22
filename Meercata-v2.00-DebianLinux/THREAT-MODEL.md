# Meercata v2.00 Threat Model

## Scope

Meercata is a local, CLI-only Suricata control plane. It does not provide a GUI, web server, remote API, or packet-processing implementation. Suricata and the Linux kernel remain the data plane.

The initial model covers local CLI invocation, configuration and rule staging, the privileged-operation boundary, nftables/NFQUEUE ownership, Suricata control, transaction recovery, controller audit, and local evidence references.

## Protected assets

- host availability and network connectivity;
- integrity of Meercata-owned nftables objects;
- active Suricata configuration and rules;
- last-known-good snapshots and recovery state;
- controller authorization policy;
- audit completeness and integrity;
- confidentiality of secrets and packet-derived evidence;
- availability of disk, CPU, memory, and NFQUEUE capacity.

## Trust boundaries

```text
Unprivileged operator CLI
          |
          | typed request; local authorization
          v
Meercata control plane and durable state
          |
          | allowlisted operation; canonical path; fixed argv
          v
Restricted privileged helper
          |
          +--> systemd / Suricata Unix socket
          +--> Meercata-owned nftables table
          +--> staged and active config/rule paths

Suricata EVE evidence --> separate evidence boundary
```

Anything received from CLI arguments, configuration, environment, staged files, rule sources, Unix-socket responses, command output, filesystem state, or recovery state is untrusted until validated.

## Threat actors

- an unprivileged local user attempting unauthorized mutation;
- an authorized operator making an unsafe or mistaken request;
- a compromised rule source or malformed ruleset;
- a compromised unprivileged Meercata process attempting privilege escalation;
- another local process racing or tampering with files, locks, sockets, or state;
- accidental process termination, host reboot, partial write, disk exhaustion, or service failure.

## Threats and required controls

| Threat | Required control | Verification gate |
|---|---|---|
| Shell or argument injection | `shell=False`, absolute executables, fixed argv definitions, allowlisted environment, typed inputs | Unit tests with metacharacters and unknown operations |
| Path traversal or symlink replacement | Canonical allowlisted roots, no-follow opens, atomic replacement, ownership and mode checks | Unit and integration race/path tests |
| Concurrent mutation | One non-blocking controller lock and durable transaction ownership | Multiprocess lock test |
| Partial or corrupted state | Schema validation, checksums, atomic write, file and directory `fsync` | Failure injection at each transition |
| Unauthorized privileged action | Fixed helper operations, sudoers allowlist, deny unknown operations and paths | Privilege-boundary integration tests |
| Candidate changes between approval and activation | Root-private sealed copy, independent validation/PCAP replay, activation from sealed bytes | Seal/tamper and stale-pack tests |
| Rollback overwrites an administrator change | Compare active hash with transaction candidate/snapshot and refuse unknown state | External-change rollback tests |
| Firewall damage outside Meercata | Dedicated named nftables table and ownership metadata; never flush the ruleset | Namespace tests with unrelated rules |
| Suricata accepts a bad deployment | Stage, strict validation, apply, readiness and packet-health verification | Invalid-config/rule and PCAP tests |
| Malicious or reduced ruleset | Allowlisted source, hashes, rule-count policy, regression pack, manual initial promotion | RuleOps tests and audited approval |
| Audit suppression or secret leakage | Mutation fails closed on audit failure; explicit redaction; separate evidence logs | Permission, disk-full, and redaction tests |
| Crash or reboot during mutation | Durable state before the next transition, last-known-good pointer, bounded recovery | SIGKILL and reboot tests at every state |
| NFQUEUE listener loss or overload | Initial fail-open policy, queue bypass, counter/latency monitoring, emergency bypass | Load and listener-loss tests |
| Resource exhaustion | Bounded command time/output, disk thresholds, retention policy, CPU/RSS/drop monitoring | Timeout, output, disk-full, load, and soak tests |
| Evidence privacy breach | No payloads in audit, local retention default, restricted access, remote export disabled | Audit inspection and retention tests |

## Safety invariants

1. No unvalidated request reaches a privileged operation.
2. No controller input is evaluated by a shell.
3. A transaction state is durable before the next side effect starts.
4. Only one mutation transaction may be active.
5. Meercata automatically modifies or restores only state it can prove it owns.
6. Validation success alone is not deployment success; verification must pass.
7. Audit failure blocks ordinary mutation.
8. The active and last-known-good artefacts are protected from retention cleanup.
9. Missing health evidence is unknown or critical according to policy, never healthy.
10. Initial inline operation is fail-open; fail-closed requires a separately approved HA or bypass design.

## Residual risks and deferred scope

- A fully compromised root account can bypass Meercata controls.
- Kernel, Suricata, nftables, systemd, and distribution supply-chain defects are mitigated through supported-version policy and updates, not eliminated by Meercata.
- Remote multi-host orchestration, GUI/web access, and a network-listening API are outside the initial scope.
- Fail-closed operation remains prohibited until its external availability design and tests are approved.

This model must be reviewed whenever the privilege boundary, supported topology, external integrations, evidence handling, or fail policy changes.
