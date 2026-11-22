# Meercata privileged RuleOps helper

## Current status

The Python helper boundary is implemented and tested against isolated filesystem roots. It is not installed or enabled on the development host. Public `meercata rules promote` therefore remains disabled.

The helper exposes exactly ten operations:

```text
meercata-helper rules.snapshot TRANSACTION_UUID
meercata-helper rules.activate TRANSACTION_UUID
meercata-helper rules.rollback TRANSACTION_UUID
meercata-helper rules.reload TRANSACTION_UUID
meercata-helper health.socket-snapshot
meercata-helper nftables.snapshot TRANSACTION_UUID
meercata-helper nftables.apply TRANSACTION_UUID
meercata-helper nftables.verify TRANSACTION_UUID
meercata-helper nftables.rollback TRANSACTION_UUID
meercata-helper emergency.bypass REASON INCIDENT_ID
```

It accepts no candidate path, rules destination, executable, shell text, configuration path, service name, socket path, PCAP path, nftables family/table/chain, or nft command. RuleOps and nftables operands are canonical transaction UUIDs. Emergency bypass accepts only three fixed reasons and an anchored incident reference.

## Authorization checks

Every operation verifies:

- the transaction identifier is a canonical UUID;
- the controller lock file names that transaction and is actively locked by another process;
- the transaction operation is `rules.promote`;
- the transaction is in the exact state authorized for the operation;
- candidate validation and regression evidence refer to the candidate hash;
- the approved root-managed regression pack manifest has not changed;
- production configuration, privileged state, regression packs, and activation targets meet ownership and mode policy.

The install-time sudoers rule matches only the four RuleOps names followed by one UUID. The separate health command accepts no operand. Helper authorization does not depend on a caller-controlled path or environment variable.

The nftables sudoers alias matches only four fixed operation names followed by one UUID. A separate anchored expression permits `emergency.bypass` only for `listener-loss`, `queue-overload`, or `recovery-failed` and an `INC-...` reference. These mutations are never granted to the dedicated health identity.

## Transactional nftables policy

`nftables.snapshot`, `apply`, `verify`, and `rollback` enforce the same active controller lock and exact transaction-state boundary as RuleOps. The transaction operation must be `ips.activate`, and its interface, queue, fail-open policy, and gateway-forward scope must exactly match root-managed configuration.

Snapshot seals a deterministic policy and will treat an existing table as restorable only when its full semantics match a prior root activation receipt. Apply writes a prepared intent before native syntax validation and atomic mutation. Verify binds live semantics to the applied receipt. Rollback changes state only when the current table is either the transaction candidate or already the recorded snapshot; any third state is refused.

Emergency bypass is deliberately configuration- and lock-independent so connectivity recovery still works after normal control-plane failure. It nevertheless removes only a complete dev17-owned table, persists intent before removal, supports interrupted retry, and records a root-private receipt. See [NFTABLES-TRANSACTIONS.md](NFTABLES-TRANSACTIONS.md).

## Snapshot and sealing

`rules.snapshot` runs while the transaction is `LOCKED`. It:

1. creates transaction state below `/var/lib/meercata/privileged/transactions/TRANSACTION_UUID/rules`;
2. copies the approved candidate into a mode-0600 sealed file while hashing it;
3. reruns strict Suricata validation against the sealed file;
4. independently replays the approved PCAP pack against the sealed file;
5. snapshots the active rules if they exist;
6. persists hashes and bounded qualification results with file and directory `fsync`;
7. writes required root-side audit events.

Changing the unprivileged candidate after this point cannot change the bytes later activated.

## Activation

`rules.activate` is accepted only while the transaction is `VALIDATED`. It:

1. verifies sealed and snapshot hashes;
2. reruns strict Suricata validation;
3. verifies active rules still match the snapshot, detecting unrelated administrator changes;
4. durably writes a `prepared` activation intent;
5. copies the sealed rules into a temporary file in the active directory;
6. calls `fsync`, atomically replaces the active file, and syncs the directory;
7. records the applied hash and root-side audit outcome.

Writing the intent before replacement lets recovery determine whether a crash happened before or after the atomic activation.

## Rollback

`rules.rollback` is accepted only while the transaction is `ROLLING_BACK`. It restores the snapshot only when the current active hash is the candidate hash written by this transaction. If no active rules existed originally, it removes the activated file only when that same ownership proof succeeds.

If active rules contain any unrelated hash, rollback refuses to overwrite or remove them and leaves the transaction for explicit recovery. Rollback audit is best-effort so loss of the normal audit sink cannot prevent restoration; a durable rollback receipt remains in privileged state.

## Socket mediation

`rules.reload` is accepted only for an `APPLIED` or `ROLLING_BACK` transaction. Before connecting, the helper verifies the active rules hash against the activation or rollback receipt. It then invokes only non-blocking reload, reload-time, rule-statistics, and failed-rule commands. A successful result is stored separately for applied and rollback phases, making retries idempotent. Applied reload audit is required; rollback reload audit remains best-effort so recovery is not blocked.

`health.socket-snapshot` accepts no argument. It invokes only the eight existing read-only Suricata commands, lists only the fixed owned `inet meercata` table, and reads only `/proc/net/netfilter/nfnetlink_queue`. It returns one typed and bounded snapshot containing the socket results, nftables JSON, and kernel queue text. Operators and the dedicated health user receive neither direct socket/nftables access nor a caller-selected command, path, table, or unit field.

The health systemd sandbox retains `CAP_NET_ADMIN` only because the fixed helper's read-only nftables netlink query requires it. The sudoers entry still authorizes exactly the no-argument snapshot; no ruleset, mutation operation, or operator-only helper command is available to the health identity.

The Dev22 monitor service runs under that same dedicated identity and invokes
the identical snapshot through ordinary health collection. Monitoring adds no
privileged helper operation and receives write access only to its unprivileged
state, transition-log, and lock directories.

## Installation policy

Production packaging must:

- create `meercata-operators` deliberately and review its membership;
- install Python modules, the helper launcher, regression packs, and sudoers policy as root-owned and not group/world writable;
- install the helper at `/usr/lib/meercata/bin/meercata-helper` mode 0755;
- create `/var/lib/meercata/privileged` and descendants root-owned mode 0700;
- use sticky group-writable controller state/log parents plus a separate root-only privileged audit directory;
- keep controller and Suricata configuration root-owned and not group/world writable;
- validate sudoers with `visudo -cf` before installation;
- remove sudo authorization before removing helper code during rollback.

The supplied files in `packaging/` are reviewed templates, not an installer. The Python-only package builder can assemble and verify them below a non-root staging directory using a versioned hash manifest, but it refuses the live filesystem root. Socket mediation and supervision templates are implemented but not installed. Installed permission tests, monitoring integration, retention, native package signing, and live upgrade/removal behavior remain Phase 4 work.
