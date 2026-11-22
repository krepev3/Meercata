# Meercata transactional nftables helper

## Scope

Dev18 binds the dev17 fail-open policy compiler to the durable controller transaction engine and restricted root helper. It does not expose public `meercata ips` activation.

The helper adds these fixed operations:

```text
meercata-helper nftables.snapshot TRANSACTION_UUID
meercata-helper nftables.apply TRANSACTION_UUID
meercata-helper nftables.verify TRANSACTION_UUID
meercata-helper nftables.rollback TRANSACTION_UUID
meercata-helper emergency.bypass REASON INCIDENT_ID
```

The four ordinary operations accept only a canonical UUID. The emergency operation accepts one of `listener-loss`, `queue-overload`, or `recovery-failed` plus an anchored `INC-...` reference. No operation accepts a table, chain, executable, path, or nft command from the caller.

## Transaction invariants

`nftables.snapshot` requires the controller lock, `ips.activate`, exact `LOCKED` state, and configuration intent matching the transaction. It seals the deterministic policy and records either absence or a previously receipted Meercata table in root-private mode-0600 state.

`nftables.apply` requires `VALIDATED`. It refuses if active state changed after snapshot, writes a durable `prepared` receipt, runs native `nft -c -f`, applies one atomic `nft -f` batch, verifies the complete resulting table, and finalizes the receipt as `applied`.

`nftables.verify` requires `APPLIED` and proves the live semantic fingerprint still matches both candidate and receipt.

`nftables.rollback` requires `ROLLING_BACK`. It restores only when live state equals this transaction's candidate. A previous table is reconstructed from its receipted transaction identity/interface/queue; originally absent state removes only `inet meercata`. Already-restored state is idempotent. Any third state is refused and classified `RECOVERY_FAILED` by the transaction engine.

## Emergency bypass

Emergency bypass deliberately does not require the normal controller lock or readable active IPS configuration. It still removes only a complete table accepted by the dev17 ownership inspector. A root-private prepared intent is durable before removal, retry is idempotent, and privileged audit is best-effort so a broken audit sink cannot block connectivity recovery.

## Qualification

The dev18 Debian 13 container gate ran with `--network none`, read-only source/root filesystems, and only `CAP_NET_ADMIN`. It committed the first live transaction, forced failure after the second live apply, restored the first receipted policy, verified five mode-0600 receipts and both audit streams, executed emergency bypass, and preserved an unrelated operator table byte-semantically.

The seven-check report is retained as `qualification-evidence/nftables-transaction-dev18.json`. This qualifies the transaction/helper ownership boundary only. Suricata NFQUEUE packet verdicts, listener loss, capacity, latency, systemd lifecycle, crash/reboot recovery, and public CLI activation remain pending.
