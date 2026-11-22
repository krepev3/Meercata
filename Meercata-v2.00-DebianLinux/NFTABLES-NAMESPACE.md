# Meercata fail-open nftables namespace qualification

## Scope

Dev17 introduces the first Phase 5 IPS component without enabling public IPS mutation. Python compiles one deterministic nftables policy for the approved initial topology:

- family/table: `inet meercata`;
- one `forward` base chain at filter priority 10 with accept policy;
- one inbound and one outbound interface match;
- one configured NFQUEUE number;
- counters and the NFQUEUE `bypass` flag on both rules;
- table, chain, and rule ownership comments bound to a canonical transaction UUID.

The interface and queue come from `[health]`; `[ips]` permits only `fail_policy = "open"` and `traffic_scope = "gateway-forward"`. Fail-closed and host input/output policies are rejected during configuration validation.

## Safety boundary

The compiler never emits `flush ruleset`, iptables commands, a caller-selected family/table/chain, or shell text. Initial creation and replacement are native nft batch scripts intended for `nft -f`, so the kernel applies each complete batch atomically. Replacement may delete and recreate only `inet meercata` in the same batch.

Observed state is accepted as owned only when the complete table matches the contract. Handles and live counter values are excluded from the semantic fingerprint; missing ownership, another object, an unexpected rule, wrong priority/interface/queue, or absent bypass fails closed.

## Reproduce the isolated gate

Provision an image from the pinned Debian 13 slim digest with Python 3 and nftables, then run the source read-only in a container with `--network none`, all capabilities dropped except `NET_ADMIN`, a read-only root filesystem, and a temporary `/tmp`:

```text
python3 -m meercata.nftables_namespace_qualifier \
  --confirm I_UNDERSTAND_THIS_MUTATES_ONLY_A_DISPOSABLE_CONTAINER_NETNS \
  --image-digest sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
```

The qualifier refuses a non-root process, non-Docker environment, connected namespace, running systemd manager, wrong OS/image identity, or missing fixed `/usr/sbin/nft` executable.

## Result and limitations

The recorded Debian 13 run passed native syntax validation, initial apply, atomic replacement, rejection of an unowned table, rejection of injected drift, and removal of only the Meercata table. A separate `inet operator_guard` table retained the same semantic SHA-256 throughout. The schema-valid report is `qualification-evidence/nftables-namespace-dev17.json`.

This gate does not start Suricata or an NFQUEUE listener. Listener-loss packet flow, verdict correctness, overload, latency, transactional privileged-helper recovery, service lifecycle, and reboot behavior remain mandatory later gates. Public `meercata ips` activation remains disabled.
