# Bounded NFQUEUE load and overload qualification

## Scope

Dev20 extends the dev19 routed functional gate with bounded concurrent load, Suricata/kernel/resource evidence, abrupt listener loss during traffic, controlled queue saturation, and the existing privileged emergency-bypass operation.

It remains a CLI-only Python qualification harness. Python creates the test topology and evaluates bounded evidence; Suricata and the Linux kernel process packets. The run uses only synthetic local HTTP traffic inside a disposable Debian 13 container. It is not a production traffic replay, line-rate benchmark, or 24–72 hour soak.

## Safety boundary

`meercata.nfqueue_load_qualifier` inherits the dev19 root, Debian 13, Docker, systemd-absent, loopback-only, route-empty, approved-image-digest, capability, and pre-existing kernel-NFQUEUE guards. It adds mandatory cgroup limits:

- 512 MiB–2 GiB memory;
- 128–1024 PIDs;
- 1–4 CPU cores.

The qualified profile used a read-only container root/source mount, temporary `/tmp` and `/run`, no external network, no-new-privileges, 1 GiB memory/swap, two CPUs, and 512 PIDs. Child namespaces, addresses, routes, nftables state, server processes, load generators, and Suricata instances are removed before the container exits.

Example invocation after provisioning the disposable image:

```text
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=768m \
  --tmpfs /run:rw,nosuid,nodev,size=16m \
  --sysctl net.ipv4.ip_forward=1 \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --security-opt no-new-privileges \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --memory 1g --memory-swap 1g --cpus 2 --pids-limit 512 \
  --mount type=bind,src=/absolute/path/to/meercata,dst=/src,readonly \
  --workdir /src --env PYTHONPATH=/src \
  DISPOSABLE_IMAGE \
  python3 -m meercata.nfqueue_load_qualifier \
    --confirm I_UNDERSTAND_THIS_RUNS_BOUNDED_NFQUEUE_LOAD_IN_DISPOSABLE_NAMESPACES \
    --image-digest sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
```

## Fixed profile and acceptance oracles

The normal six-second profile uses eight accepted-transfer workers, four blocked-flow workers, a deterministic 1 MiB payload, queue 42, and 256 Suricata pending packets. It fails unless all accepted payloads match SHA-256, all intended drops remain blocked, no accepted flow fails, no corruption occurs, nftables counters advance, and both kernel and userspace NFQUEUE transport-drop deltas remain zero.

The resource/statistics gate records CPU, RSS, thread count, queue occupancy, Suricata IPS accept/block counters, NFQ errors, memcap pressure, flow emergency, TCP reassembly gaps, TCP session/segment memcap drops, and alert-queue overflow. Normal load permits no NFQ error, emergency entry, reassembly gap, memcap drop, or alert overflow. RSS has a fixed 768 MiB ceiling inside the 1 GiB container.

The listener-loss phase starts eight accepted-transfer workers for six seconds, then injects `SIGKILL` into only the directly spawned Suricata process group. At least 90% of complete attempts must succeed, no payload may be corrupt, the kernel listener must disappear, and the formerly blocked port must deliver the complete payload through nftables `bypass`.

The overload phase restarts Suricata with 16 pending packets, pauses it using `SIGSTOP` while its NFQUEUE listener remains attached, and launches 128 bounded connections with 64 workers. This intentionally demonstrates that listener-present queue saturation is different from listener absence: nftables `bypass` alone does not guarantee lossless overload. The gate requires a positive kernel/userspace queue-drop delta, invokes the transaction-bound `queue-overload` emergency bypass, requires removal of only the owned Meercata table, resumes Suricata for cleanup, and verifies full payload delivery.

## Recorded result

The decisive run passed all ten checks:

- 227 accepted payloads and 68 intended blocked flows;
- zero accepted failures, corruption, unexpected accepts, normal kernel queue drops, or normal userspace queue drops;
- measured 303.951 Mbit/s synthetic goodput, 206.656 ms median and 310.134 ms p95 transfer latency;
- 66.7 MiB peak Suricata RSS and 117.8% of one CPU core under a two-core cgroup limit;
- no Suricata NFQ error, flow emergency, TCP gap/memcap drop, or alert overflow;
- 1370/1370 successful complete transfers across abrupt listener loss;
- controlled overload produced three kernel queue drops, triggered emergency bypass, and restored the full 1 MiB payload.

The strict report is retained as `qualification-evidence/nfqueue-load-dev20.json` and validates against `nfqueue-load-qualification-v1.schema.json`.

## Interpretation and remaining gate

`nfqueue-load-qualified` means the fixed synthetic profile passed on this container/kernel/CPU combination. It must not be translated into production link capacity or an SLO. Real capacity requires deployment-specific protocol/rule/packet-size mixes, NIC queues/offloads, multiple NFQUEUEs, explicit packet-loss and latency budgets, and a 24–72 hour soak.

Dev20 invokes emergency bypass directly after detecting overload; it does not yet enable an automatic production response or public IPS CLI. Installed systemd IPS lifecycle, restart/reboot behavior, monitoring-driven overload response, and operator UAT remain gated.
