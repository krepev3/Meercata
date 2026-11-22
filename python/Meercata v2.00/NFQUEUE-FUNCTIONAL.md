# Live NFQUEUE functional qualification

## Scope

Dev19 adds a guarded CLI-only qualification harness for the first real Suricata NFQUEUE packet path. It creates a client namespace, a Meercata gateway namespace, and a server namespace inside one disposable Debian 13 container. The source tree is mounted read-only and the outer container starts with `--network none`.

The harness uses the dev18 transaction workflow to install the exact owned `inet meercata` policy on gateway interface `lan0`, starts Suricata 8 in NFQ mode on queue 42, and sends deterministic Python HTTP probes through this routed path:

```text
meercata-client (10.77.0.2)
        |
      lan0
        |
disposable Meercata gateway
        |
      wan0
        |
meercata-server (10.88.0.2)
```

Python remains the control/orchestration language. Suricata and the Linux kernel remain the packet-processing data plane. No GUI, web control plane, generic shell execution, or host firewall integration is introduced.

## Safety guard

The qualifier refuses to start unless all of these are true:

- the exact confirmation phrase is supplied;
- effective UID/GID are root;
- `/.dockerenv` is a regular file and the OS is Debian 13;
- systemd is not running in the container;
- loopback is the only initial interface and the IPv4 route table is empty;
- the approved Debian 13 base-image digest is supplied;
- `/usr/bin/ip`, `/usr/sbin/nft`, `/usr/bin/python3`, `/usr/bin/suricata`, and the Suricata configuration exist;
- effective `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` are present.

The outer container must explicitly set IPv4 forwarding. `CAP_SYS_ADMIN` plus unconfined seccomp/AppArmor is required only so `ip netns` can mount and enter the two child namespaces. Use a disposable `--network none` container with no writable host mount. Do not run this command on a production host or reuse the qualification container.

Example after provisioning a disposable image with Debian 13, Suricata 8.0.6, Python 3, iproute2, and nftables:

```text
docker run --rm \
  --network none \
  --sysctl net.ipv4.ip_forward=1 \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --mount type=bind,src=/absolute/path/to/meercata,dst=/src,readonly \
  --workdir /src \
  --env PYTHONPATH=/src \
  DISPOSABLE_IMAGE \
  python3 -m meercata.nfqueue_functional_qualifier \
    --confirm I_UNDERSTAND_THIS_RUNS_LIVE_NFQUEUE_IN_DISPOSABLE_NETWORK_NAMESPACES \
    --image-digest sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
```

## Required checks

A successful `nfqueue-functional-qualified` report contains exactly nine passed checks:

1. isolated Debian/container/capability guard;
2. routed client-to-server baseline;
3. Suricata NFQueue build capability and strict exclusive-rule validation;
4. committed dev18 nftables transaction with exact interface, queue, ownership, and bypass semantics;
5. kernel listener attachment to queue 42;
6. accepted 1 MiB payload with SHA-256 verification and advancing nftables counters;
7. blocked TCP flow on the private qualification SID with a blocking EVE action and advancing counters;
8. five bounded accepted transfers with min/median/max latency and aggregate throughput recorded;
9. listener removal followed by successful delivery on the formerly blocked port, proving nftables `bypass` fail-open behavior.

The bounded timing sample is functional evidence only. It is not a capacity, overload, packet-loss, resource-ceiling, or soak benchmark.

## Cleanup and failure behavior

Every spawned process is placed in its own process group and stopped with a bounded TERM/KILL sequence. Cleanup invokes the dev18 emergency bypass for the exactly owned table, deletes both child namespaces, and restores the disposable namespace's forwarding value when writable. Failures return exit code 3 and never emit a successful report.

The qualifier does not execute a module-loading command. The final guard requires `/proc/net/netfilter/nfnetlink_queue` to exist before topology creation, because opening an NFQ socket can otherwise trigger normal host-kernel module autoload even from a container. The environment must therefore provide the backend before the run; otherwise the gate fails explicitly and no evidence may be recorded.

## Recorded evidence

The final guarded dev19 run passed all nine checks with Suricata 8.0.6. Queue 42 attached with zero initial kernel/userspace drops; a 1 MiB accepted payload matched its deterministic SHA-256; private SID 9900019 blocked TCP port 9090 with EVE action `blocked`; and after Suricata stopped, the same port delivered the complete payload through the mandatory nftables bypass path.

The bounded five-transfer sample recorded 39.988 ms minimum, 42.277 ms median, 44.485 ms maximum, and 197.75 Mbit/s aggregate throughput. These values describe only this functional run. The schema-valid report is retained as `qualification-evidence/nfqueue-functional-dev19.json`. Public IPS activation remains gated pending overload/capacity/soak and installed IPS lifecycle/recovery work.
