# Meercata v2.00 dev25 qualification report

22 November 2026 · Debian package `2.0.0~dev25-1`

Dev25 passed all 15 installed monitoring checks on a fresh Debian 13 x86-64 KVM guest. Its four stock timers ran before and after a normal reboot. The HTTPS collector accepted both events queued before shutdown, and the delivery log contained a receipt for each event ID. The outbox finished empty with zero dead letters.

## Results

| Check | Observation |
|---|---|
| Service permissions | The `meercata` account could read its disposable credentials. It could neither write the controller configuration nor read or write the privileged log and state directories. |
| HTTPS and rotation | The collector rejected the retired token with HTTP 401. The worker refused the replacement server certificate while it still trusted only the old CA. Delivery resumed after each credential update. |
| Scheduler | The watchdog reported stale data at 182 seconds with exit code 2. A fresh observation restored exit code 0. |
| Retention | After 14 forced rotations, each log retained 12 generations, including 11 compressed files. The installed producer and delivery worker resumed writing. |
| Full log filesystem | Filling a 64 KiB guest-only log filesystem caused the producer to exit 3 and preserved the previous state byte for byte. After storage recovered, the producer exited 0. |
| Restart and reboot | Restarting the producer preserved its sequence for an unchanged observation. The sequence was 9 on both sides of the reboot, and both queued IDs matched collector acceptance and on-disk receipts. |
| Cleanup | The qualifier restored the controller configuration, compared five protected files with their original hashes and modes, removed disposable credentials and private keys, and confirmed all four timers were disabled and inactive. Suricata passed its service-user health check. |

## Fix found in the VM

The installed monitor could traverse its parent directories under the packaged ACLs, but it tried to open them for listing. This prevented it from writing to its own state and log directories. Secure directory traversal now uses Linux `O_PATH` with directory and no-follow checks. An unprivileged regression test exercises nested creation below a search-only directory.

The qualifier compares native systemd timer timestamps with monotonic journal timestamps and reads full journal JSON records. Before reboot, every accepted trigger must fall after the last manual probe. After reboot, the qualifier requires service output from the new boot.

## Verification

| Check | Result |
|---|---|
| Full v2 regression suite | 531 passed |
| Frozen v1 reference suite | 44 passed |
| Installed Debian VM checks | 15 passed |
| Installed monitoring, outbox and TLS regression launchers | 7, 8 and 12 passed |
| Staged image | 6 checks passed, including validation of 15 systemd units |
| Debian package | Two independent builds were byte-identical. The guest verified the package digest before installation. |

The package contains 162 payload files. Its SHA-256 is `d9691987d8d4460becdb97f8ed4d09544bde84a6f6a461e3e6521b9922b0061d`.

The host verified the SHA-512 of Debian genericcloud image build `20261116-2664`. The guest ran systemd as PID 1 with two vCPUs, 2 GiB RAM, Suricata 8.0.8, synthetic ICMP traffic, and a loopback HTTPS collector. The validation summary records the exact package and runtime versions.

During an earlier run, systemd timed out once waiting for Suricata readiness and subsequently restarted it successfully. That run failed qualification. The cause of that intermittent startup timeout remains unconfirmed. The final qualification used a clean guest and the packaged timeouts and schedules.

## Remaining release work

The next deployment check is end-to-end delivery to the intended collector and operator notification channel, including certificate and token rotation and an outage. Target-hardware traffic tests, the 24–72-hour soak, sustained storage pressure, release signing and rollout qualification remain open. Public IPS activation and live rule promotion remain gated.

The [VM evidence](qualification-evidence/monitor-systemd-vm-dev25.json) contains the two kernel boot IDs, recovered event IDs and all fifteen observations. The [validation summary](qualification-evidence/dev25-validation-summary.json), [package build](qualification-evidence/deb-build-dev25.json) and [staged checks](qualification-evidence/staged-dev25.json) record the rest of the verification. The [VM procedure](MONITOR-SYSTEMD-VM.md) describes how to repeat the test.
