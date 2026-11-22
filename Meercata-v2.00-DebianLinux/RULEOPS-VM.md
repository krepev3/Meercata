# Meercata live RuleOps VM qualification

## Safety boundary

The dev13 qualifier is a root-only harness for a disposable Debian 13 KVM/QEMU guest. It does not enable the public `meercata rules promote` command. It refuses to run unless the exact confirmation phrase, approved Debian genericcloud image SHA-512, root identity, Debian 13, systemd PID 1, x86-64 architecture, KVM/QEMU virtualization, and exact installed package versions all match.

The qualifier mutates the active Suricata ruleset and therefore must never be run first on a production host. VM snapshotting and recovery access remain operator responsibilities outside the harness.

## Required preparation

The package installs `dev13-ruleops-v1`, an original synthetic one-packet UDP regression fixture plus two alert-only overlays. The source hex, fixed timestamp, PCAP hash, overlay hashes, and minimal development validation configuration are retained with the pack. It contains no captured user or third-party traffic.

Inside the guarded disposable VM, prepare the two candidates with the installed launcher:

```text
/usr/lib/meercata/bin/meercata-ruleops-vm-qualifier \
  --confirmation "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 LIVE RULEOPS" \
  --image-sha512 APPROVED_SHA512 \
  --prepare-candidates
```

Preparation begins with the active ET/Open ruleset, refuses a collision with private qualification SID `9900013`, appends one fixed overlay to each candidate, and requires distinct resulting hashes. It then passes both candidates through the ordinary rule-count policy, strict Suricata validation, and immutable PCAP regression path. The JSON output supplies `success_candidate.candidate_id` and `rollback_candidate.candidate_id` for the mutation run. This qualification-only operation does not enable the public promotion command.

The initial active ruleset must differ from both candidates. Suricata and all dev12 readiness checks must be healthy before the mutation run.

## Execution

Run the installed qualifier as root inside the disposable guest:

```text
/usr/lib/meercata/bin/meercata-ruleops-vm-qualifier \
  --confirmation "QUALIFY DISPOSABLE MEERCATA DEBIAN 13 LIVE RULEOPS" \
  --image-sha512 APPROVED_SHA512 \
  --success-candidate SUCCESS_UUID \
  --rollback-candidate ROLLBACK_UUID
```

The candidate arguments accept canonical UUIDs only through the existing candidate and transaction stores. They are never interpreted as paths or commands. Candidate preparation and mutation are independently protected by the full disposable-VM and exact-package gate.

## Qualification sequence

The fixed sequence is:

1. verify the disposable VM guard and exact dev13, Suricata, and suricata-update packages;
2. re-hash both candidate files and their root-managed PCAP manifests;
3. promote the success candidate through the transaction engine and four-operation helper;
4. verify its activation and non-blocking reload receipts and committed state;
5. activate and reload the rollback candidate, require genuine healthy post-reload state, then inject a critical qualification result;
6. require transactional restoration and a second non-blocking reload of the success candidate;
7. verify final healthy runtime state, active hash, root-only receipts, and controller/privileged audit evidence.

The failure injection occurs only after the ordinary health collector returns healthy. An already unhealthy system therefore cannot be mislabeled as a successful rollback test.

## Evidence and limitations

Success emits one `ruleops-vm-qualification-v1` JSON report with six passed checks. Failed qualification emits no success report and returns exit code 3 for expected qualification or transaction failures.

The dev13 run passed all six checks in the approved Debian 13 KVM guest using the exact artifact recorded in `qualification-evidence/deb-build-dev13.json`. Transaction `272e2ac0-0cd4-4930-9e4a-af608c22935a` committed the success candidate. Transaction `fb57d329-a211-46ed-b6e3-5732e1a10272` activated and reloaded the second candidate, received the deliberate critical result, restored the success rules, reloaded them, and finished `ROLLED_BACK`. The final rules SHA-256 was `2705cda0e02b88413f8872d3d0f0eb16d3910c1ece892ad2715e0dc4fadebd48`, with 15 healthy checks and both audit streams present. The complete schema-valid report is `qualification-evidence/ruleops-vm-dev13.json`.

This gate covers live IDS rule activation, non-blocking reload, post-reload health, rollback, rollback reload, durable transactions, helper receipts, and audit presence. It does not cover IPS/NFQUEUE, process crash, reboot, disk exhaustion, retention, repository signing, package removal, or purge.

Dev14 adds the separately qualified seven-case `production-baseline-v1` corpus. Public rule promotion remains gated until the remaining installed-host, recovery, repository, retention, and IPS/NFQUEUE gates are completed and reviewed.
