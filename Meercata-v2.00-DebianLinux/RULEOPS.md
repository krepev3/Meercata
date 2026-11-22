# Meercata RuleOps Contract

## Scope and safety state

Phase 3 implements the Python, CLI-only rule candidate pipeline. It can stage ET/Open rules in Meercata-owned state, index and hash them, enforce count-reduction policy, show a bounded difference, validate a selected candidate with Suricata, and replay the qualified synthetic production baseline.

Production activation is deliberately disabled. `meercata rules promote CANDIDATE_ID` returns exit code 3 until the Phase 4 privileged helper is installed and explicitly wired to the tested promotion workflow. The current development code does not copy files into `/var/lib/suricata/rules` and does not reload the live engine.

Dev13 includes a root-only disposable-VM qualification harness for this internal workflow. The harness does not enable public promotion. See [RULEOPS-VM.md](RULEOPS-VM.md).

## Commands

```text
meercata rules status [--json]
meercata rules stage [--json]
meercata rules diff CANDIDATE_ID [--json]
meercata rules validate CANDIDATE_ID [--json]
meercata rules regress CANDIDATE_ID PACK_ID [--json]
meercata rules promote CANDIDATE_ID
```

`rules stage` has no source URL or output-path parameter. It invokes the fixed `/usr/bin/suricata-update` executable for the allowlisted `et/open` source, uses a UUID candidate directory below `/var/lib/meercata/ruleops/candidates`, and forces `--no-reload --no-test --fail`. Meercata then performs its own explicit validation rather than allowing the update tool to reload the live engine.

`rules validate` invokes this fixed command shape:

```text
/usr/bin/suricata -T -c APPROVED_CONFIG -S CANDIDATE_RULES \
  --init-errors-fatal --set unix-command.enabled=no
```

The approved config and candidate rules paths come from strict configuration and UUID-owned state. They are not caller-provided paths.

`rules regress` accepts only a candidate UUID and safe pack ID. Packs are installed below `/usr/lib/meercata/regression-packs`, pin every `.pcap`/`.pcapng` SHA-256, and define required and forbidden `(gid, sid)` alert counts. Suricata replays each capture in single-threaded offline mode with the candidate loaded exclusively. EVE input, line sizes, case counts, expectations, failures, and recorded identities are bounded. Raw packet data and alert payloads are never copied into candidate manifests or controller audit.

## Candidate policy

Every candidate records:

- schema version, UUID, UTC creation time, source, and lifecycle status;
- SHA-256, size, active/disabled counts, and action counts;
- added, removed, and changed rule identities compared with the active ruleset;
- total difference counts and whether displayed identities were truncated;
- configured minimum count and unexpected-reduction decision;
- bounded update, validation, and PCAP regression results without raw rules, packets, alert payloads, or unbounded command output;
- tool identity and validation timestamp.

Active duplicate `(gid, sid)` identities, invalid UTF-8, malformed active rules without numeric SIDs, candidates below the minimum count, and candidates exceeding the configured reduction limit are rejected. Rule strings inside quoted options cannot impersonate `gid`, `sid`, or `rev` fields. Candidate files are re-hashed immediately before promotion to detect post-validation changes.

Promotion also requires `regression.status = "passed"`. The recorded candidate SHA-256 and pack-manifest SHA-256 are rechecked, so editing the candidate or replacing an approved pack invalidates earlier evidence.

Identity lists in manifests and CLI JSON are limited to 1,000 entries per category; total counts remain exact. This prevents a large first install or replacement from producing an unbounded manifest or transaction record.

## Promotion and rollback workflow

The internal workflow is implemented and failure-tested in Python:

```text
lock -> snapshot -> re-hash candidate -> re-check policy -> helper activation
     -> ruleset-reload-nonblocking -> poll ruleset-reload-time
     -> ruleset-stats + ruleset-failed-rules -> health -> commit
```

Any apply, reload, failed-rule, timeout, or health failure enters rollback. After restoration, the previous rules are reloaded and verified. A failed restoration is recorded as `RECOVERY_FAILED`. The narrow reload client permits only:

- `ruleset-reload-nonblocking`;
- `ruleset-reload-time`;
- `ruleset-stats`;
- `ruleset-failed-rules`.

## Configuration

```toml
[rules]
source = "et/open"
minimum_rule_count = 1
maximum_reduction_percent = 5
update_timeout_seconds = 600
validation_timeout_seconds = 120
regression_timeout_seconds = 300
reload_timeout_seconds = 120
reload_poll_seconds = 1
active_rules_path = "/var/lib/suricata/rules/suricata.rules"
suricata_config_path = "/etc/suricata/suricata.yaml"
```

Unknown keys, unsupported sources, non-finite/out-of-range numbers, relative paths, and paths outside the fixed Suricata roots are rejected.

## Qualification status and remaining production gate

Completed through dev14:

- the fixed RuleOps helper, mediated socket access, sudoers policy, supervision units, root-owned configuration, and candidate/state permissions were qualified on Debian 13;
- ET/Open staging, strict validation, installed live reload, and forced rollback passed against the full ruleset;
- `production-baseline-v1` now provides four positive and three benign-negative redistribution-safe cases across DNS, HTTP, TLS, raw TCP, and raw UDP;
- the dev13 live qualifier passed with two reviewed, hash-distinct candidates and retained schema-valid evidence.

Production approval remains blocked until crash/restart, timeout, disk-full, permission, reboot, retention, signed-repository delivery, and IPS/NFQUEUE gates pass. Deployments must also review and extend the synthetic baseline for their own protocols and false-positive history; the built-in pack is not a substitute for site-specific acceptance traffic.
