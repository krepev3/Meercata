# Meercata Experimental Validation Protocol

**Status: Proposed protocol, not completed testing.**

This document gives Meercata a reproducible research methodology. It does **not** represent results obtained in this authoring session. Complete the report template for each experiment, attach sanitized evidence, and explicitly distinguish unit tests from end-to-end network validation.

## Experiment identification

Record the following before testing:

| Field | Required value |
| --- | --- |
| Experiment ID | e.g., `MC-WIN-IDS-001` |
| Research question / hypothesis | What would count as supporting or refuting evidence? |
| Meercata commit | Full Git SHA |
| Test date (with time zone) | ISO 8601 timestamp |
| Tester and authorization | Authorized operator / owned lab |
| OS | Edition, version, build, architecture |
| Python | Exact version |
| Suricata | Exact version and build features (`--build-info`) |
| Npcap | Exact version and installation options |
| Interface/topology | Adapter type, interface ID, traffic route / visibility |
| Ruleset | Source, version, relevant SID and revision |
| Test input | Sanitized PCAP or synthetic EVE JSON with SHA-256 |
| Output | Raw result path, log hash, screenshots as applicable |

Avoid storing real hostnames, internal topology, usernames, production PCAPs, or secrets in this repository.

## Validation tiers

| Tier | Meaning | Examples |
| --- | --- | --- |
| T0 — Source inspection | Implementation exists in source | Function and call-site review |
| T1 — Unit test | Controlled inputs exercise functions | `pytest` parser, formatting, checks |
| T2 — Integration | Components communicate in a disposable test lab | Suricata writes EVE; Meercata reads it |
| T3 — Network observation | Real packets follow the intended sensor path | PCAP/capture counters, observed alerts, independent capture |
| T4 — Enforcement | An inline path prevents specific traffic | Sender/receiver observations and network counters |
| T5 — Operational resilience | Failure / recovery tested | Invalid config, restart, log loss, rollback |

**Do not report T4 from T1–T3 evidence.** A monitor displaying a blocked-action field is not a packet-drop efficacy test.

## Proposed experiments

### MC-UNIT-001 — Test suite baseline

**Hypothesis:** Existing unit tests complete in the recorded Python environment.

**Procedure:**
```powershell
cd Meercata-v1.00-Windows
python --version
python -m pip install -e ".[test]"
python -m pytest -q
```

Capture commit SHA, console output, Python version, package versions, any failures/skips, and whether running in Windows or a non-Windows test environment. Report **your observed count**, not a number copied from README. Unit tests cannot establish real-world intrusion detection or IPS coverage.

**Pass criterion:** Exit code 0 and documented tests pass; characterize skips separately. **Status:** Not executed for this portfolio change.

### MC-EVE-001 — Allowed alert versus blocked action

**Hypothesis:** EVE events representing allowed alerts are logged as alert evidence rather than counted as actual drops.

**Inputs:** Synthetic EVE events with `alert.action=allowed`, an event with a blocking action, and an event without an `alert` object.

**Method:** Exercise `suricatamon.format_alert_record`, `format_drop_record`, and `format_trigger_record`, including the existing `tests/test_suricatamon.py` cases. Review output and ensure action semantics remain unchanged.

**Pass criterion:** Allowed alert is not reported as a drop; blocked-action input carries an explicit action; malformed data does not silently become a proof of prevention. **Status:** Source and test cases identified; not rerun here.

### MC-EVE-002 — DNS association and cache limitations

**Hypothesis:** Domain enrichment adds context but can also associate a reused/shared IP with a name that is no longer applicable.

**Method:** Inject synthetic DNS-answer events followed by alerts involving the same destination IP. Repeat with alternate domain, TTL change, shared hosting, and invalid IP inputs. Assess current cache eviction and absence of authoritative ownership or time-bound validation.

**Pass criterion:** Output is consistently labeled contextual; limitations are documented; no domain relationship is presented as conclusive attribution. **Status:** Planned.

### MC-WIN-IDS-001 — Passive packet visibility

**Hypothesis:** A Windows Npcap/Suricata IDS deployment detects known lab traffic on the selected capture interface without blocking it.

**Method:** In an isolated and authorized lab, record the actual Windows adapter and Suricata config, run preflight, capture controlled benign and detection-test packets, verify the same packets using an independent capture where possible, and inspect `eve.json`. Test a positive and a negative rule case.

**Primary measures:** Packets sent vs observed, alerts matching the chosen rule, traffic allowed to complete, time alignment between evidence sources.

**Pass criterion:** Expected traffic appears at the sensor, known-rule alert is observed when appropriate, and the application flow remains unaffected by passive IDS operation. Do not generalize to traffic the interface never receives. **Status:** Planned; no runtime evidence attached.

### MC-CONFIG-001 — Change-safety and recovery

**Hypothesis:** Unsafe or invalid YAML changes do not leave the monitored service in an unrecoverable state.

**Method:** On a disposable lab instance with a backed-up known-good config, record baseline file hashes, issue a dry-run change, attempt a syntactically invalid change, inspect config-test results, rollback files, and post-test health. No failure injection on production sensors.

**Pass criterion:** Dry run does not alter files; invalid changes are rejected or rolled back; final config hash and service state match the expected recovery behavior. **Status:** Planned.

### MC-IPS-001 — Conditional Windows inline prevention

**Hypothesis:** A specific Windows build with explicit WinDivert support can block controlled test traffic using an appropriately configured inline path.

**Prerequisite:** Verify Suricata build features, selected filter, routing path, fail behavior, and operator authorization. Missing WinDivert support means **not applicable**, not passed.

**Method:** Use dedicated sender/receiver lab endpoints and independent packet capture. Compare baseline connectivity, passive IDS, and enabled inline mode. Preserve action events, packet traces, and independent receiver observations.

**Pass criterion:** Measured delivery changes only when inline control is enabled, with consistent independent evidence. **Status:** Proposed / not demonstrated. Never claim production-ready IPS from an EVE action alone.

## Measurement and adverse cases

Whenever applicable, report: true/false positives on **labeled** stimuli, alert latency, EVE loss, memory/CPU overhead, interface coverage, service behavior, recoverability, and relevance of rule versions. Sample size matters; small lab tests do not establish production detection rates.

Include negative cases for malformed/truncated JSON, missing timestamps, log rotation, inaccessible paths, mismatched time zones, repeated event IDs, unsigned or altered rules, and noisy DNS associations. The aim is to discover limitations, not only to demonstrate expected behavior.

## Per-experiment report template

Copy the block below to a new file under `docs/experiments/` after executing a test:

```markdown
# MC-<ID> — <Experiment title>
- Date/time zone:
- Author / authorization:
- Repository commit:
- Hypothesis:
- Lab environment (OS, Python, Suricata build, Npcap, topology):
- Test data provenance / SHA-256:
- Commands and configuration:
- Expected observations:
- Actual observations:
- Evidence files / hashes:
- Result: PASS / FAIL / INCONCLUSIVE / NOT APPLICABLE
- Confidence and limitations:
- Alternative explanations:
- Next checks:
```

**Publishing rule:** If a test cannot be reproduced or lacks core telemetry, mark it **INCONCLUSIVE**, not `PASS`. If the feature is absent on the tested build, report **NOT APPLICABLE**, not `FAIL`.
