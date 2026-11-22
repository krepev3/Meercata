# Meercata Research Log and Claims Ledger

This log records what can be supported by repository evidence as of **2026-11-22**. It is not a laboratory test report. New entries should include date, commit, operator, method, observed output, and limitations.

## Entry 2026-11-22 — Portfolio baseline (source/document review)

**Scope reviewed:** Root `README.md`, Windows README, `WINDOWS.md`, `preflight.py`, `suricatamon.py`, `pyproject.toml`, and selected unit tests.

**Observed in source/docs:**
- The root README identifies v1.00 as a Windows Suricata/Npcap passive IDS controller and monitor.
- `suricatamon.py` contains functions for readable EVE alert/action evidence and domain context.
- `preflight.py` contains checks for Suricata features and environment requirements.
- `tests/test_suricatamon.py` includes cases that distinguish allowed alerts from blocked-action events and exercise DNS association.
- The Windows README reports **50 passed, 2 platform-specific skipped** for a past test run, but the conditions and current reproducibility are **not independently confirmed by this document**.
- Windows IPS is described as conditional on WinDivert support; Linux v2 is described as separate work in progress.

**Not observed in this review:** An executed Windows lab setup; measured network detection efficacy; packet-drop confirmation; Windows IPS benchmarking; Linux v2 tests; production performance metrics.

**Conclusion:** Documentation and unit-test artifacts support an engineering research portfolio, but runtime claims require independently recorded experiments.

## Claims ledger

| ID | Claim | Supporting artifact | Status | Evidence needed to strengthen |
| --- | --- | --- | --- | --- |
| CL-001 | Windows v1.00 is designed for passive IDS using Npcap and Suricata | Root/Windows READMEs, Windows guide | Documented | MC-WIN-IDS-001 with environment and traffic evidence |
| CL-002 | EVE alert/action formatting functions are implemented | `suricatamon.py` | Source-inspected | Fresh unit test report and integration run |
| CL-003 | Unit tests cover allowed vs blocking action distinctions | `tests/test_suricatamon.py` | Source-inspected test cases | Run MC-UNIT-001 at a pinned commit |
| CL-004 | Configuration validation/rollback is part of intended workflow | Windows README / implementation modules | Documented | MC-CONFIG-001 with before/after hashes |
| CL-005 | Windows inline IPS enforcement works on target host | Conditional WinDivert description only | **Unverified** | MC-IPS-001 independent receiver packet results |
| CL-006 | Linux v2 is functional and validated | Development roadmap only | **Unverified / out of v1.00 scope** | Versioned Linux repository/build, integration tests and lab notes |
| CL-007 | Meercata reduces false positives or improves detection rate | No measured comparative dataset in reviewed materials | **Not established** | Labeled corpus, baseline, definitions, methodology, metrics |

## Rules for future entries

1. Record **date of observation** separately from the date a CVE, rule, or event was published.
2. Link each claim to a specific commit, test artifact, issue, or report.
3. State evidence status: proposed, source-inspected, unit-tested, lab-validated, or field-validated.
4. Describe null results, failures, and telemetry gaps as clearly as successes.
5. Do not publish organization-specific logs or traffic without explicit approval.
6. Corrections are welcome: note what changed, why, and which prior conclusion was revised.

## Next research entry

Run [MC-UNIT-001](VALIDATION_PLAN.md#mc-unit-001--test-suite-baseline), capture exact output, and then execute the isolated Windows passive IDS test with sanitized evidence. This is a **next action**, not an already completed test.
