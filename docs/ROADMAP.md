# Meercata Research Roadmap

Roadmap items are **proposals and evaluation priorities**, not commitments, implemented features, or completed tests. Their order favors evidence and deployment safety over adding features.

| Priority | Research deliverable | Reason | Exit evidence / completion criterion | Status |
| --- | --- | --- | --- | --- |
| P0 | Repeatable Windows test baseline | Establish current reproducibility | Pinned commit, Python/Suricata versions, actual `pytest` output, recorded skips | Planned |
| P0 | Passive IDS end-to-end validation | Prove traffic visibility at selected sensor | Lab topology, PCAP hashes, Suricata EVE output, independent capture comparison | Planned |
| P0 | Configuration safety review | Avoid breaking operator systems | Dry-run and failure-injection tests; config hash comparison and recovery record | Planned |
| P1 | EVE ingestion robustness | Reduce missing/misclassified evidence | Tests for malformed JSON, log rotation, duplication and timestamps | Planned |
| P1 | Alert enrichment correctness | Prevent misleading IP/domain conclusions | Synthetic DNS reuse/shared-IP cases, aging and context labels | Planned |
| P1 | Detection effectiveness study | Measure signal quality rather than count alerts | Labeled benign/attack lab traffic, rule-version controls, FP/FN definitions | Proposed |
| P2 | Windows IPS feasibility | Validate conditional WinDivert functionality | Supported build plus independent blocked-packet evidence; rollback and fail behavior | Proposed |
| P2 | Linux v2 architecture and validation | Avoid cross-platform assumption drift | Separate code/release evidence, NFQUEUE/firewall safety lab results | Work in progress, not validated here |
| P3 | Operational performance study | Understand deployment cost | Repeated load tests with packet loss, CPU/memory, alert latency and limitations | Proposed |

## Release / research gates

- **Gate A — Code evidence:** Link implementation and unit tests to a commit.
- **Gate B — Reproducible lab:** Another person can follow the instructions using a clean, authorized environment.
- **Gate C — Independent observation:** Claims of capture or enforcement have packet-level or endpoint-level corroboration.
- **Gate D — Safety:** Failure, rollback, privileges, and data handling are documented.
- **Gate E — Publish:** Scope, results, limitations, and reference versions are clearly stated.

## Suggested public case studies

1. **Does an EVE alert mean a connection was blocked?** Compare allowed alerts with drop-action records, then independently validate actual traffic delivery in a controlled lab.
2. **Why passive IDS visibility differs from endpoint visibility.** Show what Npcap sees on one selected adapter and what it cannot see.
3. **When can DNS enrichment mislead an investigator?** Explore shared IPs and reused addresses using synthetic EVE data.
4. **Can safe configuration changes survive invalid YAML?** Document failure injection and recovery in an isolated instance.

## Evidence and publication process

Use [the experiment template](VALIDATION_PLAN.md#per-experiment-report-template). For substantial changes, open an issue with a research question and expected evidence; implement and test in a branch; then merge only with documented outcomes. Unsuccessful experiments are still publishable when responsibly analyzed.

**Scope guard:** Meercata is the portfolio. Do not silently transform this roadmap into a claim of a production IDS/IPS, autonomous threat hunting engine, or cross-platform enforcement capability.
