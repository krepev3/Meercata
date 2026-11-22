# Meercata | Applied Network Security Research

> Research portfolio for the [Meercata project](../README.md). This page describes the project's research questions, evidence standards, and technical work. It is **not** a claim that every proposed capability has been implemented or tested.

## Research statement

**Problem:** Operating a network intrusion detection stack involves more than enabling signatures. Defenders must establish which traffic can be observed, whether configuration changes are safe, what alerts actually mean, and how to retain enough context to investigate them.

**Project approach:** Meercata is a Python-based controller and monitoring utility built around **Suricata**, the packet analysis and detection engine. The publicly released v1.00 is focused on **Windows passive IDS** with Npcap; Linux v2 is a separate work in progress.

**Working research question:** Can a lightweight controller improve the observability, operational safety, and evidentiary usefulness of a Suricata deployment without overstating detection or prevention outcomes?

This repository documents the engineering approach, testable hypotheses, methods, and limitations. Results should only be promoted from *proposed* to *validated* when reproducible evidence is attached.

## Current evidence-based scope

| Area | What repository materials show | Evidence level / limitation |
| --- | --- | --- |
| Windows passive IDS | Command paths and Windows documentation describe Npcap-based Suricata pcap capture | Documented implementation; requires lab/runtime reproduction on a target host |
| EVE JSON monitoring | `suricatamon.py` includes event formatting, alert/drop record handling, and domain-context functions | Source-inspected; unit-test examples exist; not a measurement of real-world detection quality |
| Alert and drop evidence | The monitor formats alert and Suricata-reported drop actions into readable records | Source-inspected; a drop record is **not**, by itself, proof that traffic was prevented |
| Operator checks | `preflight.py` checks dependencies, runtime conditions, privileges, and selected feature support | Source-inspected; full platform matrix not independently measured here |
| Configuration safety | Windows documentation describes dry runs, Suricata config tests, backups, and rollback | Documented design; destructive and failure-injection tests still need published records |
| Windows inline IPS | Documented as conditional on a WinDivert-enabled Suricata binary | **Not part of the stated validated passive IDS deployment** |
| Linux v2 | Described as separately under development | **Not included** in the Windows v1.00 release |

**Meaning of evidence labels**

- **Documented**: described in project documentation; may still need independent test evidence.
- **Source-inspected**: implementation path is visible in code; not proof of runtime correctness.
- **Unit-tested**: a test exists; passing results must include environment, commit, command, and output.
- **Lab-validated**: reproducible result on a specified operating system, Suricata build, capture path, and test dataset.
- **Field-validated**: authorized deployment observations with appropriately sanitized evidence and defined limits.
- **Proposed**: a research idea or future capability, not an implemented feature.

## Research tracks

### R1 — Traffic visibility and passive IDS limits

**Question:** What traffic is actually observable by the Windows Npcap capture path?

- Compare capture interfaces, traffic direction, and local vs routed traffic.
- Identify visibility gaps introduced by switched networks, encryption, capture configuration, and traffic not traversing the monitored interface.
- Separate *no alert* from *no traffic*, *no relevant signature*, and *no malicious activity*.

### R2 — Detection evidence and alert interpretation

**Question:** Can Meercata preserve context without turning an alert into a premature incident conclusion?

- Test Suricata EVE events for allowed alerts, blocked-action events, DNS observations, and missing fields.
- Review the domain association cache as **contextual enrichment**, not authoritative ownership proof.
- Correlate timestamp, flow, signature, action, host, and independent endpoint/firewall evidence where available.
- Measure false positives and false negatives against labeled test traffic rather than reputation labels alone.

### R3 — Safe security operations

**Question:** Do preflight checks, dry runs, backups, config validation, and recovery paths reduce operational risk?

- Test requirements under standard-user and Administrator sessions.
- Deliberately submit invalid configuration in a **disposable lab** and verify that known-good state remains recoverable.
- Record unexpected service interruption, config drift, and recoverability.

### R4 — Platform and prevention boundary

**Question:** Which platform-specific components are prerequisites for IPS, and which assumptions fail across Windows and Linux?

- Windows: verify the installed Suricata binary's WinDivert support before any inline IPS experiment.
- Linux: treat NFQUEUE, firewall rules, fail-open behavior, and systemd as a separate versioned investigation.
- Never equate a parser recognizing `drop` with demonstrated packet blocking.

## Published documents

- [Architecture and trust boundaries](ARCHITECTURE.md)
- [Experimental validation plan and report template](VALIDATION_PLAN.md)
- [Research log and claims ledger](RESEARCH_LOG.md)
- [Research and engineering roadmap](ROADMAP.md)
- [Windows operations and requirements](../Meercata-v1.00-Windows/README.md)

## Reproducibility and disclosure standard

Every completed experiment should include: a question and hypothesis; repository commit SHA; OS and build; Suricata/Npcap versions and relevant feature flags; interface and capture topology; synthetic or authorized traffic; exact commands and configuration; expected versus observed output; limitations; and an explicit conclusion with a confidence level.

**Privacy and authorization:** Do not publish enterprise IPs, production packet captures, credentials, sensitive DNS/URL history, live user information, internal configuration, or employer-owned artifacts without approval. Favor lab-generated PCAPs, RFC 5737 documentation addresses, synthetic EVE JSON, and sanitized screenshots. Run capture, replay, and blocking tests only on systems and networks you own or are authorized to assess.

**Contribution and credibility:** Favor reproducible demonstrations, issue-based peer review, clear failure reports, and corrections over claims of novelty or endorsement. This is a living research record; planned work should remain visibly marked until tested.
