# Meercata v2.00 Architecture Decisions

## Status

This document is the Phase 0 architecture baseline for Phase 1 implementation. The decisions are accepted for development; passing the later production qualification gates is still required before deployment.

The baseline was recorded on 2026-08-10 against this development host:

- Kali GNU/Linux 2026.3 on amd64;
- systemd 260;
- Suricata 8.0.6 with NFQUEUE, AF_PACKET, Unix socket, and systemd support;
- nftables 1.1.6;
- Python 3.13.14.

Kali is a development and compatibility environment, not the initial production deployment target.

## AD-001 — Supported platform

The initial production target is Debian 13 on amd64 with systemd. Python 3.11 or newer is required. The controller may be developed and tested on compatible Debian-family systems, but each additional production distribution requires its own installation, integration, reboot, upgrade, and rollback qualification results.

Reason: one narrow production target makes service supervision, filesystem permissions, package behavior, and failure testing reproducible.

Reconsider when: Debian 13 qualification is complete and another distribution has an identified operator and test environment.

## AD-002 — Supported Suricata version

The initial supported line is Suricata 8.0.x, with 8.0.6 as the development baseline. Meercata must check the installed version and required build features before a mutating operation. A new Suricata minor or major line is unsupported until configuration validation, socket, rule reload, EVE schema, NFQUEUE, PCAP regression, and recovery tests pass.

Required build capabilities are:

- detection support;
- AF_PACKET for passive IDS;
- NFQUEUE for inline IPS;
- Unix socket support for controlled runtime operations;
- systemd notification support for supervised production operation.

## AD-003 — Firewall scope

Production IPS uses nftables only. Legacy iptables and ip6tables behavior remains part of the v1 compatibility reference but will not be migrated into the first v2 production implementation.

Meercata may create, inspect, replace, and delete only objects in its own nftables table. It must never flush a ruleset or infer ownership from rule position alone. Owned objects must include stable names and transaction metadata.

## AD-004 — Deployment topology and fail policy

Qualification proceeds in this order:

1. passive IDS on a dedicated sensor interface;
2. fail-open NFQUEUE IPS on a single Linux gateway;
3. fail-closed IPS only after an external HA or bypass design is documented, tested, and explicitly approved.

Fail-closed operation is outside the initial release scope. Queue bypass, listener loss, queue saturation, controller failure, Suricata failure, boot failure, and rollback failure must each have an explicit test before the IPS pilot.

## AD-005 — Audit destinations

Controller events are written to both:

- journald for operational visibility and central collection;
- root-owned JSON Lines files under `/var/log/meercata/` for structured transaction history.

Every event includes a schema version, transaction ID when applicable, UTC timestamp, actor identity, operation, redacted arguments, result, and error classification. Audit failure blocks mutations unless the operation is an explicitly documented emergency recovery action. Threat evidence remains separate from controller audit data.

## AD-006 — Operator authorization

Read-only health commands may run unprivileged through group-readable state and narrowly scoped system interfaces. Mutations use a fixed privileged helper invoked through explicit sudoers rules. The helper accepts typed operations and canonical paths, not arbitrary commands or shell text.

A service API and polkit integration are deferred until the local CLI and privilege boundary pass security and failure-injection testing.

## AD-007 — Configuration and schema policy

Meercata controller configuration uses TOML at `/etc/meercata/meercata.toml`. Every file contains an integer `schema_version`. Unknown keys, invalid types, unsafe paths, and unsupported schema versions are rejected.

Suricata configuration remains YAML and is handled as a separately staged artefact. Controller code must not implement a general-purpose YAML rewrite when a purpose-specific validated change is sufficient.

Schema migrations are explicit, versioned, reversible where practical, and never performed implicitly during service startup.

## AD-008 — Health metrics and alert integration

The canonical health result is a versioned JSON document exposed by `meercata health --json`. Human-readable and watch output are projections of the same model.

Initial external integration uses journald plus an atomic Prometheus textfile export. A network-listening metrics service is out of scope until authentication and exposure policy are defined.

Default thresholds are shipped as documented conservative values, but production thresholds must be recorded from a passive IDS baseline and then approved before inline IPS. Missing data is reported as unknown, never silently healthy.

## AD-009 — Rule source and promotion policy

The first supported external source is Emerging Threats Open through `suricata-update`. Source URLs and identifiers are allowlisted in root-owned configuration.

Updates are staged daily but promoted manually in the initial release. Promotion requires source/version metadata, hashes, strict validation, rule-count and ruleset-diff review, PCAP regression results, a last-known-good snapshot, controlled reload, and post-reload health verification.

Automatic promotion is deferred until operational history demonstrates reliable validation and rollback.

## AD-010 — Retention, privacy, and integrity

Controller audit records and transaction manifests are retained for at least 365 days. Configuration and rule snapshots use a count-and-age policy with a minimum of 10 successful versions and 30 days. Retention cleanup is audited and must not remove the active or last-known-good version.

EVE threat evidence defaults to 30 days of local retention. Packet payload capture, remote export, and longer retention are disabled unless an operator documents purpose, access controls, storage capacity, and applicable privacy requirements.

Manifests store cryptographic hashes for staged and activated artefacts. Secrets and packet payloads must never be included in controller audit records.

## AD-011 — Operator interface and implementation language

Meercata v2.00 is a CLI-only application. It will not include a desktop GUI, web GUI, or network-listening control API in the initial production scope.

2026-11-08 clarification: an interactive terminal menu is part of the local CLI
scope. It delegates to the same command/service boundary, retains release gates,
and does not introduce direct service/firewall/configuration mutations. Existing
scriptable commands remain available. Missing installation/configuration must
not prevent browsing the menu. This presentation addition preserves AD-011's
Python and privilege boundaries; full v1 feature migration remains separate.

The control plane is implemented in Python. Introducing or integrating another programming language requires explicit operator approval before implementation, along with a documented security, packaging, maintenance, and rollback impact assessment.

## Change policy

An architecture decision may change through a new dated decision record that states:

- the reason for the change;
- affected requirements and threats;
- compatibility and migration impact;
- added or changed tests;
- rollback behavior.

Changing a baseline does not waive an acceptance gate.
