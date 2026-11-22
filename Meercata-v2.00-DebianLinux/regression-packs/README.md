# Production PCAP regression packs

This source directory contains two original synthetic packs: the single-case `dev13-ruleops-v1` live-transaction fixture and the seven-case `production-baseline-v1` DNS/HTTP/TLS/TCP/UDP regression corpus. They contain no user, customer, credential, production, exploit-binary, or third-party capture. Any future captured or externally sourced traffic may contain sensitive or malicious content and must pass legal, privacy, provenance, licensing, and handling review before inclusion.

An installed pack lives at `/usr/lib/meercata/regression-packs/PACK_ID/` and contains:

```text
manifest.json
case-one.pcap
case-two.pcapng
```

Qualification packs may also retain reviewed source hex, alert-only rule overlays, a regeneration recipe, and a development-only offline validation configuration. Only manifest-declared `.pcap` or `.pcapng` files are replayed by the production regression runner.

The manifest follows `schemas/regression-pack-v1.schema.json`. Each case pins its PCAP SHA-256 and declares at least one required or forbidden `(gid, sid)` alert. Pack IDs and case IDs are lowercase safe identifiers; PCAP paths are basenames, not arbitrary paths.

The qualified synthetic baseline now covers:

- benign DNS, HTTP, and TLS negatives with four explicitly forbidden ET/Open SIDs;
- stable positive DNS, HTTP, raw TCP, and raw UDP ET/Open identities;
- deterministic packet bytes, timestamps, checksums, hashes, and regeneration;
- full replay against the same 52,322-active-rule ET/Open snapshot used by dev13.

Future environment-specific extensions should add relevant parser edge cases, locally important detections, and privacy-scrubbed false-positive regressions without weakening the baseline or importing unclear data.

Do not commit packet captures containing credentials, personal data, customer traffic, proprietary payloads, or unclear licensing. The installed package must make the directory and files root-owned and non-writable by group or other users.
