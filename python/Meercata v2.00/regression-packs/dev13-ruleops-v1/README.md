# Dev13 RuleOps qualification fixture

This pack is an original, synthetic Meercata fixture. It contains no captured user, customer, production, credential, or third-party traffic and is distributed under the same license as Meercata.

The packet is UDP from the documentation-only address `192.0.2.10` to `198.51.100.20`, destination port `65013`, with the ASCII payload `MEERCATA-QUALIFICATION-DEV13\n`. The two alert-only overlays detect the same payload and differ only by rule revision, producing hash-distinct candidates with equivalent qualification behavior.

Regenerate the PCAP from the reviewed hex source with Wireshark `text2pcap`:

```sh
text2pcap -q -F pcap -t ISO \
  -4 192.0.2.10,198.51.100.20 \
  -u 40000,65013 \
  payload.hex qualification.pcap
```

After regeneration, update `pcap_sha256` in `manifest.json` only after inspecting the packet and confirming the expected hash.

`suricata-offline.yaml` is a minimal, project-owned configuration used only to validate the fixture on a development host whose system configuration is not readable. Installed regression runs use Meercata's configured production Suricata file instead.
