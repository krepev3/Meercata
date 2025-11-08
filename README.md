# 🦦 Meercata (suricata-mode) v1.6

**Meercata** = **Meerkat + Suricata** — a friendly, menu‑driven Bash controller for [Suricata](https://suricata.io/) in **IDS/IPS NFQUEUE mode** with a built‑in rules manager and live monitoring. It wraps common Suricata operations into an interactive TUI for analysts and sysadmins.

> **Heads‑up**
> Meercata’s IPS enforcement only works when traffic is sent to **NFQUEUE** (iptables/ufw or nftables). If you run Suricata in **AF‑PACKET/PCAP sniff‑only**, Meercata can start IDS, but it will not block traffic.

---

## Table of contents

* [Features](#features)
* [How it works](#how-it-works)
* [Requirements](#requirements)
* [Installation](#installation)
* [Quick start](#quick-start)
* [Operating modes](#operating-modes)
* [Backends: nftables vs xtables](#backends-nftables-vs-xtables)
* [Systemd auto‑start (inline IPS)](#systemd-auto-start-inline-ips)
* [Rules management](#rules-management)
* [Live monitoring (suricatamon)](#live-monitoring-suricatamon)
* [YAML summary helper](#yaml-summary-helper)
* [Environment variables](#environment-variables)
* [CLI switches](#cli-switches)
* [Logs](#logs)
* [Troubleshooting](#troubleshooting)
* [Security notes](#security-notes)
* [Sample rules (optional)](#sample-rules-optional)
* [FAQ](#faq)
* [Contributing](#contributing)
* [License](#license)

---

## Features

* IDS (sniff‑only) and IPS (inline enforce via **NFQUEUE**)
* Auto‑detect network interface & NFQUEUE number
* **Backend auto‑selection**: prefers nftables if present, falls back to iptables
* Fail‑open kernel toggle (`net.netfilter.nf_queue_bypass`)
* Cautious : Boot persistence: generates a systemd unit that installs hooks **before** starting Suricata
* Backup/restore of iptables/ip6tables rules
* Allowlist insertion (before NFQUEUE)
* Rule‑files insight (enabled/disabled, existence, size, line count)
* Checklist to enable/disable rule‑files directly in `suricata.yaml`
* Multi‑open rule‑files in your editor (`$EDITOR`, default `vim`)
* Live monitoring via `suricatamon` (colorized, human‑readable events)
* Single log: `/var/log/suricata-mode.log`

## How it works

Meercata expects Suricata to run **inline** with `-q <QUEUE>` so packets flow through NFQUEUE. Meercata will:

1. **Set up hooks** (nftables or iptables) to send traffic to the queue.
2. **Start Suricata** with `-q $QUEUE` (IPS) or `-i $IFACE` (IDS).
3. Provide menus for status, YAML tools, rule management, and monitoring.

## Requirements

Install the following packages (Debian/Kali/Ubuntu style):

```bash
sudo apt update
sudo apt install -y suricata iptables jq vim dialog whiptail nftables
```

> `dialog`/`whiptail` are optional for a nicer checklist UI. `nftables` is recommended; Meercata auto‑falls back to iptables if nft is missing.

## Installation

Copy the scripts to a directory on your `PATH` and make them executable:

```bash
# Meercata engine
sudo cp meercata /usr/local/bin/meercata
sudo chmod +x /usr/local/bin/meercata

# (Optional) Suricatamon live monitor
sudo cp suricatamon /usr/local/bin/suricatamon
sudo chmod +x /usr/local/bin/suricatamon
```

Verify:

```bash
meercata --help
```

## Quick start

```bash
# 1) Pick your interface once (or let Meercata detect)
sudo IFACE=wlan0 meercata

# 2) From the menu, choose: 2) IPS-ALL (inline enforce)
#    – or run directly:
sudo IFACE=wlan0 BACKEND=auto QUEUE=0 meercata --ips

# 3) Live view (Advanced → 14) if suricatamon is installed
```

> If you only want to **sniff** without blocking, pick **IDS** in the menu or run `meercata --ids`.

## Operating modes

* **IDS (sniff‑only)**:

  * Stops any running Suricata, flushes NFQUEUE hooks, then runs `suricata -c $CFG -i $IFACE`.
  * No packets are blocked.
* **IPS‑ALL (inline)**:

  * Tests Suricata config, enables fail‑open (if available), installs hooks (nft **or** iptables) and runs `suricata -c $CFG -q $QUEUE`.
  * FORWARD hooks are **symmetric** (both directions). Loopback and conntrack fast‑path are inserted to avoid self‑lock.

## Backends: nftables vs xtables

Meercata can operate with either backend:

* **nftables (preferred)**

  * Creates `table inet suri` with `preraw`/`outraw` chains and queues `{ tcp, udp, icmp, ipv6-icmp }` to `$QUEUE`.
  * Minimal profile also available (7070 + ICMP/ICMPv6) via Advanced → 11.
* **xtables (iptables/ip6tables)**

  * Inserts loopback and conntrack fast‑path **before** NFQUEUE rules.
  * Queues INPUT/OUTPUT and symmetric FORWARD (iif/oif) to `$QUEUE`.

Select with `BACKEND=auto|nft|xt`. Default is `auto` (prefers nft if present).

## Systemd auto‑start (inline IPS)

Meercata can install a small unit that wires hooks **before** Suricata starts, and cleans them up on stop:

```bash
# Install and start on boot (uses current IFACE/QUEUE/BACKEND)
sudo IFACE=wlan0 QUEUE=0 BACKEND=auto meercata  # open menu
# Advanced → 5) Install boot auto-start (IPS-ALL + pre-hooks)

# Remove
# Advanced → 6) Remove boot auto-start
```

The unit name is `suricata-inline.service`. A small env file is placed at `/etc/default/meercata`.

---

## Boot auto‑start (IPS‑ALL + Pre‑hooks) — IMPORTANT

**Short version:** installing the boot auto‑start will apply NFQUEUE hooks *before* Suricata starts. This requires proper kernel features and careful testing — otherwise you risk disrupting networking on boot (possible loss of network connectivity until hooks are removed).

**What to check before enabling:**

* Make sure your kernel exposes `net.netfilter.nf_queue_bypass` (fail‑open). Verify with:

```bash
sysctl -a | grep net.netfilter.nf_queue_bypass
```

If the sysctl is **not present**, your kernel may not support queue bypass; enabling IPS auto‑start on such systems increases the risk that traffic will be queued without a running userspace handler (Suricata), which can block or severely impact traffic.

* Test the hooks **manually** first (Advanced → 10 or 11) and confirm you can start/stop Suricata cleanly and that critical services keep working.

* Prefer testing on a non‑production host or in a maintenance window and keep an out‑of‑band console available (serial, VM host console, or local access) so you can revert the unit if something goes wrong.

**If things go wrong:**

* Boot into rescue/recovery or use local console to run `systemctl disable --now suricata-inline.service` and remove `/etc/default/meercata`.
* From a recovery shell you can remove nftables table or iptables hooks manually (the service includes cleanup commands) or use `nft delete table inet suri` / `iptables -D ...` as needed.

**Recommendation:**
Only enable the boot auto‑start on systems where you've verified kernel support and completed manual testing. When in doubt — do not enable on critical production boxes without a full recovery plan.

## Rules management

Suricata rule files are referenced in `suricata.yaml`:

```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - local.rules
  - meercata.rules
```

Meercata provides:

* **Rules Insight**: lists enabled/disabled files, path, size, line count.
* **Checklist enable/disable**: toggles entries in `suricata.yaml` (creates a timestamped backup first).
* **Open in editor**: select files to open or auto‑create missing paths.

> Tip: Put your custom files (e.g., `meercata-nmap.rules`, `meercata-bruteforce.rules`) in the default rule path and enable them via the checklist.

## Live monitoring (suricatamon)

If `/usr/local/bin/suricatamon` is present, Advanced → **14** launches it with wide, SID‑aware output. Otherwise Meercata falls back to tailing `eve.json`.

## YAML summary helper

Menu **7 → 3** prints a short summary of **active** YAML values:

* `HOME_NET` / `EXTERNAL_NET`
* `af-packet`/`pcap` interfaces
* `nfq` mode/queue/inline/fail-open

## Environment variables

You can influence Meercata without editing the script:

| Variable          | Default                       | Meaning                                |
| ----------------- | ----------------------------- | -------------------------------------- |
| `SURICATA_CFG`    | `/etc/suricata/suricata.yaml` | Path to Suricata YAML                  |
| `EDITOR`          | `vim`                         | Editor for rule files                  |
| `SURICATAMON_BIN` | `/usr/local/bin/suricatamon`  | Live monitor path                      |
| `LOGFILE`         | `/var/log/suricata-mode.log`  | Meercata log file                      |
| `BACKEND`         | `auto`                        | `auto`, `nft`, or `xt`                 |
| `QUEUE`           | `0`                           | NFQUEUE number                         |
| `IFACE`           | auto‑detected                 | Interface to bind INPUT/OUTPUT/FORWARD |

Examples:

```bash
sudo IFACE=wlan0 QUEUE=1 BACKEND=nft meercata --ips
sudo SURICATA_CFG=/custom/suricata.yaml meercata --status
```

## CLI switches

```
meercata [--ids | --ips | --flush | --status | --advanced | --help]
```

* `--ids` — Start Suricata in sniff‑only mode
* `--ips` — Start inline IPS with NFQUEUE hooks
* `--flush` — Remove all NFQUEUE hooks (xtables & nftables)
* `--status` — Show Suricata and hook status
* `--advanced` — Jump straight into Advanced menu

## Logs

Operational notes are appended to: `/var/log/suricata-mode.log`.

## Troubleshooting

* **nft flush error**: If you see `flush table inet suri: No such file or directory`, Meercata now deletes the table instead of flushing when absent.
* **Chat service or established flows getting dropped**: Ensure the **conntrack fast‑path** rules are inserted **before** NFQUEUE (Meercata does this automatically). Also consider allowlisting critical destinations via Advanced → 9.
* **IPv6**: Meercata manages ip6tables entries when `ip6tables` is available. Verify `HOME_NET` contains your IPv6 prefix, e.g. `"2402:1980:881b:7c5a::/64"`.
* **Fail‑open**: If `net.netfilter.nf_queue_bypass` is not present, your kernel may not support queue bypass.
* **UFW**: UFW uses iptables under the hood. If UFW rewrites rules on boot, prefer the **systemd auto‑start** feature so hooks are reapplied before Suricata starts.

## Security notes

* Always test on a non‑production host first.
* Keep `HOME_NET`/`EXTERNAL_NET` accurate to avoid over‑blocking.
* Use allowlists for business‑critical systems and health checks.
* **Backups**: Meercata creates timestamped backups of `suricata.yaml` before editing rule‑file states. Use Advanced → 7/8 to back up/restore iptables sets.

## Sample rules (optional)

Consider providing a `rules/` folder in your repo so users can test immediately:

```
rules/
├── meercata-nmap.rules          # detect/drop NULL/FIN/XMAS, with sensible rate-limits
├── meercata-bruteforce.rules    # SSH/HTTP basic brute-force heuristics
└── meercata-ddos.rules          # simplistic UDP/TCP flood thresholds
```

Example **Nmap** drops (only block scans, not normal traffic):

```suricata
# Drop typical Nmap stealth scans
# Use detection_filter to avoid false positives against busy services

drop tcp any any -> $HOME_NET any (msg:"MEERCATA Nmap NULL"; flags:0; classtype:attempted-recon; sid:60030001; rev:2;)
drop tcp any any -> $HOME_NET any (msg:"MEERCATA Nmap FIN";  flags:F; classtype:attempted-recon; sid:60030002; rev:2;)
drop tcp any any -> $HOME_NET any (msg:"MEERCATA Nmap XMAS"; flags:FPU; classtype:attempted-recon; sid:60030003; rev:2;)
```

## FAQ

**Q: Can I run IDS mode while nfqueue hooks are present?**
A: Meercata flushes hooks before starting IDS to avoid accidental blocking.

**Q: What if my distro already seeds nftables rules?**
A: Some appliances reset tables on boot. Use the systemd installer so Meercata reapplies hooks pre‑start.

**Q: Where are env values stored for the boot unit?**
A: `/etc/default/meercata` (read by `suricata-inline.service`).

## Contributing

PRs welcome! Please keep changes POSIX‑ish and avoid external deps where possible. Add tests or reproducible steps for complex changes.

## License

Choose a license you prefer (e.g., MIT, Apache‑2.0). Include a `LICENSE` file in the repo.
