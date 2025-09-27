# 🦦 Meercata

**Meercata** = **Meerkat + Suricata**  
A friendly interactive Bash controller for [Suricata](https://suricata.io/) in **IDS/IPS NFQUEUE mode** with a built-in rules manager and live monitoring.

It wraps common Suricata operations into a **menu-driven TUI** for easier use by analysts and sysadmins.

---

## ⚠️ Important

**Meercata only works when Suricata is deployed inline via `NFQUEUE`.**  
This means your traffic must be hooked into NFQUEUE using either:

- **iptables** rules (classic backend or nftables backend), or  
- **ufw** (which under the hood uses iptables)  

If you only run Suricata in **AF-PACKET**, **PCAP**, or **IDS sniff-only mode**, Meercata’s IPS enforcement will not function.  

---

## ✨ Features

- IDS (sniff-only) and IPS (inline enforce with NFQUEUE)
- Auto-detect network interface & NFQUEUE number
- Fail-open kernel toggle
- Boot persistence (systemd unit for IPS mode)
- Backup/restore of iptables rules
- Allowlist insertion
- Rule-files insight (enabled/disabled, size, line count, existence check)
- Checklist-based enable/disable of rule-files directly in `suricata.yaml`
- Multi-open in editor (default `vim`, override with `$EDITOR`)
- Live monitoring (`suricatamon`) with colorized, human-readable Suricata events
- Logs and actions are recorded in `/var/log/suricata-mode.log`

---

## 📦 Installation

### 1. Dependencies

Ensure the following are installed:

```bash
# Core tools
apt install -y suricata iptables jq vim

# Optional, for better checklist UI
apt install -y dialog whiptail

