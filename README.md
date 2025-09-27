# 🦦 Meercata (suricata-mode) v1.6

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

## Interactive Mode (Engine)
  <img width="907" height="403" alt="image" src="https://github.com/user-attachments/assets/cdc823dc-879a-4d2a-bcda-a402baa5b27c" />

## Live Monitor (jq beautified and readable)
<img width="907" height="565" alt="image" src="https://github.com/user-attachments/assets/2d0c4432-0e17-4463-a9be-20be5df70931" />

---

## 📦 Installation

### 1. Dependencies

Ensure the following are installed:

```bash
# Core tools 1 : UFW/IPTABLE
apt install -y suricata iptables jq vim

and

# Core tools 2 : suricata
apt install -y suricata

# Optional, for better checklist UI
apt install -y dialog whiptail

Also recommended:

Systemd (for auto-start integration)

ufw if you prefer using UFW as your firewall manager

2. Install Meercata
sudo cp suricata-mode.sh /usr/local/bin/meercata
sudo chmod +x /usr/local/bin/meercata

RUn:
sudo meercata "or" suricata-mode

3. Install Suricatamon (live monitor)
sudo cp suricatamon /usr/local/bin/suricatamon
sudo chmod +x /usr/local/bin/suricatamon
(Suricatamon is automatically used in Advanced → 11 if available.
Otherwise, Meercata falls back to tail -f.)

Menu:
|  \/  |  ___   ___  _ __  ___  __ _ | |_  __ _ 
| |\/| | / _ \ / _ \| '__|/ __|/ _` || __|/ _` |
| |  | ||  __/|  __/| |  | (__| (_| || |_| (_| |
|_|  |_| \___| \___||_|   \___|\__,_| \__|\__,_|

============= Meercata =============
1) IDS (sniff-only)
2) IPS-ALL (inline enforce)
3) Flush NFQUEUE rules
4) Status
5) Advanced…
6) Rules Insight (rule-files)
7) Edit rule-files (YAML; checklist/open)
8) Quit
====================================

IDS vs IPS

IDS mode
Runs Suricata in sniff-only (-i <iface>), no packets are blocked.

IPS-ALL mode
Runs Suricata in inline mode with NFQUEUE.
👉 Requires iptables or ufw NFQUEUE hooks.

Example iptables hook for all traffic:
iptables -I INPUT   -j NFQUEUE --queue-num 0
iptables -I OUTPUT  -j NFQUEUE --queue-num 0
iptables -I FORWARD -j NFQUEUE --queue-num 0

Rules Management

Rules are defined in suricata.yaml:
default-rule-path: /var/lib/suricata/rules
rule-files:
  - local.rules
  - meercata.rules

Steps:

1.Create/edit .rules file in the rules directory.
2.Add custom rules (examples below).
3.Use Edit rule-files → Checklist in Meercata to enable/disable.
4.Reload Suricata from menu.

Live Monitor

Advanced → 11 launches suricatamon.
This gives a colorized, readable stream of Suricata events:

2025-09-27 12:03:12 [ALERT] [LOCAL] MEERCATA Brute-force attempt src=192.168.1.100 dst=10.0.0.5
2025-09-27 12:03:15 [DROP] 192.168.1.100 → 10.0.0.5 proto=tcp reason=policy
2025-09-27 12:03:20 [DNS] 192.168.1.50 → example.com = 93.184.216.34

🚨 Disclaimer

This tool is for educational and defensive security purposes.
Always test in a controlled environment before using in production.
Works only with NFQUEUE hooks (iptables or ufw).


---

👉 Do you also want me to create a **sample `rules/` folder** (with `meercata-ddos.rules`, `meercata-bruteforce.rules`, `meercata-nmap.rules`) so GitHub users can test right away without writing rules manually?
