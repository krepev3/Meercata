# Meercata  — v0.9.0-beta
## Notes :
Bash is the baseline Suricata Interactive Controller (Discontinued) as reference
Python is expanding to NGFW Mini.

Python CLI/interactive helper for running Suricata in IDS/IPS mode with NFQUEUE hooks, rule-file management, and a systemd inline unit. Defaults to **dry-run** so you can see commands before applying them.

## Quick start (CLI)
```bash
python3 main.py --help
python3 main.py status                           # show Suricata/NFQUEUE status (dry-run for mutating cmds)
python3 main.py diag --iface eth0 --queue 0      # combined status: service, hooks, firewall tools
python3 main.py ids --iface eth0                 # dry-run IDS
python3 main.py ips --iface eth0 --queue 0       # dry-run IPS
python3 main.py flush --iface eth0 --queue 0     # dry-run flush NFQUEUE hooks
python3 main.py rules --config /etc/suricata/suricata.yaml
python3 main.py rule-set --file local.rules --state enabled --config /etc/suricata/suricata.yaml
python3 main.py yaml-summary --config /etc/suricata/suricata.yaml
python3 main.py nfq-queue --queue 0 --config /etc/suricata/suricata.yaml
python3 main.py unit-install --iface eth0 --queue 0 --backend auto   # dry-run
```

Apply (requires root):
```bash
sudo python3 main.py ips --iface eth0 --queue 0 --apply
sudo python3 main.py flush --iface eth0 --queue 0 --apply
sudo python3 main.py unit-install --iface eth0 --queue 0 --backend auto --apply
```

## Interactive menu
Run with no arguments:
```bash
python3 main.py
```
Features:
- Suricata control: IDS/IPS start, status, monitor (suricatamon or tail).
- Rules/YAML: view/toggle rule-files, set runmode/NFQ keys, interactive add rule-file (creates `/var/lib/suricata/rules/<name>.rules` and appends to `rule-files:`).
- Hooks/firewall: show detected firewall tools, list rules (formatted iptables/ip6tables/nft), flush NFQUEUE hooks with confirmation, insert allowlist rule, counters, backup/restore iptables/ip6tables.
- Systemd: install/remove inline unit (`suricata-inline.service`).
- Defaults: store/load config/iface/queue/backend.

## Rule-file helper
- Adding a rule-file via the menu writes the file under `default-rule-path` (from `suricata.yaml`, default `/var/lib/suricata/rules`) and appends it to `rule-files:` if missing.
- YAML edits are backed up as `<cfg>.<timestamp>.bak` before modification.

## Dependencies
- Linux only. Requires `suricata`.
- For IPS/NFQUEUE: `iptables`/`ip6tables` (xtables) or `nft` (auto-detected).
- For systemd unit: systemd.

## Notes and safety
- Default mode is dry-run; pass `--apply` to execute.
- IDS/IPS commands require `--iface`.
- `suricata -T` is run before starting IDS/IPS; failures abort start.
- NFQUEUE flush/install returns warnings if hooks fail to apply/remove.
- Validate in a lab before production; no automated tests/CI are included.

## How to use (common tasks)

- **Interactive mode:** `python3 main.py` (recommended for exploration). Navigate menus for Suricata control, rules/YAML, hooks/firewall, systemd unit, defaults.
- **Start IDS:** `python3 main.py ids --iface <iface>` (add `--apply` to run). Uses `-i <iface>`, no NFQUEUE.
- **Start IPS:** `python3 main.py ips --iface <iface> --queue <q> [--backend auto|xt|nft]` (add `--apply`). Flushes old hooks, validates config, installs NFQUEUE hooks, runs Suricata inline with `-q <q>`.
- **Flush NFQUEUE hooks:** `python3 main.py flush --iface <iface> --queue <q>` (add `--apply`). Shows detected hooks, asks confirmation, flushes iptables/nft.
- **Show status/diag:** `python3 main.py status` (Suricata/NFQUEUE); `python3 main.py diag --iface <iface> --queue <q>` (service + hooks + firewall tools + config presence).
- **Rule management:** `python3 main.py rules --config <cfg>` to list; `rule-set --file <name> --state enabled|disabled` to toggle; interactive add rule-file via menu (creates `/var/lib/suricata/rules/<name>.rules` and appends to `rule-files:`).
- **YAML tweaks:** `yaml-summary` to view HOME_NET/EXTERNAL_NET/capture/nfq; `runmode-set`, `nfq-batchcount`, `nfq-failopen`, `nfq-queue` to adjust NFQ settings; af-packet toggles available via menu.
- **Firewall tools:** menu shows detected iptables/ip6tables/nft; option to list rules in formatted tables; allowlist insertion helper; backup/restore iptables/ip6tables; counters view.
- **Systemd inline unit:** `unit-install`/`unit-remove` (dry-run by default). Writes `/etc/default/meercata` and `/etc/systemd/system/suricata-inline.service`.

## Behavior at a glance
- Dry-run vs apply: every command accepts `--apply`; without it, commands are printed/logged instead of executed.
- Safety checks: ensures binaries exist; validates queue >= 0; requires iface for IDS/IPS; runs `suricata -T` before starting.
- Backups: YAML edits create timestamped backups alongside the file. iptables/ip6tables backups land in `/var/backups/meercata` by default.
- NFQUEUE hooks: backend auto-picks nft if available, otherwise iptables. Flush/install operations ignore missing rules to avoid noisy errors.
- Rule-file creation: new files placed under `default-rule-path` and appended to `rule-files:`; table shown after creation for confirmation.

## Limitations / platform
- Linux-only (netfilter/NFQUEUE + systemd). No macOS/Windows/FreeBSD support.
- No automated tests/CI yet; treat as beta (`v0.9.0-beta`) and validate changes in a lab environment.
