# Meercata on Windows

Meercata supports Windows 10/11 and Windows Server with Python 3.10 or newer, Suricata, and Npcap. Windows IDS capture uses Suricata's pcap input. Windows inline IPS uses WinDivert and is available only when Suricata was compiled with WinDivert support.

## Start

Open Command Prompt or PowerShell in this directory. Use an elevated window (**Run as administrator**) when starting IDS/IPS or editing files under `C:\Program Files`.

For the interactive UI, double-click `meercata-admin.cmd` to request elevation and start Meercata. To pass CLI options, open Command Prompt or PowerShell with **Run as administrator** and use `meercata.cmd` normally.

```powershell
.\meercata.cmd check
.\meercata.cmd
```

Meercata automatically searches `PATH`, `SURICATA_BIN`, and `C:\Program Files\Suricata` for `suricata.exe`. It discovers the usual `suricata.yaml` and `log\eve.json` paths. It also adds the detected Npcap DLL directory only to Suricata child processes; it does not alter the system `PATH`.

If Npcap was installed with **Restrict Npcap driver's access to Administrators only**, Meercata detects that setting. An unelevated requirement check defers the Suricata runtime probe, because loading Npcap's DLLs would otherwise wait for a UAC helper. Applied capture commands still require an elevated process.

If Suricata is installed elsewhere, set these before launching:

```powershell
$env:SURICATA_BIN = 'D:\Suricata\suricata.exe'
$env:SURICATA_CFG = 'D:\Suricata\suricata.yaml'
$env:SURICATA_EVE = 'D:\Suricata\log\eve.json'
```

## Passive IDS

Run `meercata.cmd check` or use **Set defaults** in the interactive menu to see capture targets. On Windows, `--iface` should normally be an IP address assigned to the adapter. An Npcap device such as `\Device\NPF_{GUID}` is also accepted.

Review the dry run:

```powershell
.\meercata.cmd --iface '<adapter-ip>' ids
```

Then run an elevated terminal and apply it:

```powershell
.\meercata.cmd --iface '<adapter-ip>' --apply ids
```

Press `Ctrl+C` to stop. Meercata detects and restores a previously running Suricata service where possible.

## Monitoring

```powershell
.\meercata.cmd monitor `
  --log 'C:\Program Files\Suricata\log\eve.json' `
  --trigger-log '.\Trigger Drop-Alert.txt'
```

The live EVE monitor and the readable threat-evidence follower are implemented in Python on Windows, so GNU `tail` is not required.

## Inline IPS

Windows does not use Linux NFQUEUE, nftables, or iptables. A WinDivert-enabled Suricata build is required:

```powershell
.\meercata.cmd --apply --windivert-filter 'true' ips
```

For a Windows gateway, add `--forward`. The requirement check blocks the command when the installed binary reports WinDivert as disabled. Passive IDS remains usable in that case.

## Platform limitations

The following commands remain Linux-only because they directly manage NFQUEUE or systemd: `flush`, `allowlist`, `backup`, `restore`, `counters`, `unit-install`, and `unit-remove`. On Windows they exit with an explanatory requirement error.

Npcap's `wpcap.dll` may be installed under `C:\Windows\System32\Npcap` rather than the normal DLL search path. Foreground Meercata runs handle that automatically. A Suricata Windows service may still require reinstalling Npcap with **WinPcap API-compatible mode** enabled.
