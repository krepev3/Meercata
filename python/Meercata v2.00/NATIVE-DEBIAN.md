# Meercata native Debian package contract

## Language boundary

Meercata remains a Python CLI and control plane. POSIX shell is used only for the four lifecycle entry points required by `dpkg`: `preinst`, `postinst`, `prerm`, and `postrm`. Each hook uses `#!/bin/sh`, `set -eu`, a fixed lifecycle case statement, absolute executable paths, and no caller-derived command construction.

The hooks contain no network command, package installation, rule or firewall operation, Suricata socket access, arbitrary deletion, `eval`, service enablement, or service start. Complex verification and mutation are dispatched to the installed Python lifecycle module through `/usr/lib/meercata/bin/meercata-package-lifecycle`.

## Build interface

Build outside the source tree into an absolute new output directory:

```text
python3 -m meercata.debian_package /absolute/output/directory
python3 -m meercata.debian_package /absolute/output/directory --revision 2
```

The project version `2.0.0.devN` maps to Debian version `2.0.0~devN-R`, where `R` is the bounded positive packaging revision. The pre-release `~devN` ordering keeps development packages below a future final `2.0.0` package.

The Python builder:

- assembles the already verified fixed package inventory;
- substitutes only version and installed-size fields into reviewed control metadata;
- generates complete payload `md5sums`;
- copies exact reviewed maintainer-script bytes;
- normalizes all package-tree timestamps to the fixed `SOURCE_DATE_EPOCH`;
- calls `/usr/bin/dpkg-deb` without a shell, with root ownership, single-threaded uniform xz compression, bounded output, and a timeout;
- extracts the completed archive and re-verifies control fields, hooks, md5sums, root ownership listing, payload manifest, modes, hashes, and absence of active configuration.

Identical source bytes, project version, Debian revision, architecture, and toolchain produce identical `.deb` bytes. The build report follows `deb-build-v1` and includes the artifact SHA-256. Reproducibility across a different dpkg/xz toolchain remains a separate release-build gate.

## Package metadata

The current package is `Architecture: all` and depends on Python 3.11 or newer, sudo, systemd, Suricata 8 or newer, and suricata-update 1.3.8 or newer. Debian 13's default suite provides Suricata 7.0.10, which is below the supported line in AD-002. Official `trixie-backports` packages for Suricata 8.0.6 and suricata-update 1.3.8 are now separately pinned and qualified; see `SURICATA-PACKAGES.md`.

The package installs only a configuration example, never `/etc/meercata/meercata.toml`, so no active controller configuration is a package conffile. The package-owned sudoers entry is declared as a conffile. It also includes a deterministic Debian changelog and `meercata(1)` manual page.

The package includes proprietary copyright metadata. Dev15 qualifies delivery through a signed local APT repository using an ephemeral qualification-only key; it is not approved for distribution until release ownership, production repository, signing-key custody, and license decisions are complete.

## Lifecycle

### Initial install

`preinst install` refuses any pre-existing package destination, including files, directories, and symlinks. This prevents a first install from claiming or overwriting an unowned helper, policy, code, unit, or documentation tree.

`postinst configure` is idempotent. It applies the fixed sysusers and tmpfiles policies, validates sudoers, verifies every required installed payload hash/mode/root ownership, and reloads systemd only when a systemd manager is running. It explicitly does not enable or start the health/monitor/freshness/delivery/delivery-health timers, their services, the private IPS target, or Suricata.

Debian installations may use dpkg path exclusions for documentation. Only manifest roles `documentation` and `copyright` may be absent for that reason. Missing code, launcher, schema, configuration example, sudoers, sysusers, tmpfiles, systemd unit, or package metadata always fails configuration.

### Upgrade

Before unpacking a new version, `preinst upgrade` validates the existing installed manifest and every required managed file. If an administrator or attacker changed a managed executable, module, policy, schema, unit, or configuration example, the upgrade fails before replacement and preserves the installed version and changed bytes for investigation.

### Removal

`prerm remove` disables/stops the private IPS target, delivery-health, delivery, freshness, transition monitor, and legacy health timers/services when systemd is running, then removes the exact sudoers path before dpkg removes helper code. If service shutdown fails, removal stops while helper and authorization remain installed; if sudoers removal succeeds but a later step fails, access is denied safely. Configuration, monitor state/transitions/outbox/dead letters, delivery receipts, recovery receipts, and audit data are preserved.

`postrm` performs only a systemd daemon reload when a manager is running. It never deletes a newly created or administrator-modified sudoers path after package payload removal.

Normal removal preserves service/operator identities, `/etc/meercata`, `/var/lib/meercata`, `/var/log/meercata`, transactions, privileged receipts, candidates, last-known-good state, and audit records. There is deliberately no automatic purge implementation. Destructive data purge requires a separately designed and explicitly approved operation.

## Debian 13 qualification

The pinned root-owned Debian 13 lifecycle qualifier builds revisions 1, 2, and 3 in-container and exercises:

1. deterministic verified package builds;
2. clean revision-1 installation with root-owned required artifacts;
3. repeated `postinst configure` idempotency;
4. revision-1 to revision-2 upgrade;
5. pre-unpack rejection of a revision-3 upgrade after managed CLI modification;
6. preservation of the modified bytes and installed revision after rejection;
7. normal removal with privileged artifacts absent and configuration/state/log sentinels intact.

The report follows `debian-lifecycle-qualification-v1`. Historical dev10 reports are stored as `qualification-evidence/deb-build-dev10.json` and `qualification-evidence/debian-lifecycle-dev10.json`. Separate dev11 evidence qualifies the exact Suricata packages without ignored dependencies. Dev12 build and KVM evidence qualify real systemd PID 1, live Suricata readiness, service-user health, and timer execution. Dev13 qualifies live rule activation and rollback, dev14 the production regression baseline, and dev15 signed local-repository installation and upgrade. Production signing-key custody and network repository delivery, crash/reboot recovery, IPS, retention, and purge remain explicit limitations.
