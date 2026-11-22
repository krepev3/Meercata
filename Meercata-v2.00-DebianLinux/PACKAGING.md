# Meercata production packaging contract

## Current safety state

Meercata provides a Python-only production image builder. It creates and verifies a filesystem image below an explicit staging root. It is not a live-host installer and it never invokes `sudo`, creates users, installs policy, reloads systemd, starts Suricata, or enables the health/monitor/freshness/delivery/delivery-health timers.

The builder rejects `/` as a staging root, relative roots, source/staging overlap, symlinked source or destination components, unowned destination collisions, modified managed files, unowned code below the installed Python/helper directories, oversized assets, and malformed prior manifests.

The separate container qualifier is the only current code path that installs this image at `/`. It refuses unless it is effective root inside Docker, the operating system is Debian 13, systemd is not running as the container service manager, an explicit confirmation phrase is supplied, and the approved official image digest is supplied. It is a qualification harness, not a general installer.

The native `.deb` builder and its four approved POSIX-shell lifecycle entry points are specified separately in [NATIVE-DEBIAN.md](NATIVE-DEBIAN.md). Package orchestration, integrity checks, and lifecycle policy remain Python; shell is limited to the interface required by dpkg.

## Build interface

From the immutable source tree, use an absolute empty or previously Meercata-managed staging directory:

```text
python3 -m meercata.package_builder stage /absolute/path/to/stage
python3 -m meercata.package_builder verify /absolute/path/to/stage
python3 -m meercata.package_builder removal-plan /absolute/path/to/stage
python3 -m meercata.package_qualifier /absolute/path/to/stage
```

All commands emit one JSON object. Expected packaging or qualification failures return exit code 3. `removal-plan` is read-only: it identifies hash-matching files that a package manager may remove, changed files that must be preserved for operator review, missing files, the manifest that must be removed last, and runtime roots that remain protected. The qualifier copies only verified package payload into an automatically removed disposable root and leaves the supplied stage unchanged; see [QUALIFICATION.md](QUALIFICATION.md).

## Image contents

The fixed inventory includes:

- Python modules below `/usr/lib/meercata/python/meercata`;
- Python-only CLI launcher `/usr/bin/meercata`;
- Python-only privileged launcher `/usr/lib/meercata/bin/meercata-helper`;
- guarded Python-only systemd-readiness and live-RuleOps qualification launchers;
- exact sudoers, sysusers, tmpfiles, monitor retention, systemd unit, and Suricata override templates;
- configuration example, versioned JSON schemas, operating contracts, and change log;
- the original synthetic `dev13-ruleops-v1` qualification pack, its reproducible source, fixed alert-only overlays, and no unreviewed production captures;
- `/usr/lib/meercata/package-manifest.json`, following `package-manifest-v1`.
- `qualification-v1`, the machine-readable staged qualification result contract.
- `container-qualification-v1`, the machine-readable root-owned Debian 13 result contract.
- `ruleops-vm-qualification-v1`, the machine-readable live activation/rollback result contract.
- `deb-build-v1` and `debian-lifecycle-qualification-v1`, the native artifact and lifecycle evidence contracts.
- `apt-repository-qualification-v1`, the machine-readable signed repository install/upgrade result contract.

The launchers disable bytecode writes and import only from the fixed root-owned `/usr/lib/meercata/python` directory.

The manifest records package version, intended `root:root` ownership, exact file modes, roles, and SHA-256 values. The image is deterministic for identical source bytes. Hashes detect accidental or unauthorized changes when the manifest itself remains trusted; they are not a cryptographic package signature and cannot defend against a hostile root account.

## Configuration and data boundary

The package image installs only `/usr/share/meercata/meercata.example.toml`. It never creates or overwrites `/etc/meercata/meercata.toml`. A production configuration must be reviewed, installed root-owned, and validated separately.

Package staging and removal never delete or rewrite:

```text
/etc/meercata
/var/lib/meercata
/var/log/meercata
```

The installed package manager must preserve controller transactions, privileged recovery receipts, last-known-good state, candidates, audit records, and operator configuration unless an explicit retention or purge action is separately approved.

## Upgrade rules

An image may be restaged over an older image only when:

1. the previous manifest is valid and within the fixed owned-path allowlist;
2. every existing managed file still matches its previous SHA-256;
3. no new destination collides with an unowned file or symlink;
4. no unowned file exists in the Python package or privileged-launcher directories.

Failure is checked before package files are written. Modified managed files stop the upgrade instead of being silently overwritten. Shared parent directories such as `/usr/bin`, `/etc/sudoers.d`, and `/usr/lib/systemd/system` are not package-owned and their existing modes are not changed by staging.

## Installed-host work still required

The staged image now feeds a reproducible native Debian binary-package builder and pinned lifecycle qualification. Dev15 additionally demonstrates signed local-repository install and upgrade with an explicitly pinned ephemeral qualification key, independent signature verification, and metadata/package tamper rejection. Before production release, packaging must additionally demonstrate:

- production signing-key custody, rotation, revocation, and repository publishing access control;
- reproducibility across the pinned release build toolchain and authenticated publication of the exact approved artifact;
- HTTPS, mirror/CDN delivery, availability monitoring, and repository incident recovery;
- systemd daemon-reload and unit behavior with systemd running as PID 1;
- configuration provisioning without replacing an administrator-managed file;
- downgrade and failed-removal recovery beyond the qualified install, idempotent configure, upgrade, modified-upgrade rejection, and normal removal paths;
- real external collector identity, credential/certificate rotation, delivery availability, long-duration retention, and preservation of recovery data under disk pressure.

Only the double-guarded disposable Debian 13 container qualifiers authorize installation onto `/`. The general staged-image builder and `.deb` builder reject the filesystem root and are not live-host installers.
