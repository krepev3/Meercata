# Suricata package qualification contract

## Supported source

Meercata targets Debian 13 amd64 and Suricata 8.0.x. The qualified binary source is the official Debian `trixie-backports` suite, not a third-party repository and not an untracked source build. The current qualification pins:

- `suricata` Debian version `1:8.0.6-1~bpo13+1`;
- `suricata-update` Debian version `1.3.8-1~bpo13+1`;
- the official Debian archive keyring at `/usr/share/keyrings/debian-archive-keyring.gpg`;
- the official Debian 13 slim base digest recorded in the platform schemas.

The reviewed deb822 source example is installed inertly at `/usr/share/meercata/apt/debian-backports.sources`. Meercata never writes `/etc/apt`, runs APT, enables a repository, downloads packages, or changes package pins on a live host. Repository activation is an administrator-owned provisioning action.

Debian Backports is opt-in and has APT priority 100. Production provisioning must request the exact approved versions or use a separately reviewed pin. A newer package is unsupported until the qualification report, compatibility tests, and release record are updated.

## Authentication and freshness

The disposable qualifier requires the installed active source to be byte-identical to the reviewed source example. It verifies the cached `trixie-backports` InRelease cleartext signature with `sqv` and the Debian archive keyring, requires the Debian Backports origin/codename/pinning fields, and rejects future-dated, expired, or unreasonably long validity windows.

Package names, versions, architectures, installed states, repository filenames, sizes, and SHA-256 values are taken from the authenticated APT metadata. Installed non-documentation package files are independently checked against dpkg's MD5 inventory with root ownership. Debian slim documentation exclusions are counted but do not make executable, library, policy, or unit files optional.

## Runtime gates

The qualified Suricata binary must report version 8.0.6 and provide all AD-002 capabilities used by the first production target:

- detection engine;
- AF_PACKET passive capture;
- NFQUEUE inline capture;
- Unix command socket;
- systemd notification support;
- portable non-native compiler architecture settings;
- `/usr` installation and `/etc/suricata` configuration paths.

The default Debian configuration is tested with a fixed local qualification rule, `--init-errors-fatal`, and no network access. The base Suricata unit is inspected, then the complete Suricata/Meercata unit set is parsed after the Meercata drop-in is installed.

## Meercata dependency test

The native package explicitly depends on both `suricata (>= 8.0)` and `suricata-update (>= 1.3.8)`. Inside the pre-provisioned disposable container, it is installed with normal `dpkg --install` and without an ignored dependency. The installed CLI version and combined units are verified.

Normal Meercata removal must leave both Suricata packages, `/usr/bin/suricata`, and `/etc/suricata/suricata.yaml` byte-identical. The expected dpkg state for Meercata after normal removal is `config-files`; automatic purge remains forbidden.

## Boundary and limitations

Repository provisioning uses network access before qualification. The qualification run itself has networking disabled and receives the source tree read-only. Systemd is not PID 1, Suricata is not started, and no packets, live socket operations, reload, nftables/NFQUEUE mutation, crash, or reboot are exercised. Those remain installed-host gates.
