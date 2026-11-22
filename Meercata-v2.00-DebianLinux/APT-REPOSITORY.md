# Meercata signed APT repository qualification

## Scope

Dev15 qualifies the Meercata package trust path through a signed APT repository. It proves that Debian APT accepts only metadata signed by an explicitly pinned key, binds the downloaded package to the signed metadata hashes, installs revision 1, upgrades to revision 2, and removes Meercata without deleting protected data.

This is a disposable qualification repository, not a production publishing service. The signing key is generated inside the container, is marked qualification-only, expires after eight days, and is destroyed with the container.

## Safety boundary

The qualifier reuses the root/container/Debian 13/exact-image-digest guard and additionally requires loopback to be the only network interface and the route table to be empty. Run it only in a new disposable container with the project mounted read-only:

```text
python3 -m meercata.apt_repository_qualifier /absolute/new/workspace \
  --source-root /absolute/read-only/source \
  --confirmation I_UNDERSTAND_THIS_IS_A_DISPOSABLE_DEBIAN_13_CONTAINER \
  --image-digest sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
```

The disposable image must already contain `apt-utils`, `gpg`, `gpg-agent`, `sqv`, Python, sudo, systemd, and the exact qualified Suricata packages. Debian and Suricata dependencies are provisioned from the official authenticated Debian repositories before the decisive container is started with networking disabled.

## Repository construction

For revisions `2.0.0~dev15-1` and `2.0.0~dev15-2`, the qualifier:

1. builds and verifies the native package through the existing deterministic builder;
2. creates `Packages` and deterministic `Packages.gz` indexes plus SHA-256 by-hash objects;
3. creates a fixed-date `Release` with `Valid-Until`, `Acquire-By-Hash`, and SHA-256-only index bindings;
4. signs both `Release.gpg` and clear-signed `InRelease` with an ephemeral RSA-3072 key;
5. independently verifies the `InRelease` payload and signer fingerprint with `sqv`;
6. configures APT with only the local repository and an explicit `Signed-By` keyring.

No `trusted=yes`, `Trusted`, insecure-repository allowance, unauthenticated-package allowance, dependency bypass, or shell-built command is used. Omitting the deb822 `Trusted` override is intentional: APT derives trust from successful verification against the pinned `Signed-By` key.

## Ten qualification checks

- exact disposable Debian 13 container identity and network isolation;
- exact preinstalled dependency versions;
- bounded ephemeral signing-key identity and fingerprint;
- two hash-bound repository revisions;
- rejection when the repository is pinned to the wrong key;
- rejection after signed metadata is changed;
- rejection after the package bytes are changed without updating signed metadata;
- authenticated revision-1 installation;
- authenticated revision-1 to revision-2 upgrade;
- normal removal with protected-data preservation.

The schema-valid result is retained as `qualification-evidence/apt-repository-dev15.json`. A successful report is `apt-repository-qualified`, not `production-qualified`.

## Remaining release work

Production publishing still requires an approved signing-key owner and custody system, rotation and revocation procedures, a release builder/toolchain policy, repository access controls, HTTPS and mirror/CDN delivery, monitoring and availability objectives, and an incident runbook. Crash/reboot recovery, IPS/NFQUEUE behavior, retention, and purge remain separate installed-host gates.
