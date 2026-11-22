"""Qualify signed Meercata APT install and upgrade in isolated Debian 13."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from email.utils import format_datetime
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.container_qualifier import (
    CONFIRMATION,
    DEBIAN_13_IMAGE_DIGEST,
    _require_disposable_debian_13,
)
from meercata.debian_package import DebianPackageBuilder
from meercata.errors import PackagingError, QualificationError


APT_FTPARCHIVE = "/usr/bin/apt-ftparchive"
APT_GET = "/usr/bin/apt-get"
DPKG_QUERY = "/usr/bin/dpkg-query"
GPG = "/usr/bin/gpg"
SQV = "/usr/bin/sqv"
SUITE = "meercata-dev"
COMPONENT = "main"
ARCHITECTURE = "all"
KEY_IDENTITY = "Meercata Qualification Repository <qualification@meercata.invalid>"
RELEASE_DATE = datetime(2026, 8, 15, tzinfo=timezone.utc)
VALID_UNTIL = RELEASE_DATE + timedelta(days=7)
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")


class AptRepositoryQualifier:
    """Build and exercise two signed local repository revisions."""

    def __init__(
        self,
        source_root: Path,
        workspace: Path,
        *,
        confirmation: str,
        image_digest: str,
    ) -> None:
        self.source_root = source_root.resolve()
        self.workspace = workspace
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_debian_13(
            self.confirmation, self.image_digest
        )
        isolation = _require_network_isolation()
        _prepare_workspace(self.workspace)
        dependencies = _verify_preinstalled_dependencies()
        packages = [
            DebianPackageBuilder(
                self.source_root,
                self.workspace / f"build-r{revision}",
                debian_revision=revision,
            ).build()
            for revision in (1, 2)
        ]
        key = _generate_qualification_key(self.workspace)
        repositories = []
        for revision, package in enumerate(packages, start=1):
            artifact = (
                self.workspace / f"build-r{revision}" / package["artifact"]
            )
            repositories.append(
                _build_repository(
                    self.workspace / f"repository-r{revision}",
                    artifact,
                    package,
                    key,
                )
            )

        signature = _verify_repository_signature(
            self.workspace / "repository-r1", key
        )
        wrong_key = _reject_unpinned_key(
            self.workspace, self.workspace / "repository-r1", packages[0], key
        )
        signature_tamper = _reject_signature_tamper(
            self.workspace, self.workspace / "repository-r1", packages[0], key
        )
        package_tamper = _reject_package_tamper(
            self.workspace, self.workspace / "repository-r1", packages[0], key
        )
        install = _apt_install_revision(
            self.workspace,
            self.workspace / "repository-r1",
            packages[0],
            key,
            phase="install-r1",
        )
        upgrade = _apt_install_revision(
            self.workspace,
            self.workspace / "repository-r2",
            packages[1],
            key,
            phase="upgrade-r2",
            previous_version=packages[0]["debian_version"],
        )
        removal = _apt_remove(
            self.workspace,
            self.workspace / "repository-r2",
            packages[1],
            key,
        )

        checks = [
            _passed("platform.container", {**platform, **isolation}),
            _passed("dependencies.preinstalled", dependencies),
            _passed("signing.ephemeral-key", key["report"]),
            _passed("repository.metadata", {"revisions": repositories}),
            _passed("trust.unpinned-key-rejected", wrong_key),
            _passed("trust.signature-tamper-rejected", signature_tamper),
            _passed("trust.package-tamper-rejected", package_tamper),
            _passed("apt.install", {**install, **signature}),
            _passed("apt.upgrade", upgrade),
            _passed("apt.remove", removal),
        ]
        return {
            "schema_version": 1,
            "status": "apt-repository-qualified",
            "project_version": __version__,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "an ephemeral qualification-only signing key was destroyed with the container; production key custody and rotation were not qualified",
                "the repository used a network-isolated local file URI; HTTPS transport, mirrors, CDN delivery, and availability were not exercised",
                "Debian and Suricata dependencies were authenticated and preinstalled before the network-isolated Meercata repository run",
                "systemd was not PID 1; service startup, crash/reboot recovery, IPS/NFQUEUE, retention, and purge were not exercised",
            ],
        }


def _require_network_isolation() -> dict[str, Any]:
    interface_root = Path("/sys/class/net")
    interfaces = sorted(path.name for path in interface_root.iterdir())
    if interfaces != ["lo"]:
        raise QualificationError("APT repository qualification requires loopback-only networking")
    routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    if any(line.split() for line in routes):
        raise QualificationError("APT repository qualification requires an empty route table")
    return {"network": "none", "interfaces": interfaces}


def _prepare_workspace(path: Path) -> None:
    if not path.is_absolute() or path == Path("/"):
        raise QualificationError("APT repository workspace is unsafe")
    if path.exists() or path.is_symlink():
        raise QualificationError("APT repository workspace must not already exist")
    path.mkdir(mode=0o755)


def _verify_preinstalled_dependencies() -> dict[str, str]:
    expected = {
        "python3": None,
        "sudo": None,
        "systemd": None,
        "suricata": "1:8.0.6-1~bpo13+1",
        "suricata-update": "1.3.8-1~bpo13+1",
    }
    result = _run(
        "dependencies.query",
        (
            DPKG_QUERY,
            "--show",
            "--showformat=${Package}\t${Version}\t${db:Status-Status}\n",
            *expected,
        ),
    )
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] in observed or parts[2] != "installed":
            raise QualificationError("preinstalled dependency query is invalid")
        observed[parts[0]] = parts[1]
    if set(observed) != set(expected):
        raise QualificationError("preinstalled dependencies are incomplete")
    for package, version in expected.items():
        if version is not None and observed[package] != version:
            raise QualificationError("preinstalled dependency version is not approved")
    return observed


def _generate_qualification_key(workspace: Path) -> dict[str, Any]:
    home = workspace / "gnupg"
    home.mkdir(mode=0o700)
    _run(
        "signing.generate",
        (
            GPG,
            "--batch",
            "--homedir",
            str(home),
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            KEY_IDENTITY,
            "rsa3072",
            "sign",
            "8d",
        ),
        timeout=120,
    )
    listing = _run(
        "signing.fingerprint",
        (GPG, "--batch", "--homedir", str(home), "--with-colons", "--list-keys"),
    )
    fingerprints = [
        line.split(":")[9]
        for line in listing.stdout.splitlines()
        if line.startswith("fpr:") and len(line.split(":")) > 9
    ]
    if len(fingerprints) != 1 or _FINGERPRINT.fullmatch(fingerprints[0]) is None:
        raise QualificationError("qualification signing fingerprint is invalid")
    fingerprint = fingerprints[0]
    keyring = workspace / "meercata-qualification-keyring.gpg"
    _run(
        "signing.export",
        (
            GPG,
            "--batch",
            "--homedir",
            str(home),
            "--output",
            str(keyring),
            "--export",
            fingerprint,
        ),
    )
    keyring.chmod(0o644)
    return {
        "home": home,
        "keyring": keyring,
        "fingerprint": fingerprint,
        "report": {
            "identity": KEY_IDENTITY,
            "fingerprint": fingerprint,
            "algorithm": "rsa3072",
            "expires_after": "8d",
            "production_key": False,
        },
    }


def _build_repository(
    root: Path,
    artifact: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    binary = root / f"dists/{SUITE}/{COMPONENT}/binary-{ARCHITECTURE}"
    pool = root / "pool/main/m/meercata"
    binary.mkdir(parents=True, mode=0o755)
    pool.mkdir(parents=True, mode=0o755)
    target = pool / artifact.name
    _copy_new(artifact, target, 0o644)
    package_index = _run(
        f"repository.packages.{package['debian_version']}",
        (APT_FTPARCHIVE, "packages", "pool/main"),
        working_directory=root,
    ).stdout.encode("utf-8")
    packages_path = binary / "Packages"
    _write_new(packages_path, package_index, 0o644)
    compressed = gzip.compress(package_index, compresslevel=9, mtime=0)
    packages_gz = binary / "Packages.gz"
    _write_new(packages_gz, compressed, 0o644)
    for path in (packages_path, packages_gz):
        _write_new(
            binary / "by-hash/SHA256" / _sha256(path),
            path.read_bytes(),
            0o644,
        )
    release = _release_bytes(root / f"dists/{SUITE}")
    release_path = root / f"dists/{SUITE}/Release"
    _write_new(release_path, release, 0o644)
    _sign_release(release_path, key)
    return {
        "debian_version": package["debian_version"],
        "artifact_sha256": package["sha256"],
        "artifact_size": package["size_bytes"],
        "packages_sha256": _sha256(packages_path),
        "packages_gz_sha256": _sha256(packages_gz),
        "release_sha256": _sha256(release_path),
        "inrelease_sha256": _sha256(root / f"dists/{SUITE}/InRelease"),
    }


def _release_bytes(suite_root: Path) -> bytes:
    entries = []
    for relative in (
        Path(f"{COMPONENT}/binary-{ARCHITECTURE}/Packages"),
        Path(f"{COMPONENT}/binary-{ARCHITECTURE}/Packages.gz"),
    ):
        path = suite_root / relative
        data = _read_regular(path, MAX_METADATA_BYTES)
        entries.append(f" {_digest(data)} {len(data):16d} {relative.as_posix()}")
    fields = [
        "Origin: Meercata",
        "Label: Meercata Qualification",
        f"Suite: {SUITE}",
        f"Codename: {SUITE}",
        f"Date: {format_datetime(RELEASE_DATE, usegmt=True)}",
        f"Valid-Until: {format_datetime(VALID_UNTIL, usegmt=True)}",
        f"Architectures: {ARCHITECTURE}",
        f"Components: {COMPONENT}",
        "Acquire-By-Hash: yes",
        "SHA256:",
        *entries,
    ]
    return ("\n".join(fields) + "\n").encode("ascii")


def _sign_release(release: Path, key: Mapping[str, Any]) -> None:
    common = (
        GPG,
        "--batch",
        "--yes",
        "--homedir",
        str(key["home"]),
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--local-user",
        str(key["fingerprint"]),
        "--digest-algo",
        "SHA256",
    )
    _run(
        "signing.detached",
        (*common, "--armor", "--output", str(release.with_name("Release.gpg")), "--detach-sign", str(release)),
    )
    _run(
        "signing.inrelease",
        (*common, "--output", str(release.with_name("InRelease")), "--clearsign", str(release)),
    )
    release.with_name("Release.gpg").chmod(0o644)
    release.with_name("InRelease").chmod(0o644)


def _verify_repository_signature(root: Path, key: Mapping[str, Any]) -> dict[str, Any]:
    authenticated = root / "authenticated-release"
    result = _run(
        "repository.signature",
        (
            SQV,
            "--keyring",
            str(key["keyring"]),
            "--output",
            str(authenticated),
            "--cleartext",
            str(root / f"dists/{SUITE}/InRelease"),
        ),
    )
    fingerprints = result.stdout.splitlines()
    if fingerprints != [key["fingerprint"]]:
        raise QualificationError("authenticated repository signature identity is invalid")
    authenticated_bytes = authenticated.read_bytes()
    release_bytes = (root / f"dists/{SUITE}/Release").read_bytes()
    # sqv's cleartext mode returns the authenticated payload without the final
    # line ending that OpenPGP cleartext signatures require on disk.
    if authenticated_bytes + b"\n" != release_bytes:
        raise QualificationError("authenticated repository release content differs")
    return {
        "authenticated": True,
        "fingerprint": key["fingerprint"],
        "signed_by_pinned_key": True,
    }


def _reject_unpinned_key(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    source = _write_source(
        workspace,
        repository,
        package,
        key,
        "wrong-key",
        signed_by=Path("/usr/share/keyrings/debian-archive-keyring.gpg"),
    )
    result = _apt_expected_failure(workspace, source, "wrong-key", "update")
    if "NO_PUBKEY" not in result.stderr and "not signed" not in result.stderr:
        raise QualificationError("unpinned-key rejection failed for an unexpected reason")
    return {"exit_code": result.return_code, "trusted_override": False}


def _reject_signature_tamper(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    tampered = workspace / "repository-signature-tampered"
    shutil.copytree(repository, tampered)
    inrelease = tampered / f"dists/{SUITE}/InRelease"
    content = inrelease.read_bytes()
    changed = content.replace(b"Origin: Meercata", b"Origin: Xeercata", 1)
    if changed == content:
        raise QualificationError("cannot construct signature-tamper fixture")
    inrelease.write_bytes(changed)
    source = _write_source(workspace, tampered, package, key, "signature-tamper")
    result = _apt_expected_failure(workspace, source, "signature-tamper", "update")
    combined = result.stdout + result.stderr
    if not any(value in combined for value in ("invalid signature", "not signed", "Clearsigned file isn't valid")):
        raise QualificationError("signature-tamper rejection failed for an unexpected reason")
    return {"exit_code": result.return_code, "tampered_metadata_accepted": False}


def _reject_package_tamper(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    tampered = workspace / "repository-package-tampered"
    shutil.copytree(repository, tampered)
    archives = tuple((tampered / "pool").rglob("*.deb"))
    if len(archives) != 1:
        raise QualificationError("package-tamper fixture inventory is invalid")
    payload = bytearray(archives[0].read_bytes())
    payload[-1] ^= 1
    archives[0].write_bytes(payload)
    source = _write_source(workspace, tampered, package, key, "package-tamper")
    _apt_run(workspace, source, "package-tamper", ("update",))
    result = _apt_expected_failure(
        workspace,
        source,
        "package-tamper",
        "--download-only",
        "--yes",
        "install",
        f"meercata={package['debian_version']}",
    )
    combined = result.stdout + result.stderr
    if not any(value in combined for value in ("Hash Sum mismatch", "Hash mismatch", "unexpected size")):
        raise QualificationError("package-tamper rejection failed for an unexpected reason")
    return {"exit_code": result.return_code, "tampered_package_installed": False}


def _apt_install_revision(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
    *,
    phase: str,
    previous_version: str | None = None,
) -> dict[str, Any]:
    source = _write_source(workspace, repository, package, key, phase)
    _apt_run(workspace, source, phase, ("update",))
    if previous_version is not None:
        _require_installed_version(previous_version)
    _apt_run(
        workspace,
        source,
        phase,
        (
            "--yes",
            "--no-install-recommends",
            "install",
            f"meercata={package['debian_version']}",
        ),
        timeout=180,
    )
    _require_installed_version(package["debian_version"])
    manifest = Path("/usr/lib/meercata/package-manifest.json")
    if not manifest.is_file() or json.loads(manifest.read_text())["version"] != __version__:
        raise QualificationError("APT installed package manifest identity is invalid")
    details = {
        "debian_version": package["debian_version"],
        "artifact_sha256": package["sha256"],
        "dependencies_ignored": False,
        "allow_unauthenticated": False,
        "repository_uri_scheme": "file",
    }
    if previous_version is not None:
        details["from"] = previous_version
        details["to"] = package["debian_version"]
    return details


def _apt_remove(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
) -> dict[str, Any]:
    source = _write_source(workspace, repository, package, key, "remove")
    _apt_run(workspace, source, "remove", ("--yes", "remove", "meercata"), timeout=120)
    result = _run(
        "apt.remove.query",
        (
            DPKG_QUERY,
            "--show",
            "--showformat=${db:Status-Status}\n",
            "meercata",
        ),
    )
    if result.stdout.strip() != "config-files":
        raise QualificationError("APT removal left an unexpected package state")
    return {"dpkg_status": "config-files", "protected_data_removed": False}


def _write_source(
    workspace: Path,
    repository: Path,
    package: Mapping[str, Any],
    key: Mapping[str, Any],
    phase: str,
    *,
    signed_by: Path | None = None,
) -> Path:
    source = workspace / f"source-{phase}.sources"
    content = (
        "Types: deb\n"
        f"URIs: {repository.resolve().as_uri()}\n"
        f"Suites: {SUITE}\n"
        f"Components: {COMPONENT}\n"
        f"Architectures: {ARCHITECTURE}\n"
        f"Signed-By: {signed_by or key['keyring']}\n"
        "Enabled: yes\n"
    ).encode("utf-8")
    _write_new(source, content, 0o644)
    return source


def _apt_run(
    workspace: Path,
    source: Path,
    phase: str,
    arguments: tuple[str, ...],
    *,
    timeout: float = 120,
):
    lists, cache = _apt_directories(workspace, phase)
    return _run(
        f"apt.{phase}.{'-'.join(arguments[-2:])}",
        (*_apt_argv(source, lists, cache), *arguments),
        timeout=timeout,
    )


def _apt_expected_failure(
    workspace: Path,
    source: Path,
    phase: str,
    *arguments: str,
):
    lists, cache = _apt_directories(workspace, phase)
    result = _run_raw(
        f"apt.{phase}.expected-failure",
        (*_apt_argv(source, lists, cache), *arguments),
        timeout=120,
    )
    if result.succeeded or result.timed_out or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError("APT trust failure was not rejected cleanly")
    return result


def _apt_directories(workspace: Path, phase: str) -> tuple[Path, Path]:
    lists = workspace / f"apt-lists-{phase}"
    cache = workspace / f"apt-cache-{phase}"
    if not lists.exists():
        (lists / "partial").mkdir(parents=True, mode=0o755)
    if not cache.exists():
        (cache / "partial").mkdir(parents=True, mode=0o755)
    return lists, cache


def _apt_argv(source: Path, lists: Path, cache: Path) -> tuple[str, ...]:
    return (
        APT_GET,
        "-o",
        f"Dir::Etc::sourcelist={source}",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        f"Dir::State::lists={lists}",
        "-o",
        f"Dir::Cache::archives={cache}",
        "-o",
        "APT::Get::List-Cleanup=0",
        "-o",
        "Acquire::AllowInsecureRepositories=false",
        "-o",
        "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o",
        "APT::Get::AllowUnauthenticated=false",
    )


def _require_installed_version(version: str) -> None:
    result = _run(
        "apt.installed.query",
        (
            DPKG_QUERY,
            "--show",
            "--showformat=${db:Status-Status} ${Version}\n",
            "meercata",
        ),
    )
    if result.stdout.strip() != f"installed {version}":
        raise QualificationError("APT installed package status/version is invalid")


def _copy_new(source: Path, target: Path, mode: int) -> None:
    if target.exists() or target.is_symlink():
        raise QualificationError("repository destination already exists")
    content = _read_regular(source, 128 * 1024 * 1024)
    _write_new(target, content, mode)


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def _read_regular(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise QualificationError("repository file is unsafe or oversized")
    return path.read_bytes()


def _sha256(path: Path) -> str:
    return _digest(_read_regular(path, 128 * 1024 * 1024))


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _run(
    command_id: str,
    argv: tuple[str, ...],
    *,
    timeout: float = 60,
    working_directory: Path = Path("/"),
):
    result = _run_raw(
        command_id, argv, timeout=timeout, working_directory=working_directory
    )
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"APT repository command failed: {command_id}")
    return result


def _run_raw(
    command_id: str,
    argv: tuple[str, ...],
    *,
    timeout: float = 60,
    working_directory: Path = Path("/"),
):
    return CommandRunner(
        {
            command_id: CommandDefinition.fixed(
                argv,
                timeout_seconds=timeout,
                working_directory=working_directory,
            )
        },
        max_output_bytes=MAX_OUTPUT_BYTES,
    ).run(command_id)


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.apt_repository_qualifier",
        description="Qualify signed Meercata APT install and upgrade in Debian 13",
    )
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--image-digest", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        report = AptRepositoryQualifier(
            arguments.source_root,
            arguments.workspace,
            confirmation=arguments.confirmation,
            image_digest=arguments.image_digest,
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError, QualificationError) as exc:
        print(f"meercata-apt-repository-qualify: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
