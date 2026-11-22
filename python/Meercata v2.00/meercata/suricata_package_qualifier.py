"""Qualify official Debian 13 Backports Suricata packages and Meercata install."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.container_qualifier import _require_disposable_debian_13
from meercata.debian_package import DebianPackageBuilder
from meercata.errors import PackagingError, QualificationError

SURICATA_DEBIAN_VERSION = "1:8.0.6-1~bpo13+1"
SURICATA_RUNTIME_VERSION = "8.0.6"
SURICATA_UPDATE_DEBIAN_VERSION = "1.3.8-1~bpo13+1"
BACKPORTS_SOURCE = Path("/etc/apt/sources.list.d/debian-backports.sources")
BACKPORTS_INRELEASE = Path(
    "/var/lib/apt/lists/deb.debian.org_debian_dists_"
    "trixie-backports_InRelease"
)
DEBIAN_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_FILE_BYTES = 128 * 1024 * 1024
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPTIONAL_MISSING_PREFIXES = (
    PurePosixPath("usr/share/doc"),
    PurePosixPath("usr/share/man"),
    PurePosixPath("usr/share/lintian"),
)


class SuricataPackageQualifier:
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
        _prepare_workspace(self.workspace)
        source = _verify_backports_source(self.source_root, self.workspace)
        packages = _verify_packages()
        integrity = {
            package: _verify_package_integrity(package)
            for package in ("suricata", "suricata-update")
        }
        runtime = _verify_suricata_runtime()
        configuration = _verify_suricata_configuration(self.workspace)
        meercata = _install_and_remove_meercata(
            self.source_root, self.workspace, packages
        )
        checks = [
            _passed("platform.container", platform),
            _passed("apt.source", source),
            _passed("packages.installed", packages),
            _passed("packages.integrity", integrity),
            _passed("suricata.capabilities", runtime),
            _passed("suricata.configuration", configuration),
            _passed("meercata.install", meercata["install"]),
            _passed("meercata.remove", meercata["remove"]),
        ]
        return {
            "schema_version": 1,
            "status": "suricata-package-qualified",
            "project_version": __version__,
            "platform": platform,
            "checks": checks,
            "limitations": [
                "the signed Debian packages were provisioned before the network-disabled qualification run",
                "systemd unit syntax was verified but systemd was not PID 1 and Suricata was not started",
                "IDS/IPS traffic, Unix-socket commands, rule reload, nftables, NFQUEUE, crash, and reboot behavior were not exercised",
                "the Meercata package was unsigned and installed directly with dpkg after its dependencies were satisfied",
            ],
        }


def _prepare_workspace(path: Path) -> None:
    if not path.is_absolute() or path == Path("/"):
        raise QualificationError("Suricata package workspace is unsafe")
    if path.exists() or path.is_symlink():
        raise QualificationError("Suricata package workspace must not already exist")
    path.mkdir(mode=0o700)


def _verify_backports_source(source_root: Path, workspace: Path) -> dict[str, Any]:
    reviewed = source_root / "packaging/apt/debian-backports.sources"
    expected = _read_regular(reviewed, 4096, expected_mode=0o644)
    installed = _read_regular(BACKPORTS_SOURCE, 4096, expected_mode=0o644)
    if installed != expected:
        raise QualificationError("Debian Backports source differs from reviewed policy")
    keyring_target = DEBIAN_KEYRING.resolve(strict=True)
    if (
        keyring_target.parent != Path("/usr/share/keyrings")
        or not stat.S_ISREG(keyring_target.stat().st_mode)
        or keyring_target.stat().st_uid != 0
        or keyring_target.stat().st_gid != 0
    ):
        raise QualificationError("Debian archive keyring is unsafe")
    inrelease = _read_regular(BACKPORTS_INRELEASE, MAX_METADATA_BYTES)
    authenticated = workspace / "authenticated-release"
    result = _run(
        "apt.inrelease-signature",
        (
            "/usr/bin/sqv",
            "--keyring",
            str(DEBIAN_KEYRING),
            "--output",
            str(authenticated),
            "--cleartext",
            str(BACKPORTS_INRELEASE),
        ),
    )
    fingerprints = result.stdout.splitlines()
    if not 1 <= len(fingerprints) <= 4 or any(
        _FINGERPRINT.fullmatch(value) is None for value in fingerprints
    ):
        raise QualificationError("Debian Backports signature identity is invalid")
    release = _parse_release(_read_regular(authenticated, MAX_METADATA_BYTES))
    expected_release = {
        "Origin": "Debian Backports",
        "Label": "Debian Backports",
        "Suite": "stable-backports",
        "Codename": "trixie-backports",
        "NotAutomatic": "yes",
        "ButAutomaticUpgrades": "yes",
        "Acquire-By-Hash": "yes",
    }
    if any(release.get(key) != value for key, value in expected_release.items()):
        raise QualificationError("authenticated Debian Backports release is invalid")
    release_date, valid_until = _require_release_validity(release)
    return {
        "suite": "trixie-backports",
        "component": "main",
        "uri": "http://deb.debian.org/debian",
        "signed_by": str(DEBIAN_KEYRING),
        "signatures": sorted(fingerprints),
        "inrelease_sha256": hashlib.sha256(inrelease).hexdigest(),
        "release_date": release_date,
        "valid_until": valid_until,
    }


def _verify_packages() -> dict[str, Any]:
    expected = {
        "suricata": SURICATA_DEBIAN_VERSION,
        "suricata-update": SURICATA_UPDATE_DEBIAN_VERSION,
    }
    result = _run(
        "packages.query",
        (
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${Package} ${Version} ${Architecture} "
            "${db:Status-Status}\\n",
            "suricata",
            "suricata-update",
        ),
    )
    observed: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[0] in observed:
            raise QualificationError("installed Suricata package query is invalid")
        name, version, architecture, status_value = parts
        observed[name] = {
            "version": version,
            "architecture": architecture,
            "status": status_value,
        }
    if set(observed) != set(expected):
        raise QualificationError("required Suricata packages are incomplete")
    metadata: dict[str, Any] = {}
    for name, version in expected.items():
        item = observed[name]
        if (
            item["version"] != version
            or item["architecture"] not in {"amd64", "all"}
            or item["status"] != "installed"
        ):
            raise QualificationError("installed Suricata package identity is invalid")
        archive = _apt_package_metadata(name, version)
        metadata[name] = {**item, **archive}
    return metadata


def _apt_package_metadata(name: str, version: str) -> dict[str, Any]:
    result = _run(
        f"apt.metadata.{name}",
        ("/usr/bin/apt-cache", "show", f"{name}={version}"),
    )
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line or line[0].isspace() or ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in {"Package", "Version", "Architecture", "Filename", "Size", "SHA256"}:
            if key in fields:
                raise QualificationError("APT package metadata contains duplicates")
            fields[key] = value
    required = {"Package", "Version", "Architecture", "Filename", "Size", "SHA256"}
    if (
        set(fields) != required
        or fields["Package"] != name
        or fields["Version"] != version
        or not fields["Filename"].startswith("pool/main/")
        or not fields["Size"].isdigit()
        or not 1 <= int(fields["Size"]) <= MAX_PACKAGE_FILE_BYTES
        or _SHA256.fullmatch(fields["SHA256"]) is None
    ):
        raise QualificationError("APT package metadata is invalid")
    return {
        "repository_filename": fields["Filename"],
        "repository_size": int(fields["Size"]),
        "repository_sha256": fields["SHA256"],
    }


def _verify_package_integrity(package: str) -> dict[str, int]:
    path = Path(f"/var/lib/dpkg/info/{package}.md5sums")
    content = _read_regular(path, MAX_METADATA_BYTES).decode("ascii")
    required = {
        "suricata": {
            PurePosixPath("usr/bin/suricata"),
            PurePosixPath("usr/lib/systemd/system/suricata.service"),
        },
        "suricata-update": {PurePosixPath("usr/bin/suricata-update")},
    }[package]
    observed: set[PurePosixPath] = set()
    verified = 0
    optional_missing = 0
    for line in content.splitlines():
        if len(line) < 35 or line[32:34] != "  ":
            raise QualificationError("dpkg package checksum entry is invalid")
        digest, relative_value = line[:32], line[34:]
        relative = PurePosixPath(relative_value)
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or relative.is_absolute()
            or ".." in relative.parts
            or relative in observed
        ):
            raise QualificationError("dpkg package checksum inventory is invalid")
        observed.add(relative)
        target = Path("/") / relative
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            if any(prefix == relative or prefix in relative.parents for prefix in _OPTIONAL_MISSING_PREFIXES):
                optional_missing += 1
                continue
            raise QualificationError("required Suricata package file is missing")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or _md5(target) != digest
        ):
            raise QualificationError("Suricata package file integrity failed")
        verified += 1
    if not required <= observed:
        raise QualificationError("Suricata package checksum inventory is incomplete")
    return {"verified_files": verified, "optional_missing_files": optional_missing}


def _verify_suricata_runtime() -> dict[str, Any]:
    version = _run("suricata.version", ("/usr/bin/suricata", "-V"))
    expected = f"This is Suricata version {SURICATA_RUNTIME_VERSION} RELEASE"
    if version.stdout.strip() != expected:
        raise QualificationError("Suricata runtime version is invalid")
    build = _run("suricata.build-info", ("/usr/bin/suricata", "--build-info"))
    required = {
        "AF_PACKET support:": "yes",
        "NFQueue support:": "yes",
        "Unix socket enabled:": "yes",
        "Detection enabled:": "yes",
        "Systemd support:": "yes",
        "GCC march native enabled:": "no",
        "Installation prefix:": "/usr",
        "Configuration directory:": "/etc/suricata/",
    }
    parsed = _parse_build_info(build.stdout)
    if any(parsed.get(key) != value for key, value in required.items()):
        raise QualificationError("Suricata required build capability is missing")
    update = _run(
        "suricata-update.version", ("/usr/bin/suricata-update", "--version")
    )
    if update.stdout.strip() != "suricata-update version 1.3.8":
        raise QualificationError("suricata-update runtime version is invalid")
    return {
        "suricata_version": SURICATA_RUNTIME_VERSION,
        "suricata_update_version": "1.3.8",
        "af_packet": True,
        "nfqueue": True,
        "unix_socket": True,
        "detection": True,
        "systemd_notify": True,
        "portable_march": True,
    }


def _parse_build_info(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in value.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, item = stripped.split(":", 1)
        normalized = key + ":"
        if normalized in result:
            continue
        result[normalized] = item.strip()
    return result


def _verify_suricata_configuration(workspace: Path) -> dict[str, Any]:
    rule = workspace / "qualification.rules"
    _write_new(
        rule,
        b'alert icmp any any -> any any (msg:"Meercata qualification"; '
        b"sid:9900001; rev:1;)\n",
        0o644,
    )
    log_directory = workspace / "suricata-log"
    log_directory.mkdir(mode=0o700)
    _run(
        "suricata.configuration",
        (
            "/usr/bin/suricata",
            "-T",
            "-c",
            "/etc/suricata/suricata.yaml",
            "-S",
            str(rule),
            "--init-errors-fatal",
            "-l",
            str(log_directory),
        ),
        timeout=120,
    )
    unit = _read_regular(
        Path("/usr/lib/systemd/system/suricata.service"), 64 * 1024
    ).decode("utf-8")
    required_unit_lines = {
        "Type=notify",
        "ExecStart=/usr/bin/suricata -D --af-packet -c "
        "/etc/suricata/suricata.yaml --pidfile "
        "/var/run/suricata/suricata.pid",
        "WantedBy=multi-user.target",
    }
    if not required_unit_lines <= set(unit.splitlines()):
        raise QualificationError("Suricata base systemd unit policy is invalid")
    return {"strict_configuration_test": True, "base_systemd_unit_reviewed": True}


def _install_and_remove_meercata(
    source_root: Path,
    workspace: Path,
    packages: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    configuration = Path("/etc/suricata/suricata.yaml")
    configuration_before = _sha256_file(configuration)
    binary_before = _sha256_file(Path("/usr/bin/suricata"))
    report = DebianPackageBuilder(source_root, workspace / "meercata-deb").build()
    artifact = workspace / "meercata-deb" / report["artifact"]
    _run("meercata.install", ("/usr/bin/dpkg", "--install", str(artifact)), timeout=120)
    installed = _run(
        "meercata.query",
        (
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${db:Status-Status} ${Version}\\n",
            "meercata",
        ),
    )
    if installed.stdout.strip() != f"installed {report['debian_version']}":
        raise QualificationError("Meercata dependency-satisfied install is invalid")
    version = _run("meercata.version", ("/usr/bin/meercata", "--version"))
    if version.stdout.strip() != f"meercata {__version__}":
        raise QualificationError("installed Meercata version is invalid")
    _run(
        "meercata.combined-systemd-units",
        (
            "/usr/bin/systemd-analyze",
            "verify",
            "--man=no",
            "suricata.service",
            "meercata-health.service",
            "meercata-health.timer",
        ),
    )
    install = {
        "debian_version": report["debian_version"],
        "artifact_sha256": report["sha256"],
        "dependencies_ignored": False,
        "suricata_version": packages["suricata"]["version"],
        "suricata_update_version": packages["suricata-update"]["version"],
        "combined_systemd_units_verified": 3,
    }
    _run("meercata.remove", ("/usr/bin/dpkg", "--remove", "meercata"), timeout=120)
    query = _run_allow_failure(
        "meercata.removed-query",
        (
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${db:Status-Status}\\n",
            "meercata",
        ),
    )
    if (
        not query.succeeded
        or query.stdout.strip() != "config-files"
        or Path("/usr/bin/meercata").exists()
        or Path("/etc/sudoers.d/meercata").exists()
    ):
        raise QualificationError("Meercata removal did not remove the package")
    if (
        _sha256_file(configuration) != configuration_before
        or _sha256_file(Path("/usr/bin/suricata")) != binary_before
    ):
        raise QualificationError("Meercata lifecycle changed Suricata-owned files")
    after = _verify_packages()
    if after != packages:
        raise QualificationError("Meercata removal changed Suricata packages")
    remove = {
        "meercata_removed": True,
        "dpkg_status": "config-files",
        "suricata_packages_preserved": 2,
        "suricata_configuration_preserved": True,
        "suricata_binary_preserved": True,
    }
    return {"install": install, "remove": remove}


def _parse_release(value: bytes) -> dict[str, str]:
    try:
        lines = value.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise QualificationError("authenticated release metadata is not UTF-8") from exc
    result: dict[str, str] = {}
    for line in lines:
        if line == "SHA256:":
            break
        if ": " not in line:
            continue
        key, item = line.split(": ", 1)
        if key in result:
            raise QualificationError("authenticated release metadata has duplicates")
        result[key] = item
    return result


def _require_release_validity(
    release: Mapping[str, str], *, now: datetime | None = None
) -> tuple[str, str]:
    try:
        release_date = parsedate_to_datetime(release["Date"])
        valid_until = parsedate_to_datetime(release["Valid-Until"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QualificationError("authenticated release validity is invalid") from exc
    if release_date.tzinfo is None or valid_until.tzinfo is None:
        raise QualificationError("authenticated release validity lacks timezone")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise QualificationError("qualification clock lacks timezone")
    if not release_date <= current < valid_until:
        raise QualificationError("authenticated release metadata is expired or future-dated")
    if not 0 < (valid_until - release_date).total_seconds() <= 14 * 24 * 60 * 60:
        raise QualificationError("authenticated release validity window is unsafe")
    return release["Date"], release["Valid-Until"]


def _read_regular(path: Path, limit: int, *, expected_mode: int | None = None) -> bytes:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise QualificationError(f"required qualification file is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not 0 <= metadata.st_size <= limit
        or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
    ):
        raise QualificationError(f"required qualification file is unsafe: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise QualificationError(f"required qualification file cannot be read: {path}") from exc


def _write_new(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, mode, follow_symlinks=False)


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_PACKAGE_FILE_BYTES:
                raise QualificationError("Suricata package file exceeds verification limit")
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command_id: str, argv: tuple[str, ...], *, timeout: float = 60):
    result = _run_allow_failure(command_id, argv, timeout=timeout)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"Suricata package command failed: {command_id}")
    return result


def _run_allow_failure(
    command_id: str, argv: tuple[str, ...], *, timeout: float = 60
):
    return CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=timeout)},
        max_output_bytes=4 * 1024 * 1024,
    ).run(command_id)


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.suricata_package_qualifier",
        description="Qualify pinned Debian 13 Backports Suricata packages",
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
        report = SuricataPackageQualifier(
            arguments.source_root,
            arguments.workspace,
            confirmation=arguments.confirmation,
            image_digest=arguments.image_digest,
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError, QualificationError) as exc:
        print(f"meercata-suricata-package-qualify: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
