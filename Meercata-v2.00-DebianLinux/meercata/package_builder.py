"""Build and verify a deterministic production filesystem image.

This source-tree utility writes only below an explicit non-root staging directory.
It does not create users, install sudoers, reload systemd, or mutate a live host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence, TextIO

from meercata import __version__
from meercata.errors import PackagingError

MANIFEST_PATH = PurePosixPath("/usr/lib/meercata/package-manifest.json")
MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PackageFile:
    source: Path
    destination: PurePosixPath
    mode: int
    role: str


@dataclass(frozen=True, slots=True)
class PackageDirectory:
    destination: PurePosixPath
    mode: int


class ProductionPackageBuilder:
    """Stage fixed project assets and verify them against a hash-bound inventory."""

    def __init__(self, source_root: Path, stage_root: Path) -> None:
        self.source_root = _safe_source_root(source_root)
        self.stage_root = _safe_stage_root(stage_root, self.source_root)

    def inventory(self) -> tuple[PackageFile, ...]:
        package_sources = sorted((self.source_root / "meercata").glob("*.py"))
        module_names = {source.name for source in package_sources}
        required_modules = {"__init__.py", "cli.py", "privileged_helper.py"}
        if not required_modules <= module_names:
            raise PackagingError("required Python package modules are missing")
        files = [
            PackageFile(
                source.relative_to(self.source_root),
                PurePosixPath("/usr/lib/meercata/python/meercata") / source.name,
                0o644,
                "python-module",
            )
            for source in package_sources
        ]
        fixed = (
            ("packaging/bin/meercata", "/usr/bin/meercata", 0o755, "cli-launcher"),
            (
                "packaging/bin/meercata-helper",
                "/usr/lib/meercata/bin/meercata-helper",
                0o755,
                "privileged-launcher",
            ),
            (
                "packaging/bin/meercata-package-lifecycle",
                "/usr/lib/meercata/bin/meercata-package-lifecycle",
                0o755,
                "package-lifecycle-launcher",
            ),
            (
                "packaging/bin/meercata-ips-engine",
                "/usr/lib/meercata/bin/meercata-ips-engine",
                0o755,
                "ips-lifecycle-launcher",
            ),
            (
                "packaging/bin/meercata-ips-bootstrap",
                "/usr/lib/meercata/bin/meercata-ips-bootstrap",
                0o755,
                "ips-lifecycle-launcher",
            ),
            (
                "packaging/bin/meercata-ips-guard",
                "/usr/lib/meercata/bin/meercata-ips-guard",
                0o755,
                "ips-lifecycle-launcher",
            ),
            (
                "packaging/bin/meercata-systemd-vm-qualifier",
                "/usr/lib/meercata/bin/meercata-systemd-vm-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-ruleops-vm-qualifier",
                "/usr/lib/meercata/bin/meercata-ruleops-vm-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-recovery-vm-qualifier",
                "/usr/lib/meercata/bin/meercata-recovery-vm-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-ips-systemd-vm-qualifier",
                "/usr/lib/meercata/bin/meercata-ips-systemd-vm-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-monitor-qualifier",
                "/usr/lib/meercata/bin/meercata-monitor-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-monitor-delivery-qualifier",
                "/usr/lib/meercata/bin/meercata-monitor-delivery-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-monitor-systemd-vm-qualifier",
                "/usr/lib/meercata/bin/meercata-monitor-systemd-vm-qualifier",
                0o755,
                "qualification-launcher",
            ),
            (
                "packaging/bin/meercata-monitor-tls-qualifier",
                "/usr/lib/meercata/bin/meercata-monitor-tls-qualifier",
                0o755,
                "qualification-launcher",
            ),
            ("packaging/sudoers.d/meercata", "/etc/sudoers.d/meercata", 0o440, "sudoers"),
            (
                "packaging/sysusers.d/meercata.conf",
                "/usr/lib/sysusers.d/meercata.conf",
                0o644,
                "sysusers",
            ),
            (
                "packaging/tmpfiles.d/meercata.conf",
                "/usr/lib/tmpfiles.d/meercata.conf",
                0o644,
                "tmpfiles",
            ),
            (
                "packaging/systemd/system/meercata-health.service",
                "/usr/lib/systemd/system/meercata-health.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-health.timer",
                "/usr/lib/systemd/system/meercata-health.timer",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor.service",
                "/usr/lib/systemd/system/meercata-monitor.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor.timer",
                "/usr/lib/systemd/system/meercata-monitor.timer",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-freshness.service",
                "/usr/lib/systemd/system/meercata-monitor-freshness.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-freshness.timer",
                "/usr/lib/systemd/system/meercata-monitor-freshness.timer",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-delivery.service",
                "/usr/lib/systemd/system/meercata-monitor-delivery.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-delivery.timer",
                "/usr/lib/systemd/system/meercata-monitor-delivery.timer",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-delivery-health.service",
                "/usr/lib/systemd/system/meercata-monitor-delivery-health.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-monitor-delivery-health.timer",
                "/usr/lib/systemd/system/meercata-monitor-delivery-health.timer",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/logrotate.d/meercata-monitor",
                "/etc/logrotate.d/meercata-monitor",
                0o644,
                "logrotate-policy",
            ),
            (
                "packaging/systemd/system/meercata-suricata-ips.service",
                "/usr/lib/systemd/system/meercata-suricata-ips.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-ips-activate.service",
                "/usr/lib/systemd/system/meercata-ips-activate.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-ips-guard.service",
                "/usr/lib/systemd/system/meercata-ips-guard.service",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/meercata-ips.target",
                "/usr/lib/systemd/system/meercata-ips.target",
                0o644,
                "systemd-unit",
            ),
            (
                "packaging/systemd/system/suricata.service.d/50-meercata-production.conf",
                "/usr/lib/systemd/system/suricata.service.d/50-meercata-production.conf",
                0o644,
                "systemd-override",
            ),
            (
                "config/meercata.example.toml",
                "/usr/share/meercata/meercata.example.toml",
                0o644,
                "configuration-example",
            ),
            (
                "packaging/apt/debian-backports.sources",
                "/usr/share/meercata/apt/debian-backports.sources",
                0o644,
                "repository-example",
            ),
            (
                "regression-packs/README.md",
                "/usr/share/doc/meercata/REGRESSION-PACKS.md",
                0o644,
                "documentation",
            ),
            (
                "regression-packs/dev13-ruleops-v1/README.md",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/README.md",
                0o644,
                "regression-pack-provenance",
            ),
            (
                "regression-packs/dev13-ruleops-v1/manifest.json",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/manifest.json",
                0o644,
                "regression-pack-manifest",
            ),
            (
                "regression-packs/dev13-ruleops-v1/payload.hex",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/payload.hex",
                0o644,
                "regression-pack-source",
            ),
            (
                "regression-packs/dev13-ruleops-v1/qualification.pcap",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification.pcap",
                0o644,
                "regression-pack-pcap",
            ),
            (
                "regression-packs/dev13-ruleops-v1/qualification-a.rules",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification-a.rules",
                0o644,
                "qualification-rule-overlay",
            ),
            (
                "regression-packs/dev13-ruleops-v1/qualification-b.rules",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification-b.rules",
                0o644,
                "qualification-rule-overlay",
            ),
            (
                "regression-packs/dev13-ruleops-v1/suricata-offline.yaml",
                "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/suricata-offline.yaml",
                0o644,
                "regression-pack-validation-config",
            ),
            (
                "packaging/debian/copyright",
                "/usr/share/doc/meercata/copyright",
                0o644,
                "copyright",
            ),
        )
        files.extend(
            PackageFile(Path(source), PurePosixPath(destination), mode, role)
            for source, destination, mode, role in fixed
        )
        production_pack_files = (
            ("README.md", "regression-pack-provenance"),
            ("generate.py", "regression-pack-source"),
            ("manifest.json", "regression-pack-manifest"),
            ("suricata-offline.yaml", "regression-pack-validation-config"),
            ("dns-benign.pcap", "regression-pack-pcap"),
            ("dns-scan-positive.pcap", "regression-pack-pcap"),
            ("http-benign.pcap", "regression-pack-pcap"),
            ("http-exploit-positive.pcap", "regression-pack-pcap"),
            ("tcp-response-positive.pcap", "regression-pack-pcap"),
            ("tls-benign.pcap", "regression-pack-pcap"),
            ("udp-remote-positive.pcap", "regression-pack-pcap"),
        )
        files.extend(
            PackageFile(
                Path("regression-packs/production-baseline-v1") / name,
                PurePosixPath(
                    "/usr/lib/meercata/regression-packs/production-baseline-v1"
                )
                / name,
                0o644,
                role,
            )
            for name, role in production_pack_files
        )
        schema_sources = sorted((self.source_root / "schemas").glob("*.json"))
        if {source.name for source in schema_sources} != {
            "apt-repository-qualification-v1.schema.json",
            "container-qualification-v1.schema.json",
            "deb-build-v1.schema.json",
            "debian-lifecycle-qualification-v1.schema.json",
            "health-v1.schema.json",
            "ips-systemd-vm-qualification-v1.schema.json",
            "monitor-v1.schema.json",
            "monitor-delivery-v1.schema.json",
            "monitor-delivery-qualification-v1.schema.json",
            "monitor-freshness-v1.schema.json",
            "monitor-tls-qualification-v1.schema.json",
            "monitor-systemd-vm-qualification-v1.schema.json",
            "monitor-qualification-v1.schema.json",
            "nfqueue-functional-qualification-v1.schema.json",
            "nfqueue-load-qualification-v1.schema.json",
            "nftables-namespace-qualification-v1.schema.json",
            "nftables-transaction-qualification-v1.schema.json",
            "package-manifest-v1.schema.json",
            "qualification-v1.schema.json",
            "recovery-vm-qualification-v1.schema.json",
            "regression-corpus-qualification-v1.schema.json",
            "regression-pack-v1.schema.json",
            "rule-candidate-v1.schema.json",
            "ruleops-vm-qualification-v1.schema.json",
            "suricata-package-qualification-v1.schema.json",
            "systemd-vm-readiness-v1.schema.json",
        }:
            raise PackagingError("production JSON schema inventory is incomplete or unexpected")
        for source in schema_sources:
            files.append(
                PackageFile(
                    source.relative_to(self.source_root),
                    PurePosixPath("/usr/share/meercata/schemas") / source.name,
                    0o644,
                    "json-schema",
                )
            )
        for name in (
            "APT-REPOSITORY.md",
            "README.md",
            "ARCHITECTURE-DECISIONS.md",
            "CHANGELOG.md",
            "HEALTH.md",
            "IPS-SYSTEMD.md",
            "MONITORING.md",
            "MONITOR-SYSTEMD-VM.md",
            "NATIVE-DEBIAN.md",
            "NFQUEUE-FUNCTIONAL.md",
            "NFQUEUE-LOAD.md",
            "NFTABLES-NAMESPACE.md",
            "NFTABLES-TRANSACTIONS.md",
            "PACKAGING.md",
            "PRIVILEGED-HELPER.md",
            "PRIVILEGED-OPERATIONS.md",
            "PRODUCTION-ROADMAP.md",
            "QUALIFICATION.md",
            "RECOVERY-VM.md",
            "RULEOPS.md",
            "RULEOPS-VM.md",
            "SUPERVISION.md",
            "SURICATA-PACKAGES.md",
            "THREAT-MODEL.md",
        ):
            files.append(
                PackageFile(
                    Path(name),
                    PurePosixPath("/usr/share/doc/meercata") / name,
                    0o644,
                    "documentation",
                )
            )
        destinations = [item.destination for item in files]
        if len(destinations) != len(set(destinations)):
            raise PackagingError("package inventory contains duplicate destinations")
        return tuple(sorted(files, key=lambda item: str(item.destination)))

    def directories(self) -> tuple[PackageDirectory, ...]:
        return tuple(
            PackageDirectory(PurePosixPath(path), mode)
            for path, mode in (
                ("/usr/lib/meercata", 0o755),
                ("/usr/lib/meercata/bin", 0o755),
                ("/usr/lib/meercata/python", 0o755),
                ("/usr/lib/meercata/python/meercata", 0o755),
                ("/usr/lib/meercata/regression-packs", 0o755),
                ("/usr/lib/meercata/regression-packs/dev13-ruleops-v1", 0o755),
                ("/usr/lib/meercata/regression-packs/production-baseline-v1", 0o755),
                ("/usr/lib/systemd/system/suricata.service.d", 0o755),
                ("/usr/share/meercata", 0o755),
                ("/usr/share/meercata/apt", 0o755),
                ("/usr/share/meercata/schemas", 0o755),
                ("/usr/share/doc/meercata", 0o755),
            )
        )

    def stage(self) -> dict[str, Any]:
        payloads = self._validated_payloads()
        previous = self._load_manifest(required=False)
        self._preflight_existing(previous, payloads)

        self.stage_root.mkdir(parents=True, exist_ok=True, mode=0o755)
        _reject_symlink(self.stage_root, "staging root")
        for directory in self.directories():
            target = self._target(directory.destination)
            _prepare_directory(
                self.stage_root, target, directory.mode, enforce_mode=True
            )
        for item, content, _digest in payloads:
            target = self._target(item.destination)
            _prepare_directory(
                self.stage_root, target.parent, 0o755, enforce_mode=False
            )
            _atomic_write(target, content, item.mode)

        manifest = self._manifest(payloads)
        manifest_target = self._target(MANIFEST_PATH)
        _atomic_write(
            manifest_target,
            _canonical_json(manifest),
            0o644,
        )
        self._remove_obsolete(previous, manifest)
        self.verify()
        return manifest

    def verify(self) -> dict[str, Any]:
        manifest = self._load_manifest(required=True)
        failures: list[str] = []
        manifest_target = self._target(MANIFEST_PATH)
        if stat.S_IMODE(manifest_target.lstat().st_mode) != 0o644:
            failures.append(f"{MANIFEST_PATH}: mode mismatch")
        for item in manifest["files"]:
            path = self._target(_manifest_path(item["path"]))
            try:
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise PackagingError("not a regular file")
                if stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8):
                    raise PackagingError("mode mismatch")
                if _hash_file(path) != item["sha256"]:
                    raise PackagingError("SHA-256 mismatch")
            except (OSError, PackagingError) as exc:
                failures.append(f"{item['path']}: {exc}")
        for item in manifest["directories"]:
            path = self._target(_manifest_path(item["path"]))
            try:
                metadata = path.lstat()
                if not stat.S_ISDIR(metadata.st_mode):
                    raise PackagingError("not a directory")
                if stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8):
                    raise PackagingError("mode mismatch")
            except (OSError, PackagingError) as exc:
                failures.append(f"{item['path']}: {exc}")
        if failures:
            raise PackagingError("package verification failed: " + "; ".join(failures))
        return {
            "schema_version": 1,
            "status": "verified",
            "version": manifest["version"],
            "verified_files": len(manifest["files"]),
            "verified_directories": len(manifest["directories"]),
        }

    def load_manifest(self) -> dict[str, Any]:
        """Return the validated staged manifest for read-only qualification tooling."""
        manifest = self._load_manifest(required=True)
        assert manifest is not None
        return manifest

    def removal_plan(self) -> dict[str, Any]:
        manifest = self._load_manifest(required=True)
        removable: list[str] = []
        modified: list[str] = []
        missing: list[str] = []
        for item in manifest["files"]:
            path = self._target(_manifest_path(item["path"]))
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                missing.append(item["path"])
                continue
            try:
                matches = stat.S_ISREG(metadata.st_mode) and (
                    _hash_file(path) == item["sha256"]
                )
            except (OSError, PackagingError):
                matches = False
            if not matches:
                modified.append(item["path"])
            else:
                removable.append(item["path"])
        return {
            "schema_version": 1,
            "status": "review-required" if modified else "safe",
            "removable_files": removable,
            "preserve_modified_files": modified,
            "missing_files": missing,
            "remove_manifest_last": str(MANIFEST_PATH),
            "preserve_runtime_roots": [
                "/etc/meercata",
                "/var/lib/meercata",
                "/var/log/meercata",
            ],
        }

    def _validated_payloads(self) -> tuple[tuple[PackageFile, bytes, str], ...]:
        payloads: list[tuple[PackageFile, bytes, str]] = []
        total = 0
        for item in self.inventory():
            source = _source_file(self.source_root, item.source)
            content = source.read_bytes()
            if len(content) > MAX_SOURCE_FILE_BYTES:
                raise PackagingError(f"package source exceeds 4 MiB: {item.source}")
            total += len(content)
            if total > MAX_PACKAGE_BYTES:
                raise PackagingError("package payload exceeds 64 MiB")
            payloads.append((item, content, hashlib.sha256(content).hexdigest()))
        return tuple(payloads)

    def _manifest(
        self, payloads: Iterable[tuple[PackageFile, bytes, str]]
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "package": "meercata",
            "version": __version__,
            "ownership": {"user": "root", "group": "root"},
            "files": [
                {
                    "path": str(item.destination),
                    "sha256": digest,
                    "mode": f"{item.mode:04o}",
                    "role": item.role,
                }
                for item, _content, digest in payloads
            ],
            "directories": [
                {"path": str(item.destination), "mode": f"{item.mode:04o}"}
                for item in self.directories()
            ],
        }

    def _preflight_existing(
        self,
        previous: dict[str, Any] | None,
        payloads: Iterable[tuple[PackageFile, bytes, str]],
    ) -> None:
        old_files = {} if previous is None else {
            item["path"]: item for item in previous["files"]
        }
        new_paths = {str(item.destination) for item, _content, _digest in payloads}
        self._reject_unowned_code(old_files.keys() | new_paths)
        for path_text, item in old_files.items():
            path = self._target(_manifest_path(path_text))
            if not path.exists() and not path.is_symlink():
                continue
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or _hash_file(path) != item["sha256"]:
                raise PackagingError(f"managed file was modified; refusing overwrite: {path_text}")
        for path_text in new_paths - set(old_files):
            path = self._target(_manifest_path(path_text))
            if path.exists() or path.is_symlink():
                raise PackagingError(f"unowned destination already exists: {path_text}")

    def _reject_unowned_code(self, allowed_paths: set[str]) -> None:
        for directory_path in (
            PurePosixPath("/usr/lib/meercata/bin"),
            PurePosixPath("/usr/lib/meercata/python/meercata"),
        ):
            directory = self._target(directory_path)
            try:
                entries = tuple(directory.iterdir())
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise PackagingError(f"cannot inspect package code directory: {exc}") from exc
            for entry in entries:
                package_path = "/" + str(entry.relative_to(self.stage_root))
                if package_path not in allowed_paths:
                    raise PackagingError(
                        f"unowned entry exists in package code directory: {package_path}"
                    )

    def _remove_obsolete(
        self, previous: dict[str, Any] | None, current: dict[str, Any]
    ) -> None:
        if previous is None:
            return
        current_paths = {item["path"] for item in current["files"]}
        for item in previous["files"]:
            if item["path"] in current_paths:
                continue
            path = self._target(_manifest_path(item["path"]))
            try:
                path.unlink()
                _sync_directory(path.parent)
            except FileNotFoundError:
                continue

    def _load_manifest(self, *, required: bool) -> dict[str, Any] | None:
        target = self._target(MANIFEST_PATH)
        try:
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
                raise PackagingError("existing package manifest is unsafe")
            value = json.loads(target.read_bytes())
        except FileNotFoundError:
            if required:
                raise PackagingError("package manifest is missing")
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise PackagingError("package manifest is unreadable or invalid") from exc
        _validate_manifest(value)
        return value

    def _target(self, destination: PurePosixPath) -> Path:
        if not destination.is_absolute() or destination == PurePosixPath("/"):
            raise PackagingError("package destination must be an absolute child path")
        target = self.stage_root.joinpath(*destination.parts[1:])
        if self.stage_root not in target.parents:
            raise PackagingError("package destination escapes the staging root")
        return target


def _safe_source_root(path: Path) -> Path:
    root = path.absolute()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise PackagingError(f"source root is unavailable: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise PackagingError("source root must be a real directory")
    return root.resolve()


def _safe_stage_root(path: Path, source_root: Path) -> Path:
    if not path.is_absolute():
        raise PackagingError("staging root must be absolute")
    root = path.absolute()
    if root == Path("/"):
        raise PackagingError("refusing to use the live filesystem root as staging root")
    if source_root == root or source_root in root.parents or root in source_root.parents:
        raise PackagingError("staging root and source tree must not overlap")
    if root.exists() or root.is_symlink():
        _reject_symlink(root, "staging root")
        if not root.is_dir():
            raise PackagingError("staging root must be a directory")
    return root.resolve(strict=False)


def _source_file(source_root: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise PackagingError("package source path is unsafe")
    path = source_root / relative
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PackagingError(f"package source is unavailable: {relative}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PackagingError(f"package source is not a regular file: {relative}")
    if metadata.st_size > MAX_SOURCE_FILE_BYTES:
        raise PackagingError(f"package source exceeds 4 MiB: {relative}")
    if path.resolve() != path.absolute():
        raise PackagingError(f"package source traverses a symlink: {relative}")
    return path


def _prepare_directory(
    stage_root: Path,
    target: Path,
    final_mode: int,
    *,
    enforce_mode: bool,
) -> None:
    if target == stage_root:
        return
    relative = target.relative_to(stage_root)
    current = stage_root
    target_created = False
    for index, component in enumerate(relative.parts):
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=final_mode if index == len(relative.parts) - 1 else 0o755)
            if index == len(relative.parts) - 1:
                target_created = True
            metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackagingError(f"package directory component is unsafe: {current}")
    if enforce_mode or target_created:
        os.chmod(target, final_mode, follow_symlinks=False)


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode, follow_symlinks=False)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_SOURCE_FILE_BYTES:
                raise PackagingError(f"managed package file exceeds 4 MiB: {path}")
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise PackagingError("package manifest path is invalid")
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise PackagingError("package manifest path is unsafe")
    return path


def _validate_manifest(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "package",
        "version",
        "ownership",
        "files",
        "directories",
    }:
        raise PackagingError("package manifest has invalid keys")
    if value["schema_version"] != 1 or value["package"] != "meercata":
        raise PackagingError("package manifest identity is invalid")
    if (
        not isinstance(value["version"], str)
        or not value["version"]
        or len(value["version"]) > 128
    ):
        raise PackagingError("package manifest version is invalid")
    if value["ownership"] != {"user": "root", "group": "root"}:
        raise PackagingError("package manifest ownership is invalid")
    if not isinstance(value["files"], list) or not isinstance(value["directories"], list):
        raise PackagingError("package manifest inventory is invalid")
    paths: set[str] = set()
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode", "role"}:
            raise PackagingError("package file inventory entry is invalid")
        path = str(_manifest_path(item["path"]))
        if not _allowed_file_path(PurePosixPath(path)):
            raise PackagingError("package file inventory path is outside owned targets")
        if path in paths:
            raise PackagingError("package manifest contains duplicate paths")
        paths.add(path)
        if (
            not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in item["sha256"])
            or item["mode"] not in {"0440", "0644", "0755"}
            or not isinstance(item["role"], str)
            or not item["role"]
            or len(item["role"]) > 64
        ):
            raise PackagingError("package file inventory metadata is invalid")
    directory_paths: set[str] = set()
    allowed_directories = {
        "/usr/lib/meercata",
        "/usr/lib/meercata/bin",
        "/usr/lib/meercata/python",
        "/usr/lib/meercata/python/meercata",
        "/usr/lib/meercata/regression-packs",
        "/usr/lib/meercata/regression-packs/dev13-ruleops-v1",
        "/usr/lib/meercata/regression-packs/production-baseline-v1",
        "/usr/lib/systemd/system/suricata.service.d",
        "/usr/share/meercata",
        "/usr/share/meercata/apt",
        "/usr/share/meercata/schemas",
        "/usr/share/doc/meercata",
    }
    for item in value["directories"]:
        if not isinstance(item, dict) or set(item) != {"path", "mode"}:
            raise PackagingError("package directory inventory entry is invalid")
        path = str(_manifest_path(item["path"]))
        if path not in allowed_directories or path in directory_paths:
            raise PackagingError("package directory inventory path is invalid")
        directory_paths.add(path)
        if item["mode"] != "0755":
            raise PackagingError("package directory mode is invalid")


def _allowed_file_path(path: PurePosixPath) -> bool:
    exact = {
        PurePosixPath("/usr/bin/meercata"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-helper"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-package-lifecycle"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-ips-engine"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-ips-bootstrap"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-ips-guard"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-systemd-vm-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-ruleops-vm-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-recovery-vm-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-ips-systemd-vm-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-monitor-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-monitor-delivery-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-monitor-tls-qualifier"),
        PurePosixPath("/usr/lib/meercata/bin/meercata-monitor-systemd-vm-qualifier"),
        PurePosixPath("/etc/sudoers.d/meercata"),
        PurePosixPath("/usr/lib/sysusers.d/meercata.conf"),
        PurePosixPath("/usr/lib/tmpfiles.d/meercata.conf"),
        PurePosixPath("/usr/lib/systemd/system/meercata-health.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-health.timer"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor.timer"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-freshness.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-freshness.timer"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-delivery.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-delivery.timer"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-delivery-health.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-monitor-delivery-health.timer"),
        PurePosixPath("/etc/logrotate.d/meercata-monitor"),
        PurePosixPath("/usr/lib/systemd/system/meercata-suricata-ips.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-ips-activate.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-ips-guard.service"),
        PurePosixPath("/usr/lib/systemd/system/meercata-ips.target"),
        PurePosixPath(
            "/usr/lib/systemd/system/suricata.service.d/50-meercata-production.conf"
        ),
        PurePosixPath("/usr/share/meercata/meercata.example.toml"),
        PurePosixPath("/usr/share/meercata/apt/debian-backports.sources"),
        PurePosixPath("/usr/share/doc/meercata/REGRESSION-PACKS.md"),
        PurePosixPath("/usr/share/doc/meercata/copyright"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/README.md"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/manifest.json"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/payload.hex"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification.pcap"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification-a.rules"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification-b.rules"),
        PurePosixPath("/usr/lib/meercata/regression-packs/dev13-ruleops-v1/suricata-offline.yaml"),
    }
    if path in exact:
        return True
    production_pack_files = {
        "README.md",
        "generate.py",
        "manifest.json",
        "suricata-offline.yaml",
        "dns-benign.pcap",
        "dns-scan-positive.pcap",
        "http-benign.pcap",
        "http-exploit-positive.pcap",
        "tcp-response-positive.pcap",
        "tls-benign.pcap",
        "udp-remote-positive.pcap",
    }
    if (
        path.parent
        == PurePosixPath("/usr/lib/meercata/regression-packs/production-baseline-v1")
        and path.name in production_pack_files
    ):
        return True
    parent_suffixes = {
        PurePosixPath("/usr/lib/meercata/python/meercata"): ".py",
        PurePosixPath("/usr/share/meercata/schemas"): ".json",
        PurePosixPath("/usr/share/doc/meercata"): ".md",
    }
    return any(
        path.parent == parent and path.name not in {"", ".", ".."} and path.suffix == suffix
        for parent, suffix in parent_suffixes.items()
    )


def _reject_symlink(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PackagingError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise PackagingError(f"{label} must not be a symlink")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.package_builder",
        description="Build or inspect a staged Meercata production filesystem image",
    )
    parser.add_argument("operation", choices=("stage", "verify", "removal-plan"))
    parser.add_argument("stage_root", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
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
        builder = ProductionPackageBuilder(arguments.source_root, arguments.stage_root)
        if arguments.operation == "stage":
            result = builder.stage()
        elif arguments.operation == "verify":
            result = builder.verify()
        else:
            result = builder.removal_plan()
        print(json.dumps(result, sort_keys=True), file=stdout)
        return 0
    except PackagingError as exc:
        print(f"meercata-package: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
