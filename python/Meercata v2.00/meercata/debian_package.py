"""Build and verify a deterministic native Debian binary package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata import __version__
from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import PackagingError
from meercata.package_builder import ProductionPackageBuilder

DPKG_DEB = "/usr/bin/dpkg-deb"
SOURCE_DATE_EPOCH = 1786579200
MAX_DEB_BYTES = 128 * 1024 * 1024
_PROJECT_VERSION = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)\.dev([0-9]+)\Z")
_CONTROL_FIELDS = {
    "Package",
    "Version",
    "Architecture",
    "Maintainer",
    "Installed-Size",
    "Depends",
    "Section",
    "Priority",
    "Description",
}


class DebianPackageBuilder:
    def __init__(
        self,
        source_root: Path,
        output_dir: Path,
        *,
        debian_revision: int = 1,
    ) -> None:
        self.source_root = source_root.resolve()
        self.output_dir = _safe_output_directory(output_dir, self.source_root)
        if type(debian_revision) is not int or not 1 <= debian_revision <= 999:
            raise PackagingError("Debian revision must be an integer from 1 to 999")
        self.debian_revision = debian_revision
        self.debian_version = _debian_version(__version__, debian_revision)
        self.artifact = self.output_dir / f"meercata_{self.debian_version}_all.deb"

    def build(self) -> dict[str, Any]:
        if self.artifact.exists() or self.artifact.is_symlink():
            raise PackagingError("Debian package artifact already exists")
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        with tempfile.TemporaryDirectory(
            prefix=".meercata-deb-build-", dir=self.output_dir
        ) as directory:
            package_root = Path(directory) / "package"
            manifest = ProductionPackageBuilder(
                self.source_root, package_root
            ).stage()
            self._write_native_documentation(package_root)
            self._write_control_area(package_root)
            _normalize_timestamps(package_root, SOURCE_DATE_EPOCH)
            result = CommandRunner(
                {
                    "package.deb.build": CommandDefinition.fixed(
                        (
                            DPKG_DEB,
                            "--root-owner-group",
                            "--uniform-compression",
                            "--threads-max=1",
                            "-Zxz",
                            "-z9",
                            "--build",
                            str(package_root),
                            str(self.artifact),
                        ),
                        timeout_seconds=180,
                        working_directory=self.output_dir,
                        environment={
                            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
                            "DPKG_DEB_THREADS_MAX": "1",
                        },
                    )
                }
            ).run("package.deb.build")
            if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
                raise PackagingError("dpkg-deb failed to build the package")
        verification = self.verify(self.artifact)
        return {
            "schema_version": 1,
            "status": "built-and-verified",
            "project_version": __version__,
            "debian_version": self.debian_version,
            "architecture": "all",
            "artifact": self.artifact.name,
            "sha256": _sha256(self.artifact, MAX_DEB_BYTES),
            "size_bytes": self.artifact.stat().st_size,
            "payload_files": len(manifest["files"]),
            "payload_directories": len(manifest["directories"]),
            "verification": verification,
        }

    def verify(self, artifact: Path) -> dict[str, Any]:
        artifact = artifact.absolute()
        try:
            metadata = artifact.lstat()
        except OSError as exc:
            raise PackagingError("Debian package artifact is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_DEB_BYTES:
            raise PackagingError("Debian package artifact is unsafe or oversized")
        with tempfile.TemporaryDirectory(
            prefix=".meercata-deb-verify-", dir=self.output_dir
        ) as directory:
            root = Path(directory)
            payload = root / "payload"
            control = root / "control"
            payload.mkdir()
            control.mkdir()
            commands = {
                "package.deb.extract": CommandDefinition.fixed(
                    (DPKG_DEB, "--extract", str(artifact), str(payload)),
                    timeout_seconds=60,
                ),
                "package.deb.control": CommandDefinition.fixed(
                    (DPKG_DEB, "--control", str(artifact), str(control)),
                    timeout_seconds=60,
                ),
                "package.deb.contents": CommandDefinition.fixed(
                    (DPKG_DEB, "--contents", str(artifact)),
                    timeout_seconds=60,
                ),
            }
            runner = CommandRunner(commands, max_output_bytes=4 * 1024 * 1024)
            for command_id in ("package.deb.extract", "package.deb.control"):
                result = runner.run(command_id)
                if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
                    raise PackagingError(f"Debian package verification failed: {command_id}")
            contents = runner.run("package.deb.contents")
            if not contents.succeeded or contents.stdout_truncated or contents.stderr_truncated:
                raise PackagingError("Debian package content listing failed")
            _verify_archive_ownership(contents.stdout)
            package_verification = ProductionPackageBuilder(
                self.source_root, payload
            ).verify()
            fields = _parse_control(control / "control")
            _verify_control(fields, self.debian_version)
            _verify_control_area(control, self.source_root)
            _verify_md5sums(control / "md5sums", payload)
            _verify_native_documentation(
                payload, self.source_root, self.debian_version
            )
            return {
                "package": fields["Package"],
                "version": fields["Version"],
                "architecture": fields["Architecture"],
                "root_owned_archive_entries": True,
                "manifest_files": package_verification["verified_files"],
                "maintainer_scripts": 4,
                "active_configuration_included": (
                    payload / "etc/meercata/meercata.toml"
                ).exists(),
            }

    def _write_control_area(self, package_root: Path) -> None:
        control_dir = package_root / "DEBIAN"
        control_dir.mkdir(mode=0o755)
        installed_size = _installed_size_kib(package_root)
        template = _read_source(
            self.source_root / "packaging/debian/control.in", expected_mode=0o644
        ).decode("utf-8")
        control = template.replace("@DEBIAN_VERSION@", self.debian_version).replace(
            "@INSTALLED_SIZE@", str(installed_size)
        )
        if "@DEBIAN_VERSION@" in control or "@INSTALLED_SIZE@" in control or not control.endswith("\n"):
            raise PackagingError("Debian control template substitution failed")
        _write_new(control_dir / "control", control.encode("utf-8"), 0o644)
        for name in ("preinst", "postinst", "prerm", "postrm"):
            content = _read_source(
                self.source_root / "packaging/debian" / name,
                expected_mode=0o755,
            )
            _write_new(control_dir / name, content, 0o755)
        _write_new(
            control_dir / "conffiles",
            b"/etc/sudoers.d/meercata\n",
            0o644,
        )
        lines = []
        for path in sorted(item for item in package_root.rglob("*") if item.is_file()):
            if control_dir == path.parent or control_dir in path.parents:
                continue
            relative = path.relative_to(package_root)
            lines.append(f"{_md5(path)}  {relative.as_posix()}")
        _write_new(
            control_dir / "md5sums",
            ("\n".join(lines) + "\n").encode("ascii"),
            0o644,
        )

    def _write_native_documentation(self, package_root: Path) -> None:
        changelog_template = _read_source(
            self.source_root / "packaging/debian/changelog.in",
            expected_mode=0o644,
        ).decode("utf-8")
        changelog = changelog_template.replace(
            "@DEBIAN_VERSION@", self.debian_version
        )
        if "@DEBIAN_VERSION@" in changelog or not changelog.endswith("\n"):
            raise PackagingError("Debian changelog substitution failed")
        changelog_target = (
            package_root / "usr/share/doc/meercata/changelog.Debian.gz"
        )
        _write_new(
            changelog_target,
            gzip.compress(
                changelog.encode("utf-8"),
                compresslevel=9,
                mtime=SOURCE_DATE_EPOCH,
            ),
            0o644,
        )
        man_source = _read_source(
            self.source_root / "packaging/debian/meercata.1",
            expected_mode=0o644,
        )
        man_target = package_root / "usr/share/man/man1/meercata.1.gz"
        man_target.parent.mkdir(parents=True, mode=0o755)
        _write_new(
            man_target,
            gzip.compress(man_source, compresslevel=9, mtime=SOURCE_DATE_EPOCH),
            0o644,
        )


def _debian_version(project_version: str, revision: int = 1) -> str:
    if type(revision) is not int or not 1 <= revision <= 999:
        raise PackagingError("Debian revision must be an integer from 1 to 999")
    match = _PROJECT_VERSION.fullmatch(project_version)
    if match is None:
        raise PackagingError("project version cannot be mapped to a Debian version")
    return f"{match.group(1)}~dev{match.group(2)}-{revision}"


def _safe_output_directory(path: Path, source_root: Path) -> Path:
    if not path.is_absolute():
        raise PackagingError("Debian package output directory must be absolute")
    output = path.absolute().resolve(strict=False)
    if output == Path("/") or output == source_root or source_root in output.parents:
        raise PackagingError("Debian package output must not be the source tree or root")
    if output.exists() or output.is_symlink():
        try:
            metadata = output.lstat()
        except OSError as exc:
            raise PackagingError("cannot inspect Debian package output") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackagingError("Debian package output must be a real directory")
    return output


def _read_source(path: Path, *, expected_mode: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PackagingError(f"Debian package source is unavailable: {path.name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_size > 1024 * 1024
    ):
        raise PackagingError(f"Debian package source is unsafe: {path.name}")
    return path.read_bytes()


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


def _installed_size_kib(root: Path) -> int:
    total = sum(item.stat().st_size for item in root.rglob("*") if item.is_file())
    return max(1, (total + 1023) // 1024)


def _normalize_timestamps(root: Path, epoch: int) -> None:
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for path in paths:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def _parse_control(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PackagingError("Debian control file cannot be read") from exc
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if line.startswith((" ", "\t")):
            if current is None:
                raise PackagingError("Debian control continuation is invalid")
            fields[current] += "\n" + line
            continue
        if ": " not in line:
            raise PackagingError("Debian control field is invalid")
        key, value = line.split(": ", 1)
        if key in fields or key not in _CONTROL_FIELDS or not value:
            raise PackagingError("Debian control fields are invalid")
        fields[key] = value
        current = key
    if set(fields) != _CONTROL_FIELDS:
        raise PackagingError("Debian control fields are incomplete")
    return fields


def _verify_control(fields: Mapping[str, str], expected_version: str) -> None:
    if (
        fields["Package"] != "meercata"
        or fields["Version"] != expected_version
        or fields["Architecture"] != "all"
        or fields["Priority"] != "optional"
        or fields["Section"] != "admin"
        or "suricata (>= 8.0)" not in fields["Depends"]
        or "suricata-update (>= 1.3.8)" not in fields["Depends"]
        or not fields["Installed-Size"].isdigit()
    ):
        raise PackagingError("Debian control identity or dependency policy is invalid")


def _verify_control_area(control: Path, source_root: Path) -> None:
    allowed = {
        "control",
        "conffiles",
        "md5sums",
        "preinst",
        "postinst",
        "prerm",
        "postrm",
    }
    if {item.name for item in control.iterdir()} != allowed:
        raise PackagingError("Debian control archive contains unexpected files")
    for name in ("preinst", "postinst", "prerm", "postrm"):
        installed = control / name
        source = source_root / "packaging/debian" / name
        if (
            stat.S_IMODE(installed.stat().st_mode) != 0o755
            or installed.read_bytes() != source.read_bytes()
        ):
            raise PackagingError("Debian maintainer script differs from reviewed source")
    if (control / "conffiles").read_text(encoding="utf-8") != (
        "/etc/sudoers.d/meercata\n"
    ):
        raise PackagingError("Debian conffiles policy is invalid")


def _verify_native_documentation(
    payload: Path, source_root: Path, debian_version: str
) -> None:
    changelog = payload / "usr/share/doc/meercata/changelog.Debian.gz"
    manual = payload / "usr/share/man/man1/meercata.1.gz"
    try:
        changelog_value = gzip.decompress(changelog.read_bytes()).decode("utf-8")
        manual_value = gzip.decompress(manual.read_bytes())
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise PackagingError("native Debian documentation is invalid") from exc
    expected_changelog = _read_source(
        source_root / "packaging/debian/changelog.in", expected_mode=0o644
    ).decode("utf-8").replace("@DEBIAN_VERSION@", debian_version)
    expected_manual = _read_source(
        source_root / "packaging/debian/meercata.1", expected_mode=0o644
    )
    if changelog_value != expected_changelog or manual_value != expected_manual:
        raise PackagingError("native Debian documentation differs from reviewed source")


def _verify_md5sums(path: Path, payload: Path) -> None:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise PackagingError("Debian md5sums cannot be read") from exc
    expected_files = sorted(
        item.relative_to(payload).as_posix()
        for item in payload.rglob("*")
        if item.is_file()
    )
    observed: list[str] = []
    for line in lines:
        if len(line) < 35 or line[32:34] != "  ":
            raise PackagingError("Debian md5sums entry is invalid")
        digest, relative = line[:32], line[34:]
        target = payload / relative
        if (
            any(character not in "0123456789abcdef" for character in digest)
            or not target.is_file()
            or _md5(target) != digest
        ):
            raise PackagingError("Debian md5sums verification failed")
        observed.append(relative)
    if sorted(observed) != expected_files:
        raise PackagingError("Debian md5sums inventory is incomplete")


def _verify_archive_ownership(listing: str) -> None:
    lines = [line for line in listing.splitlines() if line.strip()]
    if not lines or any(" root/root " not in line for line in lines):
        raise PackagingError("Debian archive does not use root/root ownership")


def _sha256(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > limit:
                raise PackagingError("Debian package artifact exceeds size limit")
            digest.update(chunk)
    return digest.hexdigest()


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.debian_package",
        description="Build a deterministic verified Meercata Debian binary package",
    )
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--revision", type=int, default=1)
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
        report = DebianPackageBuilder(
            arguments.source_root,
            arguments.output_dir,
            debian_revision=arguments.revision,
        ).build()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError) as exc:
        print(f"meercata-deb: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
