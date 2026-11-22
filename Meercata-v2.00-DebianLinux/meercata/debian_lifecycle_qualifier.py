"""Exercise native package install, upgrade, rejection, and removal in Debian 13."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.container_qualifier import (
    DEBIAN_13_IMAGE_DIGEST,
    _require_disposable_debian_13,
)
from meercata.debian_package import DebianPackageBuilder
from meercata.errors import PackagingError, QualificationError

DPKG = "/usr/bin/dpkg"
DPKG_QUERY = "/usr/bin/dpkg-query"
PROTECTED_ROOTS = (
    Path("/etc/meercata"),
    Path("/var/lib/meercata"),
    Path("/var/log/meercata"),
)


class DebianLifecycleQualifier:
    def __init__(
        self,
        source_root: Path,
        workspace: Path,
        *,
        confirmation: str,
        image_digest: str,
    ) -> None:
        self.source_root = source_root
        self.workspace = workspace
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_debian_13(
            self.confirmation, self.image_digest
        )
        _prepare_workspace(self.workspace)
        sentinels = _prepare_protected_data()
        packages = [
            DebianPackageBuilder(
                self.source_root,
                self.workspace / f"revision-{revision}",
                debian_revision=revision,
            ).build()
            for revision in (1, 2, 3)
        ]
        checks = [
            _passed("platform.container", platform),
            _passed(
                "deb.build",
                {
                    "artifacts": len(packages),
                    "architecture": "all",
                    "revisions": [item["debian_version"] for item in packages],
                    "sha256": [item["sha256"] for item in packages],
                    "payload_files": packages[0]["payload_files"],
                    "payload_directories": packages[0]["payload_directories"],
                },
            ),
        ]

        first_path = self.workspace / "revision-1" / packages[0]["artifact"]
        second_path = self.workspace / "revision-2" / packages[1]["artifact"]
        third_path = self.workspace / "revision-3" / packages[2]["artifact"]
        _dpkg_install(first_path)
        _require_installed_version(packages[0]["debian_version"])
        install = _verify_installed_state()
        checks.append(_passed("deb.install", install))

        _run(
            "deb.postinst-idempotent",
            (
                "/var/lib/dpkg/info/meercata.postinst",
                "configure",
                packages[0]["debian_version"],
            ),
        )
        _require_installed_version(packages[0]["debian_version"])
        checks.append(_passed("deb.configure-idempotent", {"repeated": True}))

        _dpkg_install(second_path)
        _require_installed_version(packages[1]["debian_version"])
        checks.append(
            _passed(
                "deb.upgrade",
                {
                    "from": packages[0]["debian_version"],
                    "to": packages[1]["debian_version"],
                },
            )
        )

        cli = Path("/usr/bin/meercata")
        original = cli.read_bytes()
        original_mode = stat.S_IMODE(cli.stat().st_mode)
        cli.write_text("externally modified\n", encoding="utf-8")
        failed = _run_expected_failure(
            "deb.modified-upgrade",
            (
                DPKG,
                "--ignore-depends=suricata",
                "--install",
                str(third_path),
            ),
        )
        if cli.read_text(encoding="utf-8") != "externally modified\n":
            raise QualificationError("failed upgrade overwrote the modified managed file")
        _require_installed_version(packages[1]["debian_version"])
        _restore_root_file(cli, original, original_mode)
        checks.append(
            _passed(
                "deb.modified-upgrade-rejected",
                {"exit_code": failed.return_code, "installed_version_preserved": True},
            )
        )

        _run("deb.remove", (DPKG, "--remove", "meercata"), timeout=120)
        removal = _verify_removed_state(sentinels)
        checks.append(_passed("deb.remove", removal))

        return {
            "schema_version": 1,
            "status": "debian-lifecycle-qualified",
            "package": "meercata",
            "project_version": packages[0]["project_version"],
            "platform": platform,
            "checks": checks,
            "limitations": [
                "the package is unsigned and was installed directly with dpkg",
                "the Suricata dependency was ignored because no live Suricata daemon was installed",
                "systemd was not PID 1, so daemon reload, unit enablement, timer execution, and restart behavior were not exercised",
                "purge was not exercised because Meercata intentionally has no automatic data/config purge contract",
            ],
        }


def _prepare_workspace(path: Path) -> None:
    if not path.is_absolute() or path == Path("/"):
        raise QualificationError("Debian lifecycle workspace is unsafe")
    if path.exists() or path.is_symlink():
        raise QualificationError("Debian lifecycle workspace must not already exist")
    path.mkdir(mode=0o700)


def _prepare_protected_data() -> dict[Path, bytes]:
    result: dict[Path, bytes] = {}
    for root in PROTECTED_ROOTS:
        root.mkdir(parents=True, exist_ok=True)
        sentinel = root / ".deb-lifecycle-preserve"
        content = f"preserve:{root}\n".encode()
        descriptor = os.open(
            sentinel,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        result[sentinel] = content
    return result


def _dpkg_install(artifact: Path) -> None:
    _run(
        "deb.install",
        (
            DPKG,
            "--ignore-depends=suricata",
            "--install",
            str(artifact),
        ),
        timeout=120,
    )


def _require_installed_version(version: str) -> None:
    result = _run(
        "deb.query",
        (
            DPKG_QUERY,
            "--show",
            "--showformat=${db:Status-Status} ${Version}\\n",
            "meercata",
        ),
    )
    if result.stdout.strip() != f"installed {version}":
        raise QualificationError("installed Debian package status/version is invalid")


def _verify_installed_state() -> dict[str, Any]:
    required = {
        Path("/usr/bin/meercata"),
        Path("/usr/lib/meercata/bin/meercata-helper"),
        Path("/usr/lib/meercata/bin/meercata-package-lifecycle"),
        Path("/etc/sudoers.d/meercata"),
    }
    for path in required:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0:
            raise QualificationError("native package installed an unsafe required artifact")
    if Path("/etc/meercata/meercata.toml").exists():
        raise QualificationError("native package installed active configuration")
    enabled_links = tuple(Path("/etc/systemd/system").glob("**/meercata-health.timer"))
    if enabled_links:
        raise QualificationError("native package enabled the health timer automatically")
    if not Path("/var/lib/meercata/privileged").is_dir():
        raise QualificationError("native package did not create privileged state")
    return {
        "required_root_files": len(required),
        "active_configuration_installed": False,
        "health_timer_enabled": False,
    }


def _restore_root_file(path: Path, content: bytes, mode: int) -> None:
    path.write_bytes(content)
    path.chmod(mode)
    os.chown(path, 0, 0, follow_symlinks=False)


def _verify_removed_state(sentinels: Mapping[Path, bytes]) -> dict[str, Any]:
    absent = (
        Path("/usr/bin/meercata"),
        Path("/usr/lib/meercata/bin/meercata-helper"),
        Path("/usr/lib/meercata/bin/meercata-package-lifecycle"),
        Path("/etc/sudoers.d/meercata"),
        Path("/usr/lib/systemd/system/meercata-health.timer"),
    )
    if any(path.exists() or path.is_symlink() for path in absent):
        raise QualificationError("native package removal left a privileged artifact")
    for path, content in sentinels.items():
        if path.read_bytes() != content:
            raise QualificationError("native package removal changed protected data")
    return {
        "privileged_artifacts_absent": len(absent),
        "preserved_data_roots": len(sentinels),
        "service_identity_preserved": "meercata" in Path("/etc/passwd").read_text(),
    }


def _run(
    command_id: str,
    argv: tuple[str, ...],
    *,
    timeout: float = 60,
):
    result = CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=timeout)},
        max_output_bytes=4 * 1024 * 1024,
    ).run(command_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"Debian lifecycle command failed: {command_id}")
    return result


def _run_expected_failure(command_id: str, argv: tuple[str, ...]):
    result = CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=120)},
        max_output_bytes=4 * 1024 * 1024,
    ).run(command_id)
    if result.succeeded or result.timed_out or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError("unsafe upgrade was not rejected cleanly")
    if "installed package verification failed" not in result.stderr:
        raise QualificationError("upgrade failed for an unexpected reason")
    return result


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.debian_lifecycle_qualifier",
        description="Exercise Meercata native package lifecycle in pinned Debian 13",
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
        report = DebianLifecycleQualifier(
            arguments.source_root,
            arguments.workspace,
            confirmation=arguments.confirmation,
            image_digest=arguments.image_digest,
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError, QualificationError) as exc:
        print(f"meercata-deb-qualify: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
