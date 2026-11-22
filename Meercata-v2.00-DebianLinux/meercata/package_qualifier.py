"""Qualify a staged Meercata image inside an ephemeral filesystem root."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import PackagingError, QualificationError
from meercata.package_builder import MANIFEST_PATH, ProductionPackageBuilder

PYTHON = "/usr/bin/python3"
VISUDO = "/usr/sbin/visudo"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
SYSTEMD_SYSUSERS = "/usr/bin/systemd-sysusers"
SYSTEMD_TMPFILES = "/usr/bin/systemd-tmpfiles"
MAX_QUALIFICATION_FILE_BYTES = 4 * 1024 * 1024
RunnerFactory = Callable[[Mapping[str, CommandDefinition]], CommandRunner]

_IMPORT_SCRIPT = """\
import importlib, json, sys
sys.path.insert(0, sys.argv[1])
modules = (
    "meercata",
    "meercata.cli",
    "meercata.health",
    "meercata.monitor",
    "meercata.monitor_delivery",
    "meercata.package_builder",
    "meercata.privileged_helper",
)
for name in modules:
    importlib.import_module(name)
import meercata
print(json.dumps({"version": meercata.__version__, "modules": len(modules)}, sort_keys=True))
"""


class StagedImageQualifier:
    """Run bounded host-tool checks without writing to the supplied stage root."""

    def __init__(
        self,
        source_root: Path,
        stage_root: Path,
        *,
        runner_factory: RunnerFactory = CommandRunner,
    ) -> None:
        self.builder = ProductionPackageBuilder(source_root, stage_root)
        self.stage_root = self.builder.stage_root
        self._runner_factory = runner_factory

    def qualify(self) -> dict[str, Any]:
        verification = self.builder.verify()
        manifest = self.builder.load_manifest()
        checks: list[dict[str, Any]] = [
            _passed(
                "package.manifest",
                {
                    "files": verification["verified_files"],
                    "directories": verification["verified_directories"],
                },
            )
        ]
        with tempfile.TemporaryDirectory(prefix="meercata-qualification-") as workspace:
            root = Path(workspace) / "root"
            self._copy_payload(root, manifest)
            self._add_systemd_fixtures(root)

            imports = self._run(
                "python.imports",
                CommandDefinition.fixed(
                    (
                        PYTHON,
                        "-I",
                        "-B",
                        "-c",
                        _IMPORT_SCRIPT,
                        str(root / "usr/lib/meercata/python"),
                    ),
                    timeout_seconds=30,
                ),
            )
            checks.append(
                _passed(
                    "python.imports",
                    _parse_import_result(imports.stdout, manifest["version"]),
                )
            )
            self._run(
                "sudoers.syntax",
                CommandDefinition.fixed(
                    (VISUDO, "-c", "-f", str(root / "etc/sudoers.d/meercata")),
                    timeout_seconds=30,
                ),
            )
            checks.append(_passed("sudoers.syntax"))
            self._run(
                "systemd.units",
                CommandDefinition.fixed(
                    (
                        SYSTEMD_ANALYZE,
                        f"--root={root}",
                        "verify",
                        "meercata-health.service",
                        "meercata-health.timer",
                        "meercata-monitor.service",
                        "meercata-monitor.timer",
                        "meercata-monitor-freshness.service",
                        "meercata-monitor-freshness.timer",
                        "meercata-monitor-delivery.service",
                        "meercata-monitor-delivery.timer",
                        "meercata-monitor-delivery-health.service",
                        "meercata-monitor-delivery-health.timer",
                        "meercata-suricata-ips.service",
                        "meercata-ips-activate.service",
                        "meercata-ips-guard.service",
                        "meercata-ips.target",
                        "suricata.service",
                    ),
                    timeout_seconds=30,
                ),
            )
            checks.append(_passed("systemd.units", {"verified_units": 15}))
            self._run(
                "sysusers.materialize",
                CommandDefinition.fixed(
                    (SYSTEMD_SYSUSERS, f"--root={root}"), timeout_seconds=30
                ),
            )
            identity = _validate_generated_identity(root)
            checks.append(_passed("sysusers.materialize", identity))
            _validate_tmpfiles_policy(root)
            tmpfiles = self._run(
                "tmpfiles.dry-run",
                CommandDefinition.fixed(
                    (
                        SYSTEMD_TMPFILES,
                        f"--root={root}",
                        "--create",
                        "--dry-run",
                    ),
                    timeout_seconds=30,
                ),
            )
            _validate_tmpfiles_dry_run(tmpfiles.stdout + tmpfiles.stderr)
            checks.append(_passed("tmpfiles.dry-run", {"managed_directories": 12}))

        return {
            "schema_version": 1,
            "status": "staged-qualified",
            "package": "meercata",
            "version": manifest["version"],
            "checks": checks,
            "limitations": [
                "root ownership and tmpfiles chown were not applied in this unprivileged qualification",
                "live Suricata readiness, socket, reload, traffic, restart, and reboot behavior were not exercised",
                "native package signature, install, upgrade, downgrade, removal, and purge were not exercised",
            ],
        }

    def _run(self, check_id: str, command: CommandDefinition):
        try:
            result = self._runner_factory({check_id: command}).run(check_id)
        except OSError as exc:
            raise QualificationError(f"{check_id} tool is unavailable") from exc
        if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
            raise QualificationError(f"{check_id} failed")
        return result

    def _copy_payload(self, root: Path, manifest: Mapping[str, Any]) -> None:
        root.mkdir(mode=0o700)
        for item in manifest["directories"]:
            target = _rooted(root, item["path"])
            target.mkdir(parents=True, exist_ok=True, mode=int(item["mode"], 8))
            target.chmod(int(item["mode"], 8), follow_symlinks=False)
        for item in manifest["files"]:
            source = _rooted(self.stage_root, item["path"])
            target = _rooted(root, item["path"])
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            content = _read_regular_bounded(source)
            _write_new(target, content, int(item["mode"], 8))
        manifest_source = _rooted(self.stage_root, str(MANIFEST_PATH))
        manifest_target = _rooted(root, str(MANIFEST_PATH))
        _write_new(
            manifest_target,
            _read_regular_bounded(manifest_source),
            0o644,
        )

    @staticmethod
    def _add_systemd_fixtures(root: Path) -> None:
        unit_root = root / "usr/lib/systemd/system"
        for name in (
            "sysinit.target",
            "basic.target",
            "timers.target",
            "network-pre.target",
            "multi-user.target",
        ):
            _write_new(
                unit_root / name,
                b"[Unit]\nDescription=Disposable qualification fixture\n",
                0o644,
            )
        _write_new(
            unit_root / "suricata.service",
            (
                b"[Unit]\nDescription=Disposable Suricata fixture\n"
                b"[Service]\nType=notify\nExecStart=/usr/bin/suricata\n"
            ),
            0o644,
        )
        _write_new(root / "usr/bin/suricata", b"", 0o755)


def _passed(check_id: str, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "status": "passed",
        "details": dict(details or {}),
    }


def _rooted(root: Path, value: Any) -> Path:
    if not isinstance(value, str):
        raise QualificationError("qualification path is invalid")
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise QualificationError("qualification path is unsafe")
    target = root.joinpath(*path.parts[1:])
    if root not in target.parents:
        raise QualificationError("qualification path escapes disposable root")
    return target


def _read_regular_bounded(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise QualificationError("qualification input is not a regular file")
        if metadata.st_size > MAX_QUALIFICATION_FILE_BYTES:
            raise QualificationError("qualification input exceeds 4 MiB")
        return path.read_bytes()
    except OSError as exc:
        raise QualificationError("qualification input cannot be read") from exc


def _write_new(path: Path, content: bytes, mode: int) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        os.chmod(path, mode, follow_symlinks=False)
    except OSError as exc:
        raise QualificationError("cannot prepare disposable qualification root") from exc


def _parse_import_result(stdout: str, expected_version: str) -> dict[str, Any]:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise QualificationError("staged Python import returned invalid JSON") from exc
    if value != {"version": expected_version, "modules": 7}:
        raise QualificationError("staged Python import identity is invalid")
    return value


def _validate_generated_identity(root: Path) -> dict[str, Any]:
    try:
        passwd_lines = (root / "etc/passwd").read_text().splitlines()
        group_lines = (root / "etc/group").read_text().splitlines()
    except OSError as exc:
        raise QualificationError("sysusers did not materialize identity files") from exc
    if sum(line.startswith("meercata:") for line in passwd_lines) != 1:
        raise QualificationError("generated service identity violates separation policy")
    if sum(line.startswith("meercata:") for line in group_lines) != 1:
        raise QualificationError("generated service identity violates separation policy")
    users = {line.split(":", 1)[0]: line.split(":") for line in passwd_lines}
    groups = {line.split(":", 1)[0]: line.split(":") for line in group_lines}
    user = users.get("meercata")
    service_group = groups.get("meercata")
    operator_group = groups.get("meercata-operators")
    if (
        user is None
        or len(user) != 7
        or not user[2].isdigit()
        or int(user[2]) == 0
        or not user[3].isdigit()
        or int(user[3]) == 0
        or user[5] != "/nonexistent"
        or user[6] != "/usr/sbin/nologin"
        or service_group is None
        or len(service_group) != 4
        or service_group[2] != user[3]
        or operator_group is None
        or len(operator_group) != 4
        or operator_group[2] == user[3]
        or "meercata" in operator_group[3].split(",")
    ):
        raise QualificationError("generated service identity violates separation policy")
    return {
        "service_user": "meercata",
        "operator_group": "meercata-operators",
        "operator_membership": False,
    }


def _validate_tmpfiles_policy(root: Path) -> None:
    expected = {
        "/etc/meercata/credentials": ("0750", "root", "meercata"),
        "/var/lib/meercata": ("1770", "root", "meercata-operators"),
        "/var/lib/meercata/privileged": ("0700", "root", "root"),
        "/var/lib/meercata/privileged/transactions": ("0700", "root", "root"),
        "/var/log/meercata": ("1770", "root", "meercata-operators"),
        "/var/log/meercata/privileged": ("0700", "root", "root"),
        "/run/meercata": ("0770", "root", "meercata-operators"),
        "/var/lib/meercata/monitor": ("0700", "meercata", "meercata"),
        "/var/lib/meercata/monitor/outbox": ("0700", "meercata", "meercata"),
        "/var/lib/meercata/monitor/dead-letter": ("0700", "meercata", "meercata"),
        "/var/log/meercata/monitor": ("0700", "meercata", "meercata"),
        "/run/meercata/monitor": ("0700", "meercata", "meercata"),
    }
    try:
        lines = (root / "usr/lib/tmpfiles.d/meercata.conf").read_text().splitlines()
    except OSError as exc:
        raise QualificationError("tmpfiles policy cannot be read") from exc
    observed: dict[str, tuple[str, str, str]] = {}
    expected_acls = {
        "/var/lib/meercata": "u:meercata:--x",
        "/var/log/meercata": "u:meercata:--x",
        "/run/meercata": "u:meercata:--x",
    }
    observed_acls: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != 7:
            raise QualificationError("tmpfiles policy contains an invalid entry")
        if fields[0] == "d" and fields[1] not in observed:
            observed[fields[1]] = (fields[2], fields[3], fields[4])
        elif fields[0] == "a+" and fields[1] not in observed_acls:
            observed_acls[fields[1]] = fields[6]
        else:
            raise QualificationError("tmpfiles policy contains an invalid entry")
    missing = set(expected) - set(observed)
    if missing:
        raise QualificationError("tmpfiles policy omitted a managed directory")
    if observed != expected:
        raise QualificationError("tmpfiles policy mode or ownership is invalid")
    if observed_acls != expected_acls:
        raise QualificationError("tmpfiles service traversal ACL is invalid")


def _validate_tmpfiles_dry_run(output: str) -> None:
    required = {
        "/etc/meercata/credentials",
        "/var/lib/meercata",
        "/var/lib/meercata/privileged",
        "/var/lib/meercata/privileged/transactions",
        "/var/log/meercata",
        "/var/log/meercata/privileged",
        "/run/meercata",
        "/var/lib/meercata/monitor",
        "/var/lib/meercata/monitor/outbox",
        "/var/lib/meercata/monitor/dead-letter",
        "/var/log/meercata/monitor",
        "/run/meercata/monitor",
    }
    if any(path not in output for path in required):
        raise QualificationError("tmpfiles dry-run omitted a managed directory")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.package_qualifier",
        description="Qualify a staged Meercata image in an ephemeral root",
    )
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
        report = StagedImageQualifier(
            arguments.source_root, arguments.stage_root
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (PackagingError, QualificationError) as exc:
        print(f"meercata-qualify: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
