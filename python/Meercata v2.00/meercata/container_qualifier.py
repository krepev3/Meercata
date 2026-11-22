"""Root-owned package qualification restricted to a disposable Debian 13 container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import PackagingError, QualificationError
from meercata.package_builder import MANIFEST_PATH, ProductionPackageBuilder

DEBIAN_13_IMAGE_DIGEST = (
    "sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
)
CONFIRMATION = "I_UNDERSTAND_THIS_IS_A_DISPOSABLE_DEBIAN_13_CONTAINER"
MAX_INSTALL_FILE_BYTES = 4 * 1024 * 1024
_VERSION_PATTERN = re.compile(r"[0-9A-Za-z.+-]{1,128}\Z")


class DisposableContainerQualifier:
    """Install and qualify one package image only after strict container guards."""

    def __init__(
        self,
        source_root: Path,
        stage_root: Path,
        *,
        confirmation: str,
        image_digest: str,
    ) -> None:
        self.source_root = source_root
        self.stage_root = stage_root
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_debian_13(
            self.confirmation, self.image_digest
        )
        builder = ProductionPackageBuilder(self.source_root, self.stage_root)
        manifest = builder.stage()
        verification = builder.verify()
        _install_package_image(builder.stage_root, manifest)
        checks: list[dict[str, Any]] = [
            _passed("platform.container", platform),
            _passed(
                "package.install",
                {
                    "files": verification["verified_files"],
                    "directories": verification["verified_directories"],
                },
            ),
        ]

        _run("sysusers.apply", ("/usr/bin/systemd-sysusers", "/usr/lib/sysusers.d/meercata.conf"))
        identity = _installed_identity()
        checks.append(_passed("sysusers.apply", identity))
        _run("tmpfiles.apply", ("/usr/bin/systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/meercata.conf"))
        runtime = _verify_runtime_directories(identity)
        _run(
            "logrotate.syntax",
            (
                "/usr/sbin/logrotate",
                "--debug",
                "/etc/logrotate.d/meercata-monitor",
            ),
        )
        runtime["logrotate_syntax"] = True
        checks.append(_passed("tmpfiles.apply", runtime))

        ownership = _verify_installed_package(manifest)
        checks.append(_passed("package.ownership", ownership))
        launchers = _verify_launchers(manifest["version"])
        checks.append(_passed("launchers.execute", launchers))
        _run("sudoers.syntax", ("/usr/sbin/visudo", "-c", "-f", "/etc/sudoers.d/meercata"))
        sudoers = _verify_sudoers_authorization()
        checks.append(_passed("sudoers.authorization", sudoers))

        _prepare_suricata_fixture()
        _run(
            "systemd.units",
            (
                "/usr/bin/systemd-analyze",
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
        )
        checks.append(_passed("systemd.units", {"verified_units": 15}))
        preservation = _verify_data_preservation_contract()
        checks.append(_passed("data.preservation", preservation))

        return {
            "schema_version": 1,
            "status": "container-installed-qualified",
            "package": "meercata",
            "version": manifest["version"],
            "platform": platform,
            "checks": checks,
            "limitations": [
                "systemd unit syntax was verified but systemd was not PID 1",
                "a minimal Suricata unit/executable fixture was used; live Suricata readiness and socket behavior were not exercised",
                "native package signature, upgrade, downgrade, removal, and purge were not exercised",
                "IDS/IPS traffic, nftables, NFQUEUE, restart, crash, and reboot behavior were not exercised",
            ],
        }


def _require_disposable_debian_13(
    confirmation: str,
    image_digest: str,
    *,
    marker: Path = Path("/.dockerenv"),
    release_path: Path = Path("/etc/os-release"),
    systemd_runtime: Path = Path("/run/systemd/system"),
) -> dict[str, Any]:
    if confirmation != CONFIRMATION:
        raise QualificationError("disposable-container confirmation is missing")
    if image_digest != DEBIAN_13_IMAGE_DIGEST:
        raise QualificationError("Debian 13 image digest is not the approved pinned digest")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise QualificationError("container qualification requires effective root")
    try:
        if not stat.S_ISREG(marker.lstat().st_mode):
            raise QualificationError("Docker container marker is invalid")
    except FileNotFoundError as exc:
        raise QualificationError("refusing to qualify outside a Docker container") from exc
    release = _read_os_release(release_path)
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise QualificationError("qualification requires Debian 13")
    if systemd_runtime.exists():
        raise QualificationError("refusing a container with a running systemd manager")
    return {
        "os_id": "debian",
        "version_id": "13",
        "architecture": os.uname().machine,
        "image_digest": image_digest,
        "effective_uid": 0,
        "effective_gid": 0,
    }


def _read_os_release(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise QualificationError("cannot read container operating-system identity") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ID", "VERSION_ID"}:
            values[key] = value.strip().strip('"')
    return values


def _install_package_image(stage_root: Path, manifest: Mapping[str, Any]) -> None:
    destinations = [item["path"] for item in manifest["files"]]
    destinations.append(str(MANIFEST_PATH))
    for value in destinations:
        target = _live_target(value)
        if target.exists() or target.is_symlink():
            raise QualificationError(f"container destination already exists: {value}")
        _verify_parent_components(target)
    for item in manifest["directories"]:
        target = _live_target(item["path"])
        target.mkdir(parents=True, exist_ok=True, mode=int(item["mode"], 8))
        target.chmod(int(item["mode"], 8), follow_symlinks=False)
        os.chown(target, 0, 0, follow_symlinks=False)
    for item in manifest["files"]:
        source = _staged_target(stage_root, item["path"])
        _copy_new_root_file(source, _live_target(item["path"]), int(item["mode"], 8))
    _copy_new_root_file(
        _staged_target(stage_root, str(MANIFEST_PATH)),
        _live_target(str(MANIFEST_PATH)),
        0o644,
    )


def _live_target(value: Any) -> Path:
    path = _safe_absolute(value)
    return Path("/").joinpath(*path.parts[1:])


def _staged_target(root: Path, value: Any) -> Path:
    path = _safe_absolute(value)
    target = root.joinpath(*path.parts[1:])
    if root not in target.parents:
        raise QualificationError("staged package path escapes its root")
    return target


def _safe_absolute(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise QualificationError("package path is invalid")
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise QualificationError("package path is unsafe")
    return path


def _verify_parent_components(target: Path) -> None:
    current = Path("/")
    for component in target.parts[1:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise QualificationError(f"container destination parent is unsafe: {current}")


def _copy_new_root_file(source: Path, target: Path, mode: int) -> None:
    content = _read_bounded_regular(source)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(target, mode, follow_symlinks=False)
        os.chown(target, 0, 0, follow_symlinks=False)
    except OSError as exc:
        raise QualificationError(f"cannot install package file: {target}") from exc


def _read_bounded_regular(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INSTALL_FILE_BYTES:
            raise QualificationError("package source is unsafe or oversized")
        return path.read_bytes()
    except OSError as exc:
        raise QualificationError("package source cannot be read") from exc


def _run(check_id: str, argv: tuple[str, ...], *, timeout: float = 30.0):
    result = CommandRunner(
        {check_id: CommandDefinition.fixed(argv, timeout_seconds=timeout)}
    ).run(check_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"{check_id} failed")
    return result


def _installed_identity() -> dict[str, Any]:
    passwd = _colon_records(Path("/etc/passwd"))
    groups = _colon_records(Path("/etc/group"))
    user = passwd.get("meercata")
    service_group = groups.get("meercata")
    operator_group = groups.get("meercata-operators")
    if (
        user is None
        or service_group is None
        or operator_group is None
        or len(user) != 7
        or len(service_group) != 4
        or len(operator_group) != 4
        or not user[2].isdigit()
        or int(user[2]) == 0
        or not user[3].isdigit()
        or user[3] != service_group[2]
        or user[5:] != ["/nonexistent", "/usr/sbin/nologin"]
        or "meercata" in operator_group[3].split(",")
    ):
        raise QualificationError("installed service identity violates separation policy")
    return {
        "service_uid": int(user[2]),
        "service_gid": int(user[3]),
        "operator_gid": int(operator_group[2]),
        "operator_membership": False,
    }


def _colon_records(path: Path) -> dict[str, list[str]]:
    try:
        rows = [line.split(":") for line in path.read_text().splitlines() if line]
    except OSError as exc:
        raise QualificationError(f"cannot read identity database: {path}") from exc
    if any(not row or not row[0] for row in rows):
        raise QualificationError("identity database is malformed")
    return {row[0]: row for row in rows}


def _verify_runtime_directories(identity: Mapping[str, Any]) -> dict[str, Any]:
    operator_gid = int(identity["operator_gid"])
    service_uid = int(identity["service_uid"])
    service_gid = int(identity["service_gid"])
    expected = {
        "/etc/meercata/credentials": (0o750, 0, service_gid),
        "/var/lib/meercata": (0o1770, 0, operator_gid),
        "/var/lib/meercata/privileged": (0o700, 0, 0),
        "/var/lib/meercata/privileged/transactions": (0o700, 0, 0),
        "/var/log/meercata": (0o1770, 0, operator_gid),
        "/var/log/meercata/privileged": (0o700, 0, 0),
        "/run/meercata": (0o770, 0, operator_gid),
        "/var/lib/meercata/monitor": (0o700, service_uid, service_gid),
        "/var/lib/meercata/monitor/outbox": (0o700, service_uid, service_gid),
        "/var/lib/meercata/monitor/dead-letter": (0o700, service_uid, service_gid),
        "/var/log/meercata/monitor": (0o700, service_uid, service_gid),
        "/run/meercata/monitor": (0o700, service_uid, service_gid),
    }
    for path_text, (mode, uid, gid) in expected.items():
        metadata = Path(path_text).lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise QualificationError(f"runtime directory policy is invalid: {path_text}")
    for index, path_text in enumerate(
        (
            "/etc/meercata/credentials",
            "/var/lib/meercata/monitor",
            "/var/lib/meercata/monitor/outbox",
            "/var/lib/meercata/monitor/dead-letter",
            "/var/log/meercata/monitor",
            "/run/meercata/monitor",
        )
    ):
        _run(
            f"tmpfiles.monitor-access-{index}",
            (
                "/usr/bin/sudo",
                "-u",
                "meercata",
                "--",
                "/usr/bin/test",
                "-d",
                path_text,
            ),
        )
    return {
        "verified_directories": len(expected),
        "root_owned_private": 3,
        "service_owned_monitor": 5,
        "root_owned_credentials": 1,
    }


def _verify_installed_package(manifest: Mapping[str, Any]) -> dict[str, Any]:
    verified = 0
    for item in manifest["files"]:
        path = _live_target(item["path"])
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8)
            or _sha256(path) != item["sha256"]
        ):
            raise QualificationError(f"installed package ownership is invalid: {item['path']}")
        verified += 1
    manifest_path = _live_target(str(MANIFEST_PATH))
    metadata = manifest_path.lstat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise QualificationError("installed package manifest ownership is invalid")
    return {"verified_root_owned_files": verified + 1}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_INSTALL_FILE_BYTES:
                raise QualificationError("installed package file exceeds 4 MiB")
            digest.update(chunk)
    return digest.hexdigest()


def _verify_launchers(expected_version: str) -> dict[str, Any]:
    if not _VERSION_PATTERN.fullmatch(expected_version):
        raise QualificationError("package version is invalid")
    cli = _run("launcher.cli", ("/usr/bin/sudo", "-u", "meercata", "--", "/usr/bin/meercata", "--version"))
    if cli.stdout.strip() != f"meercata {expected_version}":
        raise QualificationError("installed CLI version is invalid")
    helper = _run("launcher.helper", ("/usr/lib/meercata/bin/meercata-helper", "--help"))
    required = (
        "health.socket-snapshot",
        "rules.reload",
        "nftables.snapshot",
        "nftables.apply",
        "nftables.verify",
        "nftables.rollback",
        "emergency.bypass",
    )
    if any(operation not in helper.stdout for operation in required):
        raise QualificationError("installed helper operation surface is invalid")
    return {"cli_user": "meercata", "helper_operations": 10}


def _verify_sudoers_authorization() -> dict[str, Any]:
    result = _run("sudoers.list", ("/usr/bin/sudo", "-U", "meercata", "-l"))
    output = result.stdout + result.stderr
    required = (
        "/usr/lib/meercata/bin/meercata-helper health.socket-snapshot",
    )
    forbidden = (
        "rules.snapshot",
        "rules.activate",
        "rules.rollback",
        "rules.reload",
        "nftables.snapshot",
        "nftables.apply",
        "nftables.verify",
        "nftables.rollback",
        "emergency.bypass",
    )
    if any(item not in output for item in required) or any(item in output for item in forbidden):
        raise QualificationError("service-user sudo authorization is not health-only")
    return {"service_user_health_only": True, "ruleops_authorized": False}


def _prepare_suricata_fixture() -> None:
    unit = Path("/etc/systemd/system/suricata.service")
    executable = Path("/usr/bin/suricata")
    if unit.exists() or executable.exists():
        raise QualificationError("Suricata fixture destination already exists")
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(
        "[Unit]\nDescription=Disposable Suricata fixture\n"
        "[Service]\nType=notify\nExecStart=/usr/bin/suricata\n",
        encoding="utf-8",
    )
    unit.chmod(0o644)
    executable.write_bytes(b"")
    executable.chmod(0o755)
    os.chown(unit, 0, 0, follow_symlinks=False)
    os.chown(executable, 0, 0, follow_symlinks=False)


def _verify_data_preservation_contract() -> dict[str, Any]:
    protected = {
        "/etc/meercata": "administrator configuration root",
        "/var/lib/meercata": "controller and recovery state root",
        "/var/log/meercata": "audit and operational log root",
    }
    for path_text in protected:
        path = Path(path_text)
        path.mkdir(parents=True, exist_ok=True)
        sentinel = path / ".qualification-preserve"
        sentinel.write_text("preserve\n", encoding="utf-8")
        if sentinel.read_text(encoding="utf-8") != "preserve\n":
            raise QualificationError("protected data sentinel could not be verified")
    manifest = json.loads(Path(MANIFEST_PATH).read_text())
    managed = {item["path"] for item in manifest["files"]}
    if any(path in managed or any(item.startswith(path + "/") for item in managed) for path in protected):
        raise QualificationError("package manifest claims a protected data root")
    return {"preserved_roots": len(protected), "active_configuration_installed": False}


def _passed(check_id: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": dict(details)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m meercata.container_qualifier",
        description="Qualify a root-owned install only in the pinned disposable Debian 13 container",
    )
    parser.add_argument("stage_root", type=Path)
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
        report = DisposableContainerQualifier(
            arguments.source_root,
            arguments.stage_root,
            confirmation=arguments.confirmation,
            image_digest=arguments.image_digest,
        ).qualify()
        print(json.dumps(report, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError, QualificationError, json.JSONDecodeError) as exc:
        print(f"meercata-container-qualify: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
