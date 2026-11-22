"""Root-only lifecycle operations dispatched by narrow Debian maintainer hooks."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import PackagingError
from meercata.package_builder import MANIFEST_PATH, _validate_manifest

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_INSTALLED_FILE_BYTES = 4 * 1024 * 1024
SUDOERS_PATH = Path("/etc/sudoers.d/meercata")


def preinst_upgrade() -> dict[str, Any]:
    manifest = _load_installed_manifest()
    verified = _verify_installed_payload(manifest)
    return {"operation": "preinst-upgrade", **verified}


def postinst_configure() -> dict[str, Any]:
    _require_root()
    _run(
        "package.sysusers",
        ("/usr/bin/systemd-sysusers", "/usr/lib/sysusers.d/meercata.conf"),
    )
    _run(
        "package.tmpfiles",
        (
            "/usr/bin/systemd-tmpfiles",
            "--create",
            "/usr/lib/tmpfiles.d/meercata.conf",
        ),
    )
    _run(
        "package.sudoers",
        ("/usr/sbin/visudo", "-c", "-f", str(SUDOERS_PATH)),
    )
    manifest = _load_installed_manifest()
    verified = _verify_installed_payload(manifest, require_root_owner=True)
    reloaded = _daemon_reload_if_running()
    return {
        "operation": "postinst-configure",
        **verified,
        "daemon_reloaded": reloaded,
        "services_enabled": False,
        "services_started": False,
    }


def prerm_remove() -> dict[str, Any]:
    _require_root()
    stopped = False
    if Path("/run/systemd/system").is_dir():
        _run(
            "package.ips-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-ips.target",
            ),
        )
        _run(
            "package.monitor-delivery-health-timer-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-monitor-delivery-health.timer",
            ),
        )
        _run(
            "package.monitor-delivery-health-stop",
            (
                "/usr/bin/systemctl",
                "stop",
                "meercata-monitor-delivery-health.service",
            ),
        )
        _run(
            "package.monitor-delivery-timer-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-monitor-delivery.timer",
            ),
        )
        _run(
            "package.monitor-delivery-stop",
            ("/usr/bin/systemctl", "stop", "meercata-monitor-delivery.service"),
        )
        _run(
            "package.monitor-freshness-timer-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-monitor-freshness.timer",
            ),
        )
        _run(
            "package.monitor-freshness-stop",
            ("/usr/bin/systemctl", "stop", "meercata-monitor-freshness.service"),
        )
        _run(
            "package.monitor-timer-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-monitor.timer",
            ),
        )
        _run(
            "package.monitor-stop",
            ("/usr/bin/systemctl", "stop", "meercata-monitor.service"),
        )
        _run(
            "package.timer-disable",
            (
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "meercata-health.timer",
            ),
        )
        _run(
            "package.health-stop",
            ("/usr/bin/systemctl", "stop", "meercata-health.service"),
        )
        stopped = True
    try:
        metadata = SUDOERS_PATH.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            raise PackagingError("sudoers authorization path is not removable")
        SUDOERS_PATH.unlink()
        _sync_directory(SUDOERS_PATH.parent)
    return {
        "operation": "prerm-remove",
        "ips_target_stopped": stopped,
        "health_timer_stopped": stopped,
        "monitor_timer_stopped": stopped,
        "monitor_delivery_timer_stopped": stopped,
        "monitor_delivery_health_timer_stopped": stopped,
        "monitor_freshness_timer_stopped": stopped,
        "sudo_authorization_removed": not SUDOERS_PATH.exists(),
        "data_removed": False,
    }


def _load_installed_manifest() -> dict[str, Any]:
    path = Path(MANIFEST_PATH)
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
            raise PackagingError("installed package manifest is unsafe")
        value = json.loads(path.read_bytes())
    except FileNotFoundError as exc:
        raise PackagingError("installed package manifest is missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagingError("installed package manifest is unreadable or invalid") from exc
    _validate_manifest(value)
    return value


def _verify_installed_payload(
    manifest: Mapping[str, Any], *, require_root_owner: bool = False
) -> dict[str, int]:
    failures: list[str] = []
    verified = 0
    excluded_optional = 0
    for item in manifest["files"]:
        path = Path(item["path"])
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise PackagingError("not a regular file")
            if stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8):
                raise PackagingError("mode mismatch")
            if require_root_owner and (metadata.st_uid != 0 or metadata.st_gid != 0):
                raise PackagingError("ownership mismatch")
            if _sha256(path) != item["sha256"]:
                raise PackagingError("SHA-256 mismatch")
            verified += 1
        except FileNotFoundError as exc:
            if item["role"] in {"documentation", "copyright"}:
                excluded_optional += 1
                continue
            failures.append(f"{item['path']}: {exc}")
        except (OSError, PackagingError) as exc:
            failures.append(f"{item['path']}: {exc}")
    if failures:
        raise PackagingError("installed package verification failed: " + "; ".join(failures))
    return {
        "verified_files": verified,
        "dpkg_excluded_optional_files": excluded_optional,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_INSTALLED_FILE_BYTES:
                raise PackagingError("installed package file exceeds 4 MiB")
            digest.update(chunk)
    return digest.hexdigest()


def _run(command_id: str, argv: tuple[str, ...]) -> None:
    result = CommandRunner(
        {command_id: CommandDefinition.fixed(argv, timeout_seconds=60)}
    ).run(command_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise PackagingError(f"Debian lifecycle operation failed: {command_id}")


def _daemon_reload_if_running() -> bool:
    if not Path("/run/systemd/system").is_dir():
        return False
    _run("package.daemon-reload", ("/usr/bin/systemctl", "daemon-reload"))
    return True


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PackagingError("Debian lifecycle operation requires effective root")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = list(argv if argv is not None else sys.argv[1:])
    operations = {
        "preinst-upgrade": preinst_upgrade,
        "postinst-configure": postinst_configure,
        "prerm-remove": prerm_remove,
    }
    if len(arguments) != 1 or arguments[0] not in operations:
        print("meercata-package-lifecycle: operation is not allowlisted", file=stderr)
        return 2
    try:
        result = operations[arguments[0]]()
        print(json.dumps(result, sort_keys=True), file=stdout)
        return 0
    except (OSError, PackagingError) as exc:
        print(f"meercata-package-lifecycle: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
