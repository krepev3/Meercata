"""Restricted privileged access to the Suricata Unix command socket."""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from meercata.errors import PrivilegedOperationError
from meercata.health_config import HealthConfig, load_health_config
from meercata.paths import MeercataPaths
from meercata.privileged_nftables import NftablesCommandBackend
from meercata.suricata_socket import SuricataSocketClient

MAX_HEALTH_SNAPSHOT_BYTES = 512 * 1024
REQUIRED_HEALTH_COMMANDS = {
    "version",
    "uptime",
    "running-mode",
    "capture-mode",
    "iface-list",
    "iface-stat",
    "dump-counters",
}


class PrivilegedHealthSocketService:
    """Collect one fixed read-only socket snapshot; accepts no caller command."""

    def __init__(
        self,
        config: HealthConfig,
        *,
        socket_factory: Callable[[Path, float], Any] = SuricataSocketClient,
        nftables_reader: Callable[[], Mapping[str, Any] | None] | None = None,
        nfqueue_reader: Callable[[], str] | None = None,
        paths: MeercataPaths | None = None,
    ) -> None:
        self.config = config
        self.socket_factory = socket_factory
        self.nftables_reader = (
            nftables_reader or NftablesCommandBackend().read_table
        )
        self.nfqueue_reader = nfqueue_reader or _read_nfqueue_status
        self.paths = paths

    @classmethod
    def from_paths(cls, paths: Any) -> "PrivilegedHealthSocketService":
        return cls(load_health_config(paths), paths=paths)

    def snapshot(self) -> dict[str, Any]:
        _require_production_socket_trust(self.paths, self.config.socket_path)
        with self.socket_factory(
            self.config.socket_path,
            self.config.thresholds.socket_timeout_seconds,
        ) as client:
            command_list = client.request("command-list")
            available = _command_names(command_list)
            missing = sorted(REQUIRED_HEALTH_COMMANDS - available)
            if missing:
                raise PrivilegedOperationError(
                    f"required health socket commands are unavailable: {', '.join(missing)}"
                )
            snapshot = {
                "version": str(client.request("version")),
                "uptime": client.request("uptime"),
                "running_mode": str(client.request("running-mode")),
                "capture_mode": str(client.request("capture-mode")),
                "interfaces": client.request("iface-list"),
                "interface_stats": client.request(
                    "iface-stat",
                    {
                        "iface": (
                            f"NFQ#{self.config.queue}"
                            if self.config.mode == "ips"
                            else self.config.interface
                        )
                    },
                ),
                "counters": client.request("dump-counters"),
                "nftables": None,
                "nfqueue_status": None,
            }
        if self.config.mode == "ips":
            snapshot["nftables"] = self.nftables_reader()
            snapshot["nfqueue_status"] = self.nfqueue_reader()
        _validate_snapshot(snapshot)
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_HEALTH_SNAPSHOT_BYTES:
            raise PrivilegedOperationError("health socket snapshot exceeds 512 KiB")
        return snapshot


def _command_names(value: Any) -> set[str]:
    if isinstance(value, dict):
        value = value.get("commands")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PrivilegedOperationError("Suricata command list has an invalid shape")
    return set(value)


def _validate_snapshot(value: Mapping[str, Any]) -> None:
    for key in ("version", "running_mode", "capture_mode"):
        item = value.get(key)
        if not isinstance(item, str) or not 1 <= len(item) <= 256:
            raise PrivilegedOperationError(f"health socket {key} is invalid")
    uptime = value.get("uptime")
    if (
        type(uptime) not in {int, float}
        or not math.isfinite(float(uptime))
        or uptime < 0
    ):
        raise PrivilegedOperationError("health socket uptime is invalid")
    if not isinstance(value.get("interfaces"), (dict, list)):
        raise PrivilegedOperationError("health socket interface list is invalid")
    if not isinstance(value.get("interface_stats"), dict):
        raise PrivilegedOperationError("health socket interface statistics are invalid")
    if not isinstance(value.get("counters"), dict):
        raise PrivilegedOperationError("health socket counters are invalid")
    nftables = value.get("nftables")
    nfqueue_status = value.get("nfqueue_status")
    if nftables is not None and not isinstance(nftables, dict):
        raise PrivilegedOperationError("health nftables snapshot is invalid")
    if nfqueue_status is not None and not isinstance(nfqueue_status, str):
        raise PrivilegedOperationError("health NFQUEUE snapshot is invalid")


def _read_nfqueue_status() -> str:
    path = Path("/proc/net/netfilter/nfnetlink_queue")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            chunks: list[bytes] = []
            remaining = 64 * 1024 + 1
            while remaining:
                chunk = os.read(descriptor, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        payload = b"".join(chunks)
        if len(payload) > 64 * 1024:
            raise PrivilegedOperationError("NFQUEUE status exceeds 64 KiB")
        return payload.decode("ascii")
    except PrivilegedOperationError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PrivilegedOperationError("cannot read NFQUEUE status safely") from exc


def _require_production_socket_trust(
    paths: MeercataPaths | None,
    socket_path: Path,
) -> None:
    if paths is None or paths != MeercataPaths.production():
        return
    try:
        parent = socket_path.parent.lstat()
        target = socket_path.lstat()
    except OSError as exc:
        raise PrivilegedOperationError(f"cannot inspect Suricata socket: {exc}") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
        or not stat.S_ISSOCK(target.st_mode)
        or target.st_uid != 0
        or target.st_mode & 0o002
    ):
        raise PrivilegedOperationError(
            "Suricata socket must be root-owned and not world writable"
        )
