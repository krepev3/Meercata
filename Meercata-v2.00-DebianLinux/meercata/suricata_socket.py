"""Bounded read-only client for the Suricata 8 Unix command socket."""

from __future__ import annotations

import json
import socket
import stat
from pathlib import Path
from typing import Any, Mapping

from meercata.errors import HealthCollectionError
from meercata.health_config import INTERFACE_PATTERN

MAX_SOCKET_RESPONSE_BYTES = 2 * 1024 * 1024
READ_ONLY_COMMANDS = {
    "command-list",
    "version",
    "uptime",
    "running-mode",
    "capture-mode",
    "iface-list",
    "iface-stat",
    "dump-counters",
}


class SuricataSocketClient:
    def __init__(self, path: Path, timeout_seconds: float) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None
        self._reader: Any = None

    def __enter__(self) -> SuricataSocketClient:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise HealthCollectionError(f"Suricata socket is unavailable: {exc}") from exc
        if not stat.S_ISSOCK(metadata.st_mode):
            raise HealthCollectionError("Suricata socket path is not a Unix socket")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout_seconds)
        try:
            client.connect(str(self.path))
            self._socket = client
            self._reader = client.makefile("rb")
            self._send({"version": "0.2"})
            response = self._read()
            if response.get("return") != "OK":
                raise HealthCollectionError("Suricata socket handshake was rejected")
            return self
        except Exception:
            client.close()
            self._socket = None
            self._reader = None
            raise

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._reader is not None:
            self._reader.close()
        if self._socket is not None:
            self._socket.close()
        self._reader = None
        self._socket = None

    def request(
        self,
        command: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Any:
        if command not in READ_ONLY_COMMANDS:
            raise HealthCollectionError(f"socket command is not read-only allowlisted: {command}")
        if command == "iface-stat":
            if set(arguments or {}) != {"iface"}:
                raise HealthCollectionError("iface-stat requires only an iface argument")
            interface = (arguments or {}).get("iface")
            if not isinstance(interface, str) or not _valid_capture_interface(interface):
                raise HealthCollectionError("iface-stat interface is invalid")
        elif arguments:
            raise HealthCollectionError(f"{command} does not accept arguments")
        payload: dict[str, Any] = {"command": command}
        if arguments:
            payload["arguments"] = dict(arguments)
        self._send(payload)
        response = self._read()
        if response.get("return") != "OK":
            raise HealthCollectionError(f"Suricata rejected read-only command: {command}")
        return response.get("message")

    def _send(self, value: Mapping[str, Any]) -> None:
        if self._socket is None:
            raise HealthCollectionError("Suricata socket client is not connected")
        encoded = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._socket.sendall(encoded)
        except OSError as exc:
            raise HealthCollectionError(f"cannot send Suricata socket request: {exc}") from exc

    def _read(self) -> Mapping[str, Any]:
        if self._reader is None:
            raise HealthCollectionError("Suricata socket client is not connected")
        try:
            raw = self._reader.readline(MAX_SOCKET_RESPONSE_BYTES + 1)
        except OSError as exc:
            raise HealthCollectionError(f"cannot read Suricata socket response: {exc}") from exc
        if not raw:
            raise HealthCollectionError("Suricata closed the command socket")
        if len(raw) > MAX_SOCKET_RESPONSE_BYTES or not raw.endswith(b"\n"):
            raise HealthCollectionError("Suricata socket response exceeds the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HealthCollectionError("Suricata socket returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise HealthCollectionError("Suricata socket response must be an object")
        return value


def _valid_capture_interface(value: str) -> bool:
    if value == "NFQ" or value.startswith("NFQ#"):
        prefix, separator, queue_text = value.partition("#")
        if prefix != "NFQ" or separator != "#" or not queue_text.isdigit():
            return False
        if queue_text != str(int(queue_text)):
            return False
        return 0 <= int(queue_text) <= 65535
    return INTERFACE_PATTERN.fullmatch(value) is not None
