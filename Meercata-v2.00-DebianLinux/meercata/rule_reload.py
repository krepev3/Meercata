"""Narrow Suricata socket client and bounded non-blocking rule reload polling."""

from __future__ import annotations

import json
import socket
import stat
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from meercata.errors import RuleOperationError

MAX_SOCKET_RESPONSE_BYTES = 2 * 1024 * 1024
RULE_COMMANDS = {
    "ruleset-reload-nonblocking",
    "ruleset-reload-time",
    "ruleset-stats",
    "ruleset-failed-rules",
}


class ReloadSession(Protocol):
    def __enter__(self) -> "ReloadSession": ...
    def __exit__(self, kind: object, value: object, traceback: object) -> None: ...
    def request(self, command: str) -> Any: ...


class RuleReloadSocketClient:
    """Socket client that exposes only the four RuleOps commands."""

    def __init__(self, path: Path, timeout_seconds: float) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None
        self._reader: Any = None

    def __enter__(self) -> "RuleReloadSocketClient":
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise RuleOperationError(f"Suricata reload socket is unavailable: {exc}") from exc
        if not stat.S_ISSOCK(metadata.st_mode):
            raise RuleOperationError("Suricata reload socket path is not a Unix socket")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout_seconds)
        try:
            client.connect(str(self.path))
            self._socket = client
            self._reader = client.makefile("rb")
            self._send({"version": "0.2"})
            if self._read().get("return") != "OK":
                raise RuleOperationError("Suricata reload socket handshake was rejected")
            return self
        except Exception:
            client.close()
            self._socket = None
            self._reader = None
            raise

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self._reader is not None:
            self._reader.close()
        if self._socket is not None:
            self._socket.close()
        self._reader = None
        self._socket = None

    def request(self, command: str) -> Any:
        if command not in RULE_COMMANDS:
            raise RuleOperationError(f"socket command is not RuleOps allowlisted: {command}")
        self._send({"command": command})
        response = self._read()
        if response.get("return") != "OK":
            raise RuleOperationError(f"Suricata rejected RuleOps command: {command}")
        return response.get("message")

    def _send(self, value: Mapping[str, Any]) -> None:
        if self._socket is None:
            raise RuleOperationError("Suricata reload client is not connected")
        try:
            self._socket.sendall(
                (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
            )
        except OSError as exc:
            raise RuleOperationError(f"cannot send Suricata reload request: {exc}") from exc

    def _read(self) -> Mapping[str, Any]:
        if self._reader is None:
            raise RuleOperationError("Suricata reload client is not connected")
        try:
            raw = self._reader.readline(MAX_SOCKET_RESPONSE_BYTES + 1)
        except OSError as exc:
            raise RuleOperationError(f"cannot read Suricata reload response: {exc}") from exc
        if not raw:
            raise RuleOperationError("Suricata closed the reload socket")
        if len(raw) > MAX_SOCKET_RESPONSE_BYTES or not raw.endswith(b"\n"):
            raise RuleOperationError("Suricata reload response exceeds the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuleOperationError("Suricata reload socket returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuleOperationError("Suricata reload response must be an object")
        return value


class RuleReloadController:
    def __init__(
        self,
        client_factory: Callable[[], ReloadSession],
        *,
        timeout_seconds: float,
        poll_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds <= 0 or poll_seconds <= 0 or poll_seconds >= timeout_seconds:
            raise RuleOperationError("reload polling bounds are invalid")
        self._client_factory = client_factory
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self._clock = clock
        self._sleeper = sleeper

    def reload_and_verify(self) -> dict[str, Any]:
        with self._client_factory() as client:
            before = client.request("ruleset-reload-time")
            client.request("ruleset-reload-nonblocking")
            deadline = self._clock() + self.timeout_seconds
            after = before
            while _stable_value(after) == _stable_value(before):
                if self._clock() >= deadline:
                    raise RuleOperationError("Suricata rule reload timed out")
                self._sleeper(self.poll_seconds)
                after = client.request("ruleset-reload-time")
            statistics = client.request("ruleset-stats")
            failed = client.request("ruleset-failed-rules")
        if not isinstance(failed, list):
            raise RuleOperationError("Suricata returned invalid failed-rule statistics")
        if failed:
            raise RuleOperationError(f"Suricata reports {len(failed)} failed rules after reload")
        return {
            "reload_time_before": _bounded_value(before),
            "reload_time_after": _bounded_value(after),
            "ruleset_stats": _bounded_value(statistics),
            "failed_rules": 0,
        }


def _stable_value(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise RuleOperationError("Suricata returned a non-JSON reload value") from exc


def _bounded_value(value: Any) -> Any:
    encoded = _stable_value(value).encode("utf-8")
    if len(encoded) > 64 * 1024:
        return {"omitted": True, "size_bytes": len(encoded)}
    return value
