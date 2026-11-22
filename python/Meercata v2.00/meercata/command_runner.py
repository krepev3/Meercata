"""Allowlisted, bounded subprocess execution without a shell."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence

from meercata.errors import InvalidCommandError, UnknownCommandError
from meercata.models import CommandResult, utc_now

ALLOWED_ENVIRONMENT_KEYS = frozenset({"DPKG_DEB_THREADS_MAX", "SOURCE_DATE_EPOCH"})


@dataclass(frozen=True, slots=True)
class CommandDefinition:
    argv: tuple[str, ...]
    timeout_seconds: float = 30.0
    working_directory: Path = Path("/")
    environment: tuple[tuple[str, str], ...] = ()

    @classmethod
    def fixed(
        cls,
        argv: Sequence[str],
        *,
        timeout_seconds: float = 30.0,
        working_directory: Path = Path("/"),
        environment: Mapping[str, str] | None = None,
    ) -> CommandDefinition:
        return cls(
            tuple(argv),
            timeout_seconds,
            working_directory,
            tuple(sorted((environment or {}).items())),
        )

    def validate(self) -> None:
        if not self.argv:
            raise InvalidCommandError("command argv cannot be empty")
        executable = Path(self.argv[0])
        if not executable.is_absolute():
            raise InvalidCommandError("command executable must be an absolute path")
        if any(not isinstance(argument, str) or "\x00" in argument for argument in self.argv):
            raise InvalidCommandError("command arguments must be NUL-free strings")
        if not self.working_directory.is_absolute():
            raise InvalidCommandError("command working directory must be absolute")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 3600:
            raise InvalidCommandError("command timeout must be between 0 and 3600 seconds")
        if any(
            key not in ALLOWED_ENVIRONMENT_KEYS
            or not isinstance(value, str)
            or not value
            or len(value) > 128
            or "\x00" in value
            for key, value in self.environment
        ):
            raise InvalidCommandError("command environment contains an unsafe entry")
        if len(dict(self.environment)) != len(self.environment):
            raise InvalidCommandError("command environment contains duplicate keys")


class CommandRunner:
    def __init__(
        self,
        commands: Mapping[str, CommandDefinition],
        *,
        max_output_bytes: int = 1024 * 1024,
        termination_grace_seconds: float = 1.0,
    ) -> None:
        if max_output_bytes < 1 or max_output_bytes > 16 * 1024 * 1024:
            raise InvalidCommandError("max output must be between 1 byte and 16 MiB")
        if termination_grace_seconds <= 0 or termination_grace_seconds > 30:
            raise InvalidCommandError("termination grace must be between 0 and 30 seconds")
        self._commands = dict(commands)
        self._max_output_bytes = max_output_bytes
        self._termination_grace_seconds = termination_grace_seconds
        for command_id, definition in self._commands.items():
            if not command_id or len(command_id) > 128:
                raise InvalidCommandError("command ID must contain 1 to 128 characters")
            definition.validate()

    def run(self, command_id: str) -> CommandResult:
        try:
            definition = self._commands[command_id]
        except KeyError as exc:
            raise UnknownCommandError(f"command is not allowlisted: {command_id}") from exc

        started_utc = utc_now()
        started = time.monotonic()
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        }
        environment.update(definition.environment)
        process = subprocess.Popen(
            list(definition.argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=definition.working_directory,
            env=environment,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout = _BoundedCollector(process.stdout, self._max_output_bytes)
        stderr = _BoundedCollector(process.stderr, self._max_output_bytes)
        stdout.start()
        stderr.start()
        timed_out = False
        try:
            return_code = process.wait(timeout=definition.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _signal_process_group(process, signal.SIGTERM)
            try:
                return_code = process.wait(timeout=self._termination_grace_seconds)
            except subprocess.TimeoutExpired:
                _signal_process_group(process, signal.SIGKILL)
                return_code = process.wait()
        stdout.finish()
        stderr.finish()
        duration = time.monotonic() - started
        return CommandResult(
            command_id=command_id,
            argv=definition.argv,
            return_code=return_code,
            stdout=stdout.value.decode("utf-8", errors="replace"),
            stderr=stderr.value.decode("utf-8", errors="replace"),
            timed_out=timed_out,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
            started_utc=started_utc,
            duration_seconds=round(duration, 6),
        )


class _BoundedCollector:
    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._buffer = bytearray()
        self._truncated = False
        self._thread = threading.Thread(target=self._read, daemon=True)

    @property
    def value(self) -> bytes:
        return bytes(self._buffer)

    @property
    def truncated(self) -> bool:
        return self._truncated

    def start(self) -> None:
        self._thread.start()

    def finish(self) -> None:
        self._thread.join(timeout=1.0)
        if self._thread.is_alive():
            self._stream.close()
            self._thread.join(timeout=1.0)

    def _read(self) -> None:
        try:
            while True:
                chunk = self._stream.read(65536)
                if not chunk:
                    return
                remaining = self._limit - len(self._buffer)
                if remaining > 0:
                    self._buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._truncated = True
        except (OSError, ValueError):
            return
        finally:
            try:
                self._stream.close()
            except OSError:
                pass


def _signal_process_group(process: subprocess.Popen[bytes], signal_number: int) -> None:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return
