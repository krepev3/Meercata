"""Single-controller advisory mutation lock."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
from pathlib import Path

from meercata.errors import LockHeldError, StateStoreError
from meercata.models import utc_now
from meercata.paths import ensure_secure_directory


class ControllerLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self, transaction_id: str) -> None:
        if self.held:
            raise StateStoreError("controller lock instance is already held")
        ensure_secure_directory(self.path.parent)
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o640)
        except OSError as exc:
            raise StateStoreError(f"cannot open controller lock: {exc}") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise StateStoreError("controller lock is not a regular file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise LockHeldError("another Meercata mutation is active") from exc
                raise StateStoreError(f"cannot acquire controller lock: {exc}") from exc
            payload = json.dumps(
                {
                    "schema_version": 1,
                    "pid": os.getpid(),
                    "transaction_id": transaction_id,
                    "acquired_utc": utc_now(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            _write_all(fd, payload + b"\n")
            os.fsync(fd)
            self._fd = fd
        except BaseException:
            os.close(fd)
            raise

    def release(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> ControllerLock:
        if not self.held:
            raise StateStoreError("acquire must be called before entering the lock context")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written
