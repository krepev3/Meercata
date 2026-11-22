"""Durable structured controller audit logging."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from meercata.errors import AuditError
from meercata.models import Actor, local_now, utc_now
from meercata.paths import ensure_secure_directory

AUDIT_SCHEMA_VERSION = 1
MAX_AUDIT_EVENT_BYTES = 256 * 1024


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        event: str,
        *,
        actor: Actor,
        outcome: str,
        transaction_id: str | None = None,
        operation: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        if not event or len(event) > 128:
            raise AuditError("audit event name must contain 1 to 128 characters")
        record = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "utc_timestamp": utc_now(),
            "local_timestamp": local_now(),
            "event": event,
            "outcome": outcome,
            "transaction_id": transaction_id,
            "operation": operation,
            "actor": actor.to_dict(),
            "data": dict(data or {}),
        }
        try:
            payload = (
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AuditError("audit data is not JSON serializable") from exc
        if len(payload) > MAX_AUDIT_EVENT_BYTES:
            raise AuditError("audit event exceeds the size limit")
        try:
            ensure_secure_directory(self.path.parent)
        except Exception as exc:
            raise AuditError(f"cannot prepare audit directory: {exc}") from exc
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o640)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise AuditError("audit target is not a regular file")
                _write_all(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
        except AuditError:
            raise
        except OSError as exc:
            raise AuditError(f"cannot persist audit event: {exc}") from exc


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short audit write")
        offset += written
