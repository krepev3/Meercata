"""Atomic durable storage for transaction and last-known-good state."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

from meercata.errors import InvalidModelError, StateStoreError
from meercata.models import TransactionRecord, utc_now
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within

MAX_STATE_BYTES = 2 * 1024 * 1024


class StateStore:
    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths

    def save(self, record: TransactionRecord) -> None:
        path = self._transaction_path(record.transaction_id)
        _atomic_json_write(path, record.to_dict(), self.paths.transactions_dir)

    def load(self, transaction_id: str) -> TransactionRecord:
        path = self._transaction_path(transaction_id)
        data = _read_json(path)
        try:
            return TransactionRecord.from_dict(data)
        except InvalidModelError as exc:
            raise StateStoreError(f"invalid transaction state in {path.name}: {exc}") from exc

    def list_records(self) -> list[TransactionRecord]:
        if not self.paths.transactions_dir.exists():
            return []
        if self.paths.transactions_dir.is_symlink():
            raise StateStoreError("transaction directory must not be a symlink")
        records: list[TransactionRecord] = []
        for path in sorted(self.paths.transactions_dir.glob("*.json")):
            records.append(self.load(path.stem))
        return records

    def list_incomplete(self) -> list[TransactionRecord]:
        return [record for record in self.list_records() if not record.state.terminal]

    def list_recovery_required(self) -> list[TransactionRecord]:
        records = self.list_records()
        required = [record for record in records if not record.state.terminal]
        committed = [
            record for record in records if record.state.value == "COMMITTED"
        ]
        if committed:
            newest = max(committed, key=lambda record: record.updated_utc)
            pointer = self.get_last_known_good()
            if pointer is None or pointer.get("transaction_id") != newest.transaction_id:
                required.append(newest)
        return required

    def set_last_known_good(self, record: TransactionRecord) -> None:
        if record.state.value != "COMMITTED":
            raise StateStoreError("only a committed transaction can be last-known-good")
        payload = {
            "schema_version": 1,
            "transaction_id": record.transaction_id,
            "operation": record.operation,
            "committed_utc": record.updated_utc,
            "pointer_updated_utc": utc_now(),
        }
        _atomic_json_write(
            self.paths.last_known_good_file,
            payload,
            self.paths.state_dir,
        )

    def get_last_known_good(self) -> Mapping[str, Any] | None:
        if not self.paths.last_known_good_file.exists():
            return None
        return _read_json(self.paths.last_known_good_file)

    def _transaction_path(self, transaction_id: str) -> Path:
        # Parsing through the model protects the filename from traversal. A UUID
        # constructor is intentionally repeated here because load() starts with a path.
        import uuid

        try:
            parsed = uuid.UUID(transaction_id)
        except (ValueError, AttributeError) as exc:
            raise StateStoreError("transaction ID must be a UUID") from exc
        if str(parsed) != transaction_id:
            raise StateStoreError("transaction ID must use canonical UUID form")
        return require_within(
            self.paths.transactions_dir / f"{transaction_id}.json",
            self.paths.transactions_dir,
        )


def _read_json(path: Path) -> Mapping[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise StateStoreError(f"state file is not regular: {path}")
            if metadata.st_size > MAX_STATE_BYTES:
                raise StateStoreError(f"state file exceeds size limit: {path}")
            chunks: list[bytes] = []
            remaining = MAX_STATE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > MAX_STATE_BYTES:
                raise StateStoreError(f"state file exceeds size limit: {path}")
        finally:
            os.close(fd)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise StateStoreError(f"state file must contain a JSON object: {path}")
        return value
    except StateStoreError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateStoreError(f"cannot read state file {path}: {exc}") from exc


def _atomic_json_write(path: Path, value: Mapping[str, Any], allowed_root: Path) -> None:
    require_within(path, allowed_root)
    try:
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StateStoreError("state is not JSON serializable") from exc
    if len(payload) > MAX_STATE_BYTES:
        raise StateStoreError("state exceeds size limit")
    try:
        ensure_secure_directory(allowed_root)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=allowed_root,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(fd, 0o640)
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary_path, path)
        directory_fd = os.open(allowed_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except StateStoreError:
        raise
    except OSError as exc:
        raise StateStoreError(f"cannot atomically persist state {path}: {exc}") from exc
    finally:
        if "temporary_path" in locals():
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short state write")
        offset += written
