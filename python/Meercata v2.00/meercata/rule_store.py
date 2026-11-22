"""Durable, bounded storage for immutable RuleOps candidates."""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping

from meercata.errors import RuleStoreError
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 128 * 1024 * 1024


class RuleCandidateStore:
    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths

    def new_id(self) -> str:
        return str(uuid.uuid4())

    def prepare(self, candidate_id: str) -> Path:
        candidate = self.candidate_dir(candidate_id)
        ensure_secure_directory(candidate)
        ensure_secure_directory(candidate / "data")
        ensure_secure_directory(candidate / "rules")
        return candidate

    def candidate_dir(self, candidate_id: str) -> Path:
        _validate_id(candidate_id)
        try:
            return require_within(self.paths.rule_candidates_dir / candidate_id, self.paths.rule_candidates_dir)
        except Exception as exc:
            raise RuleStoreError("candidate path is unsafe") from exc

    def rules_file(self, candidate_id: str) -> Path:
        return self.candidate_dir(candidate_id) / "rules" / "suricata.rules"

    def save_manifest(self, candidate_id: str, value: Mapping[str, Any]) -> None:
        candidate = self.candidate_dir(candidate_id)
        if not candidate.is_dir() or candidate.is_symlink():
            raise RuleStoreError(f"candidate does not exist: {candidate_id}")
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(payload) > MAX_MANIFEST_BYTES:
            raise RuleStoreError("candidate manifest exceeds 1 MiB")
        _atomic_write(candidate / "manifest.json", payload, 0o640)

    def load_manifest(self, candidate_id: str) -> dict[str, Any]:
        value = _read_json(self.candidate_dir(candidate_id) / "manifest.json")
        required = {"schema_version", "candidate_id", "source", "created_utc", "status", "summary"}
        if set(value) < required or value.get("schema_version") != 1:
            raise RuleStoreError("candidate manifest has an invalid schema")
        if value.get("candidate_id") != candidate_id:
            raise RuleStoreError("candidate manifest ID does not match its directory")
        return value

    def read_rules(self, candidate_id: str) -> bytes:
        return _read_regular(self.rules_file(candidate_id), MAX_CANDIDATE_BYTES)

    def list_manifests(self) -> list[dict[str, Any]]:
        root = self.paths.rule_candidates_dir
        if not root.exists():
            return []
        if root.is_symlink() or not root.is_dir():
            raise RuleStoreError("candidate root is unsafe")
        manifests: list[dict[str, Any]] = []
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            try:
                _validate_id(child.name)
                manifests.append(self.load_manifest(child.name))
            except RuleStoreError:
                continue
        return sorted(manifests, key=lambda item: str(item.get("created_utc", "")), reverse=True)


def _validate_id(candidate_id: str) -> None:
    try:
        parsed = uuid.UUID(candidate_id)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuleStoreError("candidate ID must be a canonical UUID") from exc
    if str(parsed) != candidate_id:
        raise RuleStoreError("candidate ID must be a canonical UUID")


def _read_json(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuleStoreError("candidate manifest is invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuleStoreError("candidate manifest must be an object")
    return value


def _read_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuleStoreError(f"managed file is not regular: {path.name}")
            if metadata.st_size > limit:
                raise RuleStoreError(f"managed file exceeds its size limit: {path.name}")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
    except RuleStoreError:
        raise
    except OSError as exc:
        raise RuleStoreError(f"cannot read managed file {path.name}: {exc}") from exc
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise RuleStoreError(f"managed file exceeds its size limit: {path.name}")
    return raw


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, mode)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise RuleStoreError(f"cannot persist candidate manifest: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
