import uuid
from pathlib import Path

import pytest

from meercata.errors import InvalidModelError, StateStoreError, UnsafePathError
from meercata.models import Actor, TransactionRecord, TransactionState
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within


def test_transaction_record_round_trip() -> None:
    record = TransactionRecord.create_locked(
        "rules.update",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
        {"source": "[redacted]"},
    ).transitioned(TransactionState.SNAPSHOTTED, {"sha256": "abc"})

    restored = TransactionRecord.from_dict(record.to_dict())

    assert restored == record
    assert restored.history[-1].state == TransactionState.SNAPSHOTTED


@pytest.mark.parametrize(
    "values",
    [
        (-1, 1, "test", 1),
        (1, -1, "test", 1),
        (1, 1, "", 1),
        (1, 1, "test", -1),
    ],
)
def test_actor_rejects_invalid_identity(values: tuple[int, int, str, int]) -> None:
    with pytest.raises(InvalidModelError):
        Actor(
            uid=values[0],
            gid=values[1],
            invocation_source=values[2],
            pid=values[3],
        )


def test_transaction_record_rejects_noncanonical_id() -> None:
    with pytest.raises(InvalidModelError):
        TransactionRecord.create_locked(
            "rules.update",
            Actor(uid=1, gid=1, invocation_source="test", pid=1),
            transaction_id=str(uuid.uuid4()).upper(),
        )


@pytest.mark.parametrize("operation", ["", "Unsafe Operation", "../escape", "x" * 129])
def test_transaction_record_rejects_unsafe_operation(operation: str) -> None:
    with pytest.raises(InvalidModelError):
        TransactionRecord.create_locked(
            operation,
            Actor(uid=1, gid=1, invocation_source="test", pid=1),
        )


def test_isolated_paths_are_rooted_below_test_directory(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)

    assert paths.state_dir == tmp_path / "var" / "lib" / "meercata"
    assert paths.controller_lock_file == tmp_path / "run" / "meercata" / "controller.lock"


def test_isolated_paths_reject_filesystem_root() -> None:
    with pytest.raises(UnsafePathError):
        MeercataPaths.isolated(Path("/"))


def test_require_within_rejects_root_and_escape(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        require_within(tmp_path, tmp_path)
    with pytest.raises(UnsafePathError):
        require_within(tmp_path / ".." / "escape", tmp_path)


def test_require_within_returns_canonical_child(tmp_path: Path) -> None:
    assert require_within(tmp_path / "child" / "file", tmp_path) == (
        tmp_path / "child" / "file"
    ).resolve()


def test_secure_directory_rejects_symlink_component(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(StateStoreError, match="unsafe"):
        ensure_secure_directory(linked_root / "state")
    assert list(outside.iterdir()) == []
