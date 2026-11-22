import json
import uuid
from pathlib import Path

import pytest

from meercata.errors import StateStoreError
from meercata.models import Actor, TransactionRecord, TransactionState
from meercata.paths import MeercataPaths
from meercata.state_store import StateStore


def record() -> TransactionRecord:
    return TransactionRecord.create_locked(
        "config.deploy",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
    )


def test_state_store_atomically_round_trips_record(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))
    original = record()

    store.save(original)

    assert store.load(original.transaction_id) == original
    assert list(store.paths.transactions_dir.glob("*.tmp")) == []


def test_state_store_lists_incomplete_and_terminal_records(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))
    incomplete = record()
    terminal = record().transitioned(TransactionState.ROLLING_BACK).transitioned(
        TransactionState.ROLLED_BACK
    )
    store.save(incomplete)
    store.save(terminal)

    assert {item.transaction_id for item in store.list_records()} == {
        incomplete.transaction_id,
        terminal.transaction_id,
    }
    assert [item.transaction_id for item in store.list_incomplete()] == [
        incomplete.transaction_id
    ]


def test_state_store_rejects_path_traversal_id(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))

    with pytest.raises(StateStoreError):
        store.load("../../etc/passwd")


def test_state_store_rejects_corrupt_json(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))
    transaction_id = str(uuid.uuid4())
    store.paths.transactions_dir.mkdir(parents=True)
    (store.paths.transactions_dir / f"{transaction_id}.json").write_text(
        "not json",
        encoding="utf-8",
    )

    with pytest.raises(StateStoreError):
        store.load(transaction_id)


def test_last_known_good_requires_committed_record(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))

    with pytest.raises(StateStoreError):
        store.set_last_known_good(record())


def test_last_known_good_round_trip(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))
    committed = record()
    for state in (
        TransactionState.SNAPSHOTTED,
        TransactionState.STAGED,
        TransactionState.VALIDATED,
        TransactionState.APPLIED,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ):
        committed = committed.transitioned(state)

    store.set_last_known_good(committed)

    pointer = store.get_last_known_good()
    assert pointer is not None
    assert pointer["transaction_id"] == committed.transaction_id


def test_committed_record_without_pointer_requires_recovery(tmp_path: Path) -> None:
    store = StateStore(MeercataPaths.isolated(tmp_path))
    committed = record()
    for state in (
        TransactionState.SNAPSHOTTED,
        TransactionState.STAGED,
        TransactionState.VALIDATED,
        TransactionState.APPLIED,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ):
        committed = committed.transitioned(state)
    store.save(committed)

    assert [item.transaction_id for item in store.list_recovery_required()] == [
        committed.transaction_id
    ]


def test_state_store_rejects_symlink_transaction_directory(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    paths.state_dir.mkdir(parents=True)
    paths.transactions_dir.symlink_to(target, target_is_directory=True)

    with pytest.raises(StateStoreError):
        StateStore(paths).save(record())
    assert list(target.iterdir()) == []
