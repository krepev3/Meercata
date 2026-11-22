import json
from pathlib import Path

import pytest

from meercata.errors import LockHeldError, StateStoreError
from meercata.locking import ControllerLock


def test_controller_lock_rejects_concurrent_owner(tmp_path: Path) -> None:
    path = tmp_path / "run" / "controller.lock"
    first = ControllerLock(path)
    second = ControllerLock(path)
    first.acquire("11111111-1111-1111-1111-111111111111")
    try:
        with pytest.raises(LockHeldError):
            second.acquire("22222222-2222-2222-2222-222222222222")
    finally:
        first.release()

    second.acquire("22222222-2222-2222-2222-222222222222")
    second.release()


def test_controller_lock_records_owner_metadata(tmp_path: Path) -> None:
    path = tmp_path / "controller.lock"
    lock = ControllerLock(path)

    lock.acquire("11111111-1111-1111-1111-111111111111")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
        assert metadata["transaction_id"] == "11111111-1111-1111-1111-111111111111"
        assert metadata["schema_version"] == 1
    finally:
        lock.release()


def test_controller_lock_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("do not alter", encoding="utf-8")
    path = tmp_path / "controller.lock"
    path.symlink_to(target)

    with pytest.raises(StateStoreError):
        ControllerLock(path).acquire("11111111-1111-1111-1111-111111111111")
    assert target.read_text(encoding="utf-8") == "do not alter"
