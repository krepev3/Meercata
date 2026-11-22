from __future__ import annotations

import json
from pathlib import Path

import pytest

from meercata.errors import PrivilegedOperationError
from meercata.ips_bootstrap import IpsBootstrapService
from meercata.paths import MeercataPaths


def _paths(tmp_path: Path) -> MeercataPaths:
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        '''schema_version = 1
[health]
mode = "ips"
interface = "enp1s0"
queue = 42
[ips]
fail_policy = "open"
traffic_scope = "gateway-forward"
''',
        encoding="utf-8",
    )
    return paths


class _Lifecycle:
    def __init__(self, *, active: bool = False) -> None:
        self.active = active
        self.calls = []

    def verify_active(self):
        self.calls.append("verify_active")
        if not self.active:
            return {"status": "inactive", "active": False}
        return {
            "status": "active",
            "active": True,
            "transaction_id": "10000000-0000-0000-0000-000000000021",
            "interface": "enp1s0",
            "queue": 42,
            "fail_open": True,
            "semantic_sha256": "a" * 64,
        }

    def snapshot(self, transaction_id):
        self.calls.append(("snapshot", transaction_id))
        return {}

    def apply(self, transaction_id):
        self.calls.append(("apply", transaction_id))
        self.active = True
        return {}

    def verify(self, transaction_id):
        self.calls.append(("verify", transaction_id))
        return {}

    def rollback(self, transaction_id):
        self.calls.append(("rollback", transaction_id))
        self.active = False
        return {}

    def deactivate(self, lifecycle_id):
        self.calls.append(("deactivate", lifecycle_id))
        self.active = False
        return {"state": "removed", "removed": True, "lifecycle_id": lifecycle_id}


def _listener(*, kernel: int = 0, user: int = 0):
    return [
        {
            "queue": 42,
            "port_id": 123,
            "queue_total": 0,
            "queue_dropped": kernel,
            "user_dropped": user,
        }
    ]


def test_bootstrap_activates_only_after_clean_listener_and_persists_state(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    lifecycle = _Lifecycle()
    service = IpsBootstrapService(
        paths,
        service_factory=lambda _paths, _config: lifecycle,
        listener_reader=_listener,
        require_root=False,
    )

    result = service.activate()

    assert result["active"] is True
    assert result["idempotent"] is False
    assert any(call[0] == "apply" for call in lifecycle.calls if isinstance(call, tuple))
    state = json.loads(service.state_path.read_text())
    assert state["state"] == "active"
    assert service.state_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("listeners", [lambda: [], lambda: _listener(kernel=1)])
def test_bootstrap_refuses_missing_or_pre_dropped_listener(tmp_path: Path, listeners) -> None:
    paths = _paths(tmp_path)
    lifecycle = _Lifecycle()
    service = IpsBootstrapService(
        paths,
        service_factory=lambda _paths, _config: lifecycle,
        listener_reader=listeners,
        require_root=False,
    )

    with pytest.raises(PrivilegedOperationError):
        service.activate()
    assert lifecycle.calls == []


def test_bootstrap_active_is_idempotent_and_deactivation_is_receipted(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    lifecycle = _Lifecycle(active=True)
    service = IpsBootstrapService(
        paths,
        service_factory=lambda _paths, _config: lifecycle,
        listener_reader=_listener,
        require_root=False,
    )

    assert service.activate()["idempotent"] is True
    removed = service.deactivate()
    assert removed["state"] == "removed"
    assert lifecycle.active is False
