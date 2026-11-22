from __future__ import annotations

from pathlib import Path

from meercata.ips_guard import IpsGuardService
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
    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.bypasses = []

    def verify_active(self):
        return {"active": self.active, "queue": 42} if self.active else {"active": False}

    def emergency_bypass(self, reason, incident_id):
        self.bypasses.append((reason, incident_id))
        self.active = False
        return {"state": "removed", "removed": True}


def _listener(kernel: int = 0, user: int = 0):
    return [
        {
            "queue": 42,
            "port_id": 123,
            "queue_total": 1,
            "queue_dropped": kernel,
            "user_dropped": user,
        }
    ]


def _guard(paths, lifecycle, reader):
    return IpsGuardService(
        paths,
        service_factory=lambda _paths, _config: lifecycle,
        listener_reader=reader,
        require_root=False,
    )


def test_guard_is_idle_without_policy_and_healthy_with_clean_listener(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert _guard(paths, _Lifecycle(False), _listener).check_once()["status"] == "idle"
    healthy = _guard(paths, _Lifecycle(), _listener).check_once()
    assert healthy["status"] == "healthy"
    assert healthy["queue_dropped"] == 0


def test_guard_bypasses_on_listener_loss(tmp_path: Path) -> None:
    lifecycle = _Lifecycle()
    result = _guard(_paths(tmp_path), lifecycle, lambda: []).check_once()

    assert result["reason"] == "listener-loss"
    assert lifecycle.bypasses[0][0] == "listener-loss"
    assert result["incident_id"].startswith("INC-AUTO-LISTENER-")


def test_guard_bypasses_on_first_kernel_or_user_drop(tmp_path: Path) -> None:
    lifecycle = _Lifecycle()
    result = _guard(_paths(tmp_path), lifecycle, lambda: _listener(user=1)).check_once()

    assert result["reason"] == "queue-overload"
    assert lifecycle.bypasses[0][0] == "queue-overload"
    assert result["incident_id"].startswith("INC-AUTO-OVERLOAD-")
