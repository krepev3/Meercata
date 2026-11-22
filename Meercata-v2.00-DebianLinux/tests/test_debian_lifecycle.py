from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from meercata.debian_lifecycle import _verify_installed_payload, main, prerm_remove
from meercata.debian_lifecycle_qualifier import _prepare_workspace
from meercata.errors import PackagingError, QualificationError


SOURCE_ROOT = Path(__file__).parents[1]


def test_recorded_debian_lifecycle_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (
            SOURCE_ROOT
            / "qualification-evidence/debian-lifecycle-dev10.json"
        ).read_text()
    )
    schema = json.loads(
        (
            SOURCE_ROOT
            / "schemas/debian-lifecycle-qualification-v1.schema.json"
        ).read_text()
    )

    jsonschema.validate(report, schema)
    assert len(report["checks"]) == 7


def test_lifecycle_dispatch_denies_unknown_or_extra_operations() -> None:
    stderr = io.StringIO()

    assert main(["shell"], stderr=stderr) == 2
    assert "not allowlisted" in stderr.getvalue()
    assert main(["postinst-configure", "extra"], stderr=io.StringIO()) == 2


@pytest.mark.parametrize("operation", ["postinst-configure", "prerm-remove"])
def test_mutating_lifecycle_operations_require_effective_root(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("meercata.debian_lifecycle.os.geteuid", lambda: 1000)
    stderr = io.StringIO()

    assert main([operation], stderr=stderr) == 3
    assert "requires effective root" in stderr.getvalue()


def test_installed_payload_allows_only_missing_optional_documentation(
    tmp_path: Path,
) -> None:
    present = tmp_path / "module.py"
    present.write_text("value = 1\n")
    present.chmod(0o644)
    digest = hashlib.sha256(present.read_bytes()).hexdigest()
    manifest = {
        "files": [
            {
                "path": str(present),
                "sha256": digest,
                "mode": "0644",
                "role": "python-module",
            },
            {
                "path": str(tmp_path / "excluded.md"),
                "sha256": "0" * 64,
                "mode": "0644",
                "role": "documentation",
            },
        ]
    }

    assert _verify_installed_payload(manifest) == {
        "verified_files": 1,
        "dpkg_excluded_optional_files": 1,
    }

    manifest["files"][1]["role"] = "python-module"
    with pytest.raises(PackagingError, match="verification failed"):
        _verify_installed_payload(manifest)


def test_installed_payload_rejects_modified_required_file(tmp_path: Path) -> None:
    path = tmp_path / "module.py"
    path.write_text("modified\n")
    path.chmod(0o644)
    manifest = {
        "files": [
            {
                "path": str(path),
                "sha256": "0" * 64,
                "mode": "0644",
                "role": "python-module",
            }
        ]
    }

    with pytest.raises(PackagingError, match="SHA-256 mismatch"):
        _verify_installed_payload(manifest)


def test_lifecycle_qualification_workspace_must_be_new_absolute_child(
    tmp_path: Path,
) -> None:
    with pytest.raises(QualificationError):
        _prepare_workspace(Path("relative"))
    with pytest.raises(QualificationError):
        _prepare_workspace(Path("/"))

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(QualificationError, match="must not already exist"):
        _prepare_workspace(existing)

    created = tmp_path / "created"
    _prepare_workspace(created)
    assert created.is_dir()
    assert created.stat().st_mode & 0o777 == 0o700


def test_removal_stops_ips_target_before_health_and_removes_sudoers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    sudoers = tmp_path / "meercata-sudoers"
    sudoers.write_text("policy\n", encoding="utf-8")
    original_is_dir = Path.is_dir

    monkeypatch.setattr("meercata.debian_lifecycle.os.geteuid", lambda: 0)
    monkeypatch.setattr("meercata.debian_lifecycle.SUDOERS_PATH", sudoers)
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda self: True
        if self == Path("/run/systemd/system")
        else original_is_dir(self),
    )
    monkeypatch.setattr(
        "meercata.debian_lifecycle._run",
        lambda command_id, argv: calls.append((command_id, argv)),
    )
    monkeypatch.setattr("meercata.debian_lifecycle._sync_directory", lambda _path: None)

    result = prerm_remove()

    assert [item[0] for item in calls] == [
        "package.ips-disable",
        "package.monitor-delivery-health-timer-disable",
        "package.monitor-delivery-health-stop",
        "package.monitor-delivery-timer-disable",
        "package.monitor-delivery-stop",
        "package.monitor-freshness-timer-disable",
        "package.monitor-freshness-stop",
        "package.monitor-timer-disable",
        "package.monitor-stop",
        "package.timer-disable",
        "package.health-stop",
    ]
    assert calls[0][1][-1] == "meercata-ips.target"
    assert result["ips_target_stopped"] is True
    assert result["monitor_timer_stopped"] is True
    assert result["monitor_delivery_timer_stopped"] is True
    assert result["monitor_delivery_health_timer_stopped"] is True
    assert result["monitor_freshness_timer_stopped"] is True
    assert not sudoers.exists()
