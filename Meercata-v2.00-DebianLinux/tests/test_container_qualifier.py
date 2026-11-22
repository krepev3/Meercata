from __future__ import annotations

import json
from pathlib import Path

import pytest

from meercata.container_qualifier import (
    CONFIRMATION,
    DEBIAN_13_IMAGE_DIGEST,
    _read_os_release,
    _require_disposable_debian_13,
    _safe_absolute,
)
from meercata.errors import QualificationError


SOURCE_ROOT = Path(__file__).parents[1]


def _platform_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    marker = tmp_path / ".dockerenv"
    marker.write_text("")
    release = tmp_path / "os-release"
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    return marker, release, tmp_path / "systemd-not-running"


def test_container_guard_accepts_only_confirmed_pinned_debian_13_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker, release, systemd_runtime = _platform_fixture(tmp_path)
    monkeypatch.setattr("meercata.container_qualifier.os.geteuid", lambda: 0)
    monkeypatch.setattr("meercata.container_qualifier.os.getegid", lambda: 0)

    result = _require_disposable_debian_13(
        CONFIRMATION,
        DEBIAN_13_IMAGE_DIGEST,
        marker=marker,
        release_path=release,
        systemd_runtime=systemd_runtime,
    )

    assert result["os_id"] == "debian"
    assert result["version_id"] == "13"
    assert result["effective_uid"] == 0


@pytest.mark.parametrize(
    "confirmation,digest,uid,message",
    [
        ("wrong", DEBIAN_13_IMAGE_DIGEST, 0, "confirmation"),
        (CONFIRMATION, "sha256:" + "0" * 64, 0, "pinned digest"),
        (CONFIRMATION, DEBIAN_13_IMAGE_DIGEST, 1000, "effective root"),
    ],
)
def test_container_guard_rejects_missing_authority_or_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    confirmation: str,
    digest: str,
    uid: int,
    message: str,
) -> None:
    marker, release, systemd_runtime = _platform_fixture(tmp_path)
    monkeypatch.setattr("meercata.container_qualifier.os.geteuid", lambda: uid)
    monkeypatch.setattr("meercata.container_qualifier.os.getegid", lambda: uid)

    with pytest.raises(QualificationError, match=message):
        _require_disposable_debian_13(
            confirmation,
            digest,
            marker=marker,
            release_path=release,
            systemd_runtime=systemd_runtime,
        )


@pytest.mark.parametrize(
    "release_text,marker_kind,systemd_running,message",
    [
        ("ID=kali\nVERSION_ID=2026.3\n", "file", False, "Debian 13"),
        ("ID=debian\nVERSION_ID=12\n", "file", False, "Debian 13"),
        ('ID=debian\nVERSION_ID="13"\n', "missing", False, "outside a Docker"),
        ('ID=debian\nVERSION_ID="13"\n', "directory", False, "marker is invalid"),
        ('ID=debian\nVERSION_ID="13"\n', "file", True, "running systemd"),
    ],
)
def test_container_guard_rejects_wrong_platform_or_live_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_text: str,
    marker_kind: str,
    systemd_running: bool,
    message: str,
) -> None:
    marker = tmp_path / ".dockerenv"
    if marker_kind == "file":
        marker.write_text("")
    elif marker_kind == "directory":
        marker.mkdir()
    release = tmp_path / "os-release"
    release.write_text(release_text)
    systemd_runtime = tmp_path / "run-systemd"
    if systemd_running:
        systemd_runtime.mkdir()
    monkeypatch.setattr("meercata.container_qualifier.os.geteuid", lambda: 0)
    monkeypatch.setattr("meercata.container_qualifier.os.getegid", lambda: 0)

    with pytest.raises(QualificationError, match=message):
        _require_disposable_debian_13(
            CONFIRMATION,
            DEBIAN_13_IMAGE_DIGEST,
            marker=marker,
            release_path=release,
            systemd_runtime=systemd_runtime,
        )


def test_os_release_parser_uses_only_required_identity(tmp_path: Path) -> None:
    release = tmp_path / "os-release"
    release.write_text(
        'PRETTY_NAME="Debian GNU/Linux 13"\nID=debian\nVERSION_ID="13"\n'
    )

    assert _read_os_release(release) == {"ID": "debian", "VERSION_ID": "13"}


@pytest.mark.parametrize("value", ["relative", "/", "/etc/../passwd", 123])
def test_container_install_path_rejects_unsafe_values(value: object) -> None:
    with pytest.raises(QualificationError):
        _safe_absolute(value)


def test_recorded_debian_13_evidence_conforms_to_versioned_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (SOURCE_ROOT / "schemas/container-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (
            SOURCE_ROOT
            / "qualification-evidence"
            / "debian13-container-dev9.json"
        ).read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["status"] == "container-installed-qualified"
    assert evidence["version"] == "2.0.0.dev9"

    evidence = json.loads(
        (
            SOURCE_ROOT
            / "qualification-evidence"
            / "debian13-container-dev22.json"
        ).read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["status"] == "container-installed-qualified"
    assert evidence["version"] == "2.0.0.dev22"
    checks = {check["check_id"]: check for check in evidence["checks"]}
    assert checks["tmpfiles.apply"]["details"] == {
        "logrotate_syntax": True,
        "root_owned_private": 3,
        "service_owned_monitor": 3,
        "verified_directories": 9,
    }
    assert checks["systemd.units"]["details"]["verified_units"] == 9

    evidence = json.loads(
        (
            SOURCE_ROOT
            / "qualification-evidence"
            / "debian13-container-dev23.json"
        ).read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["version"] == "2.0.0.dev23"
    checks = {check["check_id"]: check for check in evidence["checks"]}
    assert checks["tmpfiles.apply"]["details"] == {
        "logrotate_syntax": True,
        "root_owned_credentials": 1,
        "root_owned_private": 3,
        "service_owned_monitor": 5,
        "verified_directories": 12,
    }
    assert checks["systemd.units"]["details"]["verified_units"] == 13
