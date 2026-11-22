from __future__ import annotations

from collections.abc import Iterator
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile

import pytest

from meercata.debian_package import (
    DebianPackageBuilder,
    _debian_version,
    main,
)
from meercata.errors import PackagingError


SOURCE_ROOT = Path(__file__).parents[1]


@pytest.fixture
def workspace() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="meercata-deb-tests-") as directory:
        yield Path(directory)


def test_debian_builder_creates_reproducible_verified_binary_packages(
    workspace: Path,
) -> None:
    first = DebianPackageBuilder(SOURCE_ROOT, workspace / "first").build()
    second = DebianPackageBuilder(SOURCE_ROOT, workspace / "second").build()
    first_path = workspace / "first" / first["artifact"]
    second_path = workspace / "second" / second["artifact"]

    assert first["status"] == "built-and-verified"
    assert first["project_version"] == "2.0.0.dev25"
    assert first["debian_version"] == "2.0.0~dev25-1"
    assert first["architecture"] == "all"
    assert first["verification"] == {
        "package": "meercata",
        "version": "2.0.0~dev25-1",
        "architecture": "all",
        "root_owned_archive_entries": True,
        "manifest_files": first["payload_files"],
        "maintainer_scripts": 4,
        "active_configuration_included": False,
    }
    assert first_path.read_bytes() == second_path.read_bytes()
    assert hashlib.sha256(first_path.read_bytes()).hexdigest() == first["sha256"]


def test_debian_builder_extracts_exact_reviewed_control_and_payload(
    workspace: Path,
) -> None:
    builder = DebianPackageBuilder(SOURCE_ROOT, workspace / "output")
    report = builder.build()
    artifact = workspace / "output" / report["artifact"]

    verification = builder.verify(artifact)

    assert verification["maintainer_scripts"] == 4
    assert verification["root_owned_archive_entries"] is True
    assert verification["active_configuration_included"] is False


def test_debian_build_report_conforms_to_versioned_schema(workspace: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = DebianPackageBuilder(SOURCE_ROOT, workspace / "output").build()
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)


def test_recorded_debian_build_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev10.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev10"


def test_recorded_dev11_debian_build_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev11.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev11"


def test_recorded_dev12_debian_build_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev12.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev12"


def test_recorded_dev13_debian_build_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev13.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev13"


def test_recorded_dev14_debian_build_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev14.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev14"


def test_recorded_dev15_through_dev22_debian_build_evidence_conform_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev15.json").read_text()
    )
    schema = json.loads(
        (SOURCE_ROOT / "schemas/deb-build-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev15"
    assert report["sha256"] == "fdad00762f306cd47ffce077021f290c2a56c1b16942bc32766cb2f93097b2ec"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev16.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev16"
    assert report["sha256"] == "8cda3e7f96284a273f55e1ab97d3fcbd9019a15738bce3ba7e197143e54aa3a2"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev17.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev17"
    assert report["sha256"] == "33c563019f0b59efcb43e82fef431142009f457aff13d35e710b1f89a7b3e51c"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev18.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev18"
    assert report["sha256"] == "ca614d4d6d149bf3c5411c74a28ab208b02280741e9a13754725284835d9f8c7"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev19.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev19"
    assert report["sha256"] == "050150350f874e8df10e70f99f96a3e68cc4c7fe9c6bda2f15434a7c59a33060"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev20.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev20"
    assert report["sha256"] == "e74592315403646a39295b0cb1500fc0b9230f6f8cf5a2935a771130aea9aa0e"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev21.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev21"
    assert report["sha256"] == "af475b999bd0944edcfabb908420b09c82349091e3f56ae55023a5e75f11c25f"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev22.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev22"
    assert report["sha256"] == "58a3ec0e67631711e01639e5e4adc41b8306abdb29e8b91673049163e58097b5"
    report = json.loads(
        (SOURCE_ROOT / "qualification-evidence/deb-build-dev23.json").read_text()
    )

    jsonschema.validate(report, schema)
    assert report["project_version"] == "2.0.0.dev23"
    assert report["sha256"] == "6982f9d63533fe9b012d61737a9f699abd6ebee40de9683fa542bd55ea022fce"


@pytest.mark.parametrize(
    "version,expected",
    [
        ("2.0.0.dev9", "2.0.0~dev9-1"),
        ("10.20.30.dev123", "10.20.30~dev123-1"),
    ],
)
def test_project_version_maps_to_ordered_debian_version(
    version: str, expected: str
) -> None:
    assert _debian_version(version) == expected


@pytest.mark.parametrize("version", ["2.0.0", "2.0.dev9", "2.0.0.devx", "../9"])
def test_debian_version_mapping_rejects_unsafe_shapes(version: str) -> None:
    with pytest.raises(PackagingError):
        _debian_version(version)


@pytest.mark.parametrize("revision", [0, -1, 1000, True, "2"])
def test_debian_revision_rejects_unsafe_values(revision: object) -> None:
    with pytest.raises(PackagingError, match="revision"):
        _debian_version("2.0.0.dev9", revision)  # type: ignore[arg-type]


def test_debian_revision_produces_ordered_upgrade_artifact(workspace: Path) -> None:
    first = DebianPackageBuilder(
        SOURCE_ROOT, workspace / "first", debian_revision=1
    ).build()
    second = DebianPackageBuilder(
        SOURCE_ROOT, workspace / "second", debian_revision=2
    ).build()

    assert first["debian_version"] == "2.0.0~dev25-1"
    assert second["debian_version"] == "2.0.0~dev25-2"
    assert first["sha256"] != second["sha256"]


def test_debian_builder_rejects_source_overlap_root_and_existing_artifact(
    workspace: Path,
) -> None:
    with pytest.raises(PackagingError, match="source tree or root"):
        DebianPackageBuilder(SOURCE_ROOT, Path("/"))
    with pytest.raises(PackagingError, match="source tree or root"):
        DebianPackageBuilder(SOURCE_ROOT, SOURCE_ROOT / "dist")

    builder = DebianPackageBuilder(SOURCE_ROOT, workspace / "output")
    builder.build()
    with pytest.raises(PackagingError, match="already exists"):
        builder.build()


def test_debian_builder_rejects_wrong_maintainer_script_mode(
    workspace: Path,
) -> None:
    source = workspace / "source"
    source.mkdir()
    for item in SOURCE_ROOT.iterdir():
        if item.name.startswith(".pytest") or item.name == "__pycache__":
            continue
        if item.is_dir():
            import shutil

            shutil.copytree(
                item,
                source / item.name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        else:
            (source / item.name).write_bytes(item.read_bytes())
            (source / item.name).chmod(stat.S_IMODE(item.stat().st_mode))
    hook = source / "packaging/debian/postinst"
    hook.chmod(0o644)

    with pytest.raises(PackagingError, match="postinst"):
        DebianPackageBuilder(source, workspace / "output").build()


def test_debian_builder_cli_emits_bounded_json(workspace: Path) -> None:
    stdout = io.StringIO()

    result = main(
        [str(workspace / "output"), "--source-root", str(SOURCE_ROOT)],
        stdout=stdout,
    )

    assert result == 0
    assert '"status": "built-and-verified"' in stdout.getvalue()
