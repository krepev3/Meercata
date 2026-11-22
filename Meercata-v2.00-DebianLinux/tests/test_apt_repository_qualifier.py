from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from meercata.apt_repository_qualifier import (
    _apt_argv,
    _prepare_workspace,
    _release_bytes,
    _write_source,
    main,
)
from meercata.container_qualifier import DEBIAN_13_IMAGE_DIGEST
from meercata.errors import QualificationError


ROOT = Path(__file__).parents[1]


def test_wrong_confirmation_is_rejected_before_repository_changes(tmp_path: Path) -> None:
    stderr = io.StringIO()

    result = main(
        [
            str(tmp_path / "workspace"),
            "--source-root",
            str(ROOT),
            "--confirmation",
            "wrong",
            "--image-digest",
            DEBIAN_13_IMAGE_DIGEST,
        ],
        stderr=stderr,
    )

    assert result == 3
    assert "confirmation" in stderr.getvalue()
    assert not (tmp_path / "workspace").exists()


def test_workspace_must_be_new_absolute_path(tmp_path: Path) -> None:
    with pytest.raises(QualificationError):
        _prepare_workspace(Path("relative"))
    with pytest.raises(QualificationError):
        _prepare_workspace(Path("/"))
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(QualificationError, match="must not already exist"):
        _prepare_workspace(existing)


def test_release_metadata_is_deterministic_and_hash_bound(tmp_path: Path) -> None:
    suite = tmp_path / "dists/meercata-dev"
    binary = suite / "main/binary-all"
    binary.mkdir(parents=True)
    packages = b"Package: meercata\nVersion: 2.0.0~dev15-1\n\n"
    compressed = b"deterministic-gzip-fixture"
    (binary / "Packages").write_bytes(packages)
    (binary / "Packages.gz").write_bytes(compressed)

    release = _release_bytes(suite)

    assert release.startswith(b"Origin: Meercata\n")
    assert b"Suite: meercata-dev\n" in release
    assert b"Acquire-By-Hash: yes\n" in release
    assert hashlib.sha256(packages).hexdigest().encode() in release
    assert hashlib.sha256(compressed).hexdigest().encode() in release
    assert release == _release_bytes(suite)


def test_apt_arguments_and_source_forbid_authentication_bypass(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    keyring = tmp_path / "qualification.gpg"
    keyring.write_bytes(b"keyring")
    source = _write_source(
        tmp_path,
        repository,
        {"debian_version": "2.0.0~dev15-1"},
        {"keyring": keyring},
        "test",
    )
    content = source.read_text()
    argv = _apt_argv(source, tmp_path / "lists", tmp_path / "cache")

    assert f"Signed-By: {keyring}" in content
    assert "Trusted:" not in content
    assert "trusted=yes" not in content.lower()
    assert "Acquire::AllowInsecureRepositories=false" in argv
    assert "Acquire::AllowDowngradeToInsecureRepositories=false" in argv
    assert "APT::Get::AllowUnauthenticated=false" in argv
    assert "--allow-unauthenticated" not in argv


def test_apt_repository_schema_is_valid_and_strict() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/apt-repository-qualification-v1.schema.json").read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["checks"]["minItems"] == 10


def test_recorded_dev15_apt_repository_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    evidence = json.loads(
        (ROOT / "qualification-evidence/apt-repository-dev15.json").read_text()
    )
    schema = json.loads(
        (ROOT / "schemas/apt-repository-qualification-v1.schema.json").read_text()
    )

    jsonschema.validate(evidence, schema)
    checks = {item["check_id"]: item["details"] for item in evidence["checks"]}
    assert len(checks) == len(evidence["checks"]) == 10
    repositories = checks["repository.metadata"]["revisions"]
    assert checks["apt.install"]["artifact_sha256"] == repositories[0]["artifact_sha256"]
    assert checks["apt.upgrade"]["artifact_sha256"] == repositories[1]["artifact_sha256"]
    assert checks["apt.install"]["fingerprint"] == checks["signing.ephemeral-key"]["fingerprint"]
    assert checks["trust.unpinned-key-rejected"]["trusted_override"] is False
