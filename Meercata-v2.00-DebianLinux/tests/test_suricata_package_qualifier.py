from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from meercata.errors import QualificationError
from meercata.suricata_package_qualifier import (
    SURICATA_DEBIAN_VERSION,
    _apt_package_metadata,
    _parse_build_info,
    _parse_release,
    _prepare_workspace,
    _require_release_validity,
)


SOURCE_ROOT = Path(__file__).parents[1]


def test_suricata_qualification_workspace_must_be_new_and_absolute(
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
    assert created.stat().st_mode & 0o777 == 0o700


def test_authenticated_release_parser_and_freshness_are_fail_closed() -> None:
    release = _parse_release(
        b"Origin: Debian Backports\n"
        b"Date: Thu, 13 Aug 2026 02:07:29 UTC\n"
        b"Valid-Until: Thu, 20 Aug 2026 02:07:29 UTC\n"
        b"SHA256:\n"
        b" ignored\n"
    )

    assert _require_release_validity(
        release, now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc)
    ) == (
        "Thu, 13 Aug 2026 02:07:29 UTC",
        "Thu, 20 Aug 2026 02:07:29 UTC",
    )
    with pytest.raises(QualificationError, match="expired"):
        _require_release_validity(
            release, now=datetime(2026, 8, 21, tzinfo=timezone.utc)
        )
    with pytest.raises(QualificationError, match="duplicates"):
        _parse_release(b"Origin: Debian\nOrigin: Other\n")


def test_build_info_parser_exposes_exact_capability_values() -> None:
    parsed = _parse_build_info(
        "Suricata Configuration:\n"
        "  AF_PACKET support: yes\n"
        "  NFQueue support: yes\n"
        "  Unix socket enabled: yes\n"
    )

    assert parsed == {
        "Suricata Configuration:": "",
        "AF_PACKET support:": "yes",
        "NFQueue support:": "yes",
        "Unix socket enabled:": "yes",
    }


def test_apt_metadata_requires_exact_signed_index_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (
        "Package: suricata\n"
        f"Version: {SURICATA_DEBIAN_VERSION}\n"
        "Architecture: amd64\n"
        "Filename: pool/main/s/suricata/suricata.deb\n"
        "Size: 4443912\n"
        f"SHA256: {'a' * 64}\n"
    )
    monkeypatch.setattr(
        "meercata.suricata_package_qualifier._run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=output),
    )

    assert _apt_package_metadata("suricata", SURICATA_DEBIAN_VERSION) == {
        "repository_filename": "pool/main/s/suricata/suricata.deb",
        "repository_size": 4443912,
        "repository_sha256": "a" * 64,
    }

    monkeypatch.setattr(
        "meercata.suricata_package_qualifier._run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=output.replace("pool/main/", "pool/contrib/")
        ),
    )
    with pytest.raises(QualificationError, match="metadata is invalid"):
        _apt_package_metadata("suricata", SURICATA_DEBIAN_VERSION)


def test_suricata_qualification_schema_is_valid_and_strict() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            SOURCE_ROOT
            / "schemas/suricata-package-qualification-v1.schema.json"
        ).read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["properties"]["checks"]["minItems"] == 8


def test_recorded_suricata_package_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            SOURCE_ROOT
            / "schemas/suricata-package-qualification-v1.schema.json"
        ).read_text()
    )
    evidence = json.loads(
        (
            SOURCE_ROOT
            / "qualification-evidence/suricata-package-dev11.json"
        ).read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["project_version"] == "2.0.0.dev11"
