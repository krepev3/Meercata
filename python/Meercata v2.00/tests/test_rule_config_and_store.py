from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from meercata.errors import RuleConfigurationError, RuleStoreError
from meercata.paths import MeercataPaths
from meercata.rule_config import load_rule_config
from meercata.rule_store import RuleCandidateStore


def _write_config(paths: MeercataPaths, rules: str = "") -> None:
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        f'''schema_version = 1

[health]
mode = "ids"
interface = "eth0"

[rules]
source = "et/open"
active_rules_path = "{paths.suricata_rules_dir / 'suricata.rules'}"
suricata_config_path = "{paths.suricata_config_file}"
{rules}
''',
        encoding="utf-8",
    )


def test_load_rule_config_defaults_and_fixed_paths(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _write_config(paths)

    config = load_rule_config(paths)

    assert config.source == "et/open"
    assert config.maximum_reduction_percent == 5
    assert config.active_rules_path == paths.suricata_rules_dir / "suricata.rules"


@pytest.mark.parametrize(
    "setting, message",
    [
        ('source = "custom"', "allowlisted"),
        ("minimum_rule_count = 0", "integer from 1"),
        ("maximum_reduction_percent = 101", "between 0 and 100"),
        ("reload_timeout_seconds = 10\nreload_poll_seconds = 10", "must be below"),
    ],
)
def test_load_rule_config_rejects_unsafe_policy(
    tmp_path: Path, setting: str, message: str
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    if setting.startswith("source"):
        _write_config(paths)
        body = paths.controller_config_file.read_text().replace('source = "et/open"', setting)
        paths.controller_config_file.write_text(body)
    else:
        _write_config(paths, setting)

    with pytest.raises(RuleConfigurationError, match=message):
        load_rule_config(paths)


def test_load_rule_config_rejects_path_escape(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _write_config(paths)
    body = paths.controller_config_file.read_text().replace(
        str(paths.suricata_rules_dir / "suricata.rules"), "/tmp/rules"
    )
    paths.controller_config_file.write_text(body)

    with pytest.raises(RuleConfigurationError, match="outside"):
        load_rule_config(paths)


def test_candidate_store_round_trip_and_uuid_boundary(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    store = RuleCandidateStore(paths)
    candidate_id = str(uuid.uuid4())
    candidate = store.prepare(candidate_id)
    (candidate / "rules" / "suricata.rules").write_text(
        "alert ip any any -> any any (sid:1; rev:1;)\n"
    )
    manifest = {
        "schema_version": 1,
        "candidate_id": candidate_id,
        "source": "et/open",
        "created_utc": "2026-08-10T00:00:00Z",
        "status": "policy_passed",
        "summary": {"active_rules": 1},
        "validation": {"status": "pending"},
        "regression": {"status": "pending"},
    }

    store.save_manifest(candidate_id, manifest)

    assert store.load_manifest(candidate_id) == manifest
    assert store.read_rules(candidate_id).startswith(b"alert")
    assert store.list_manifests() == [manifest]
    with pytest.raises(RuleStoreError, match="UUID"):
        store.load_manifest("../../etc/passwd")


def test_candidate_store_rejects_symlinked_rules(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    store = RuleCandidateStore(paths)
    candidate_id = str(uuid.uuid4())
    candidate = store.prepare(candidate_id)
    target = tmp_path / "outside.rules"
    target.write_text("do not read")
    (candidate / "rules" / "suricata.rules").symlink_to(target)

    with pytest.raises(RuleStoreError, match="cannot read"):
        store.read_rules(candidate_id)


def test_rule_candidate_schema_tracks_common_manifest_fields() -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "rule-candidate-v1.schema.json").read_text()
    )

    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["properties"]["schema_version"]["const"] == 1
    assert set(schema["required"]) == {
        "schema_version",
        "candidate_id",
        "source",
        "created_utc",
        "status",
        "summary",
        "validation",
        "regression",
    }
