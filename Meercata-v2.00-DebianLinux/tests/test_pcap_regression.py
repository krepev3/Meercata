from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from meercata.errors import RuleOperationError
from meercata.models import CommandResult
from meercata.paths import MeercataPaths
from meercata.pcap_regression import PcapRegressionRunner, RegressionPackStore
from meercata.rule_config import RuleConfig
from meercata.rule_store import RuleCandidateStore


RULE = b'alert ip any any -> any any (sid:1001; rev:1;)\n'
PCAP = b"pcap fixture bytes"


def _config(paths: MeercataPaths) -> RuleConfig:
    return RuleConfig(
        "et/open",
        1,
        5,
        60,
        30,
        30,
        1,
        paths.suricata_rules_dir / "suricata.rules",
        paths.suricata_config_file,
        45,
    )


def _candidate(paths: MeercataPaths) -> tuple[RuleCandidateStore, str]:
    store = RuleCandidateStore(paths)
    candidate_id = store.new_id()
    directory = store.prepare(candidate_id)
    (directory / "rules" / "suricata.rules").write_bytes(RULE)
    return store, candidate_id


def _pack(
    paths: MeercataPaths,
    *,
    pack_id: str = "et-open-smoke-v1",
    expected=None,
    forbidden=None,
) -> Path:
    directory = paths.regression_packs_dir / pack_id
    directory.mkdir(parents=True)
    (directory / "http-alert.pcap").write_bytes(PCAP)
    manifest = {
        "schema_version": 1,
        "pack_id": pack_id,
        "description": "Fixed offline alert regression",
        "cases": [
            {
                "case_id": "http-alert",
                "pcap_file": "http-alert.pcap",
                "pcap_sha256": hashlib.sha256(PCAP).hexdigest(),
                "expected_alerts": expected
                if expected is not None
                else [{"gid": 1, "sid": 1001, "minimum": 1, "maximum": 2}],
                "forbidden_alerts": forbidden
                if forbidden is not None
                else [{"gid": 1, "sid": 9999}],
            }
        ],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def _result(command_id: str, argv: tuple[str, ...], code: int = 0) -> CommandResult:
    return CommandResult(
        command_id,
        argv,
        code,
        "",
        "",
        False,
        False,
        False,
        "2026-08-12T00:00:00Z",
        0.5,
    )


class EveRunner:
    def __init__(self, commands, calls, events, *, code=0):
        self.commands = commands
        self.calls = calls
        self.events = events
        self.code = code

    def run(self, command_id):
        definition = self.commands[command_id]
        self.calls.append((command_id, definition))
        if self.code == 0:
            output = Path(definition.argv[definition.argv.index("-l") + 1])
            (output / "eve.json").write_text(
                "".join(json.dumps(event) + "\n" for event in self.events),
                encoding="utf-8",
            )
        return _result(command_id, definition.argv, self.code)


def _factory(calls, events, *, code=0):
    return lambda commands: EveRunner(commands, calls, events, code=code)


def _alert(sid: int, gid: int = 1):
    return {"event_type": "alert", "alert": {"gid": gid, "signature_id": sid}}


def test_pack_store_validates_manifest_and_pcap_hash(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _pack(paths)
    store = RegressionPackStore(paths)

    pack = store.load("et-open-smoke-v1")

    assert pack.pack_id == "et-open-smoke-v1"
    assert len(pack.manifest_sha256) == 64
    assert store.pcap_path(pack.pack_id, pack.cases[0]).name == "http-alert.pcap"

    (paths.regression_packs_dir / pack.pack_id / "http-alert.pcap").write_bytes(b"changed")
    with pytest.raises(RuleOperationError, match="hash mismatch"):
        store.pcap_path(pack.pack_id, pack.cases[0])


@pytest.mark.parametrize("pack_id", ["../escape", "UPPER", "", "a" * 65])
def test_pack_store_rejects_unsafe_pack_ids(tmp_path: Path, pack_id: str) -> None:
    with pytest.raises(RuleOperationError, match="pack ID"):
        RegressionPackStore(MeercataPaths.isolated(tmp_path)).load(pack_id)


def test_pack_store_rejects_unknown_keys_and_conflicting_oracle(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    directory = _pack(
        paths,
        expected=[{"gid": 1, "sid": 1}],
        forbidden=[{"gid": 1, "sid": 1}],
    )
    with pytest.raises(RuleOperationError, match="both expected and forbidden"):
        RegressionPackStore(paths).load("et-open-smoke-v1")

    value = json.loads((directory / "manifest.json").read_text())
    value["unknown"] = True
    (directory / "manifest.json").write_text(json.dumps(value))
    with pytest.raises(RuleOperationError, match="invalid schema"):
        RegressionPackStore(paths).load("et-open-smoke-v1")


def test_pack_store_rejects_symlinked_pack_and_pcap(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    outside = tmp_path / "outside-pack"
    outside.mkdir()
    paths.regression_packs_dir.mkdir(parents=True)
    (paths.regression_packs_dir / "linked-pack").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuleOperationError, match="not a real directory"):
        RegressionPackStore(paths).load("linked-pack")

    directory = _pack(paths)
    case = RegressionPackStore(paths).load("et-open-smoke-v1").cases[0]
    (directory / "http-alert.pcap").unlink()
    target = tmp_path / "outside.pcap"
    target.write_bytes(PCAP)
    (directory / "http-alert.pcap").symlink_to(target)
    with pytest.raises(RuleOperationError, match="PCAP path is unsafe"):
        RegressionPackStore(paths).pcap_path("et-open-smoke-v1", case)


def test_regression_runner_passes_expected_and_forbidden_oracles(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _pack(paths)
    candidates, candidate_id = _candidate(paths)
    calls = []
    runner = PcapRegressionRunner(
        paths,
        _config(paths),
        candidates,
        runner_factory=_factory(
            calls,
            [
                {"event_type": "flow", "flow_id": 1},
                _alert(1001),
            ],
        ),
    )

    result = runner.run(candidate_id, "et-open-smoke-v1")

    assert result["status"] == "passed"
    assert result["passed_cases"] == 1
    assert result["cases"][0]["observed_relevant_alerts"] == [
        {"gid": 1, "sid": 1001, "count": 1}
    ]
    command = calls[0][1]
    assert command.argv[0] == "/usr/bin/suricata"
    assert command.argv[command.argv.index("--runmode") + 1] == "single"
    assert command.argv[command.argv.index("--set") + 1] == "unix-command.enabled=no"
    assert "-r" in command.argv and "-S" in command.argv
    assert command.timeout_seconds == 45


def test_regression_runner_records_oracle_failure_without_raw_alerts(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _pack(paths)
    candidates, candidate_id = _candidate(paths)
    runner = PcapRegressionRunner(
        paths,
        _config(paths),
        candidates,
        runner_factory=_factory([], [_alert(9999)]),
    )

    result = runner.run(candidate_id, "et-open-smoke-v1")

    case = result["cases"][0]
    assert result["status"] == "failed"
    assert any("minimum" in failure for failure in case["failures"])
    assert any("forbidden" in failure for failure in case["failures"])
    assert "signature" not in json.dumps(result)


def test_regression_runner_handles_suricata_failure_without_eve(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _pack(paths)
    candidates, candidate_id = _candidate(paths)
    runner = PcapRegressionRunner(
        paths,
        _config(paths),
        candidates,
        runner_factory=_factory([], [], code=1),
    )

    result = runner.run(candidate_id, "et-open-smoke-v1")

    assert result["status"] == "failed"
    assert result["cases"][0]["return_code"] == 1
    assert "offline replay failed" in result["cases"][0]["failures"][0]


def test_regression_runner_rejects_invalid_eve_json(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    _pack(paths)
    candidates, candidate_id = _candidate(paths)

    class InvalidEveRunner(EveRunner):
        def run(self, command_id):
            definition = self.commands[command_id]
            output = Path(definition.argv[definition.argv.index("-l") + 1])
            (output / "eve.json").write_bytes(b"not-json\n")
            return _result(command_id, definition.argv)

    runner = PcapRegressionRunner(
        paths,
        _config(paths),
        candidates,
        runner_factory=lambda commands: InvalidEveRunner(commands, [], []),
    )

    result = runner.run(candidate_id, "et-open-smoke-v1")

    assert result["status"] == "failed"
    assert "invalid JSON" in result["cases"][0]["failures"][0]


def test_regression_pack_json_schema_has_strict_contract() -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "regression-pack-v1.schema.json").read_text()
    )

    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["cases"]["maxItems"] == 128


def test_production_baseline_corpus_is_reproducible_and_schema_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    pack_root = root / "regression-packs/production-baseline-v1"
    manifest = json.loads((pack_root / "manifest.json").read_text())
    pack_schema = json.loads(
        (root / "schemas/regression-pack-v1.schema.json").read_text()
    )
    jsonschema.validate(manifest, pack_schema)

    specification = importlib.util.spec_from_file_location(
        "production_baseline_generator", pack_root / "generate.py"
    )
    assert specification is not None and specification.loader is not None
    generator = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(generator)
    generated = generator.corpus()

    manifest_files = {case["pcap_file"] for case in manifest["cases"]}
    assert set(generated) == manifest_files == set(generator.EXPECTED_SHA256)
    for case in manifest["cases"]:
        payload = generated[case["pcap_file"]]
        assert (pack_root / case["pcap_file"]).read_bytes() == payload
        assert hashlib.sha256(payload).hexdigest() == case["pcap_sha256"]


def test_recorded_dev14_regression_corpus_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    evidence = json.loads(
        (root / "qualification-evidence/regression-corpus-dev14.json").read_text()
    )
    schema = json.loads(
        (root / "schemas/regression-corpus-qualification-v1.schema.json").read_text()
    )
    manifest_path = root / "regression-packs/production-baseline-v1/manifest.json"
    manifest = json.loads(manifest_path.read_text())

    jsonschema.validate(evidence, schema)
    assert len({case["case_id"] for case in evidence["cases"]}) == 7
    assert all(case["status"] == "passed" for case in evidence["cases"])
    assert evidence["pack_manifest_sha256"] == hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    manifest_cases = {case["case_id"]: case for case in manifest["cases"]}
    evidence_cases = {case["case_id"]: case for case in evidence["cases"]}
    assert set(evidence_cases) == set(manifest_cases)
    for case_id, recorded in evidence_cases.items():
        declared = manifest_cases[case_id]
        assert recorded["pcap_sha256"] == declared["pcap_sha256"]
        expected = [
            {"gid": item["gid"], "sid": item["sid"], "count": 1}
            for item in declared["expected_alerts"]
        ]
        assert recorded["observed_relevant_alerts"] == expected
