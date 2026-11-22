import io
import json
from pathlib import Path

from meercata.cli import main
from meercata.errors import RuleOperationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.models import Actor, TransactionRecord
from meercata.paths import MeercataPaths
from meercata.rule_models import RuleDiff
from meercata.state_store import StateStore


def test_cli_without_command_prints_help() -> None:
    stdout = io.StringIO()

    result = main([], stdout=stdout)

    assert result == 2
    assert "CLI-only" in stdout.getvalue()


def test_paths_json_uses_fixed_model(tmp_path: Path) -> None:
    stdout = io.StringIO()
    paths = MeercataPaths.isolated(tmp_path)

    result = main(["paths", "--json"], paths=paths, stdout=stdout)

    assert result == 0
    assert json.loads(stdout.getvalue())["state_dir"] == str(paths.state_dir)


def test_transaction_list_is_read_only_and_empty(tmp_path: Path) -> None:
    stdout = io.StringIO()
    paths = MeercataPaths.isolated(tmp_path)

    result = main(["transactions", "list", "--json"], paths=paths, stdout=stdout)

    assert result == 0
    assert json.loads(stdout.getvalue()) == []
    assert not paths.state_dir.exists()


def test_transaction_list_and_show(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    record = TransactionRecord.create_locked(
        "config.deploy",
        Actor(uid=1000, gid=1000, invocation_source="test", pid=123),
    )
    StateStore(paths).save(record)
    stdout = io.StringIO()

    assert main(["transactions", "list"], paths=paths, stdout=stdout) == 0
    assert record.transaction_id in stdout.getvalue()

    stdout = io.StringIO()
    assert (
        main(
            ["transactions", "show", record.transaction_id, "--json"],
            paths=paths,
            stdout=stdout,
        )
        == 0
    )
    assert json.loads(stdout.getvalue())["state"] == "LOCKED"

    stdout = io.StringIO()
    assert (
        main(
            ["transactions", "list", "--recovery-required", "--json"],
            paths=paths,
            stdout=stdout,
        )
        == 0
    )
    assert json.loads(stdout.getvalue())[0]["transaction_id"] == record.transaction_id


def test_transaction_show_rejects_unsafe_id(tmp_path: Path) -> None:
    stderr = io.StringIO()

    result = main(
        ["transactions", "show", "../../etc/passwd"],
        paths=MeercataPaths.isolated(tmp_path),
        stderr=stderr,
    )

    assert result == 3
    assert "must be a UUID" in stderr.getvalue()


class FakeHealthProvider:
    def __init__(self, reports: list[HealthReport]) -> None:
        self.reports = reports
        self.index = 0

    def collect(self) -> HealthReport:
        report = self.reports[min(self.index, len(self.reports) - 1)]
        self.index += 1
        return report


def health_report(status: HealthStatus) -> HealthReport:
    return HealthReport(
        "ids",
        (HealthCheck("service", status, status.value),),
    )


def test_health_json_returns_stable_exit_code(tmp_path: Path) -> None:
    stdout = io.StringIO()
    provider = FakeHealthProvider([health_report(HealthStatus.DEGRADED)])

    result = main(
        ["health", "--json"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        health_factory=lambda _paths: provider,
    )

    value = json.loads(stdout.getvalue())
    assert result == 1
    assert value["schema_version"] == 1
    assert value["status"] == "degraded"
    assert value["exit_code"] == 1


def test_health_missing_configuration_returns_json_unknown(tmp_path: Path) -> None:
    stdout = io.StringIO()

    result = main(
        ["health", "--json"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
    )

    value = json.loads(stdout.getvalue())
    assert result == 3
    assert value["status"] == "unknown"
    assert value["checks"][0]["id"] == "configuration"


def test_health_watch_reuses_provider_and_interval(tmp_path: Path) -> None:
    stdout = io.StringIO()
    sleeps: list[float] = []
    provider = FakeHealthProvider(
        [
            health_report(HealthStatus.HEALTHY),
            health_report(HealthStatus.CRITICAL),
        ]
    )

    result = main(
        ["health", "--watch", "--json", "--interval", "0.5"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        health_factory=lambda _paths: provider,
        sleeper=sleeps.append,
        watch_iterations=2,
    )

    values = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert result == 2
    assert [value["status"] for value in values] == ["healthy", "critical"]
    assert sleeps == [0.5]


def test_health_rejects_unsafe_watch_interval(tmp_path: Path) -> None:
    stdout = io.StringIO()

    result = main(
        ["health", "--json", "--interval", "0.1"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        health_factory=lambda _paths: FakeHealthProvider(
            [health_report(HealthStatus.HEALTHY)]
        ),
    )

    assert result == 3
    assert json.loads(stdout.getvalue())["status"] == "unknown"


class FakeRuleProvider:
    def status(self):
        return {
            "schema_version": 1,
            "source": "et/open",
            "active": {"exists": False},
            "candidate_count": 0,
        }

    def stage(self):
        return {"candidate_id": "00000000-0000-0000-0000-000000000001", "status": "policy_passed"}

    def diff(self, _candidate_id):
        return RuleDiff(10, 10, ("1:3",), (), (), 0, True, ())

    def validate(self, candidate_id):
        return {"candidate_id": candidate_id, "status": "validated"}

    def regress(self, candidate_id, pack_id):
        return {
            "candidate_id": candidate_id,
            "status": "regression_passed",
            "regression": {"status": "passed", "pack_id": pack_id},
        }

    def promote(self, _candidate_id):
        raise RuleOperationError("privileged helper required")


def test_rule_status_and_diff_json_cli(tmp_path: Path) -> None:
    provider = FakeRuleProvider()
    stdout = io.StringIO()

    result = main(
        ["rules", "status", "--json"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        rules_factory=lambda _paths: provider,
    )

    assert result == 0
    assert json.loads(stdout.getvalue())["source"] == "et/open"

    stdout = io.StringIO()
    result = main(
        ["rules", "diff", "00000000-0000-0000-0000-000000000001", "--json"],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        rules_factory=lambda _paths: provider,
    )
    assert result == 0
    assert json.loads(stdout.getvalue())["added"] == ["1:3"]


def test_rule_promotion_gate_returns_expected_error(tmp_path: Path) -> None:
    stderr = io.StringIO()

    result = main(
        ["rules", "promote", "00000000-0000-0000-0000-000000000001"],
        paths=MeercataPaths.isolated(tmp_path),
        stderr=stderr,
        rules_factory=lambda _paths: FakeRuleProvider(),
    )

    assert result == 3
    assert "privileged helper" in stderr.getvalue()


def test_rule_regression_json_cli(tmp_path: Path) -> None:
    stdout = io.StringIO()

    result = main(
        [
            "rules",
            "regress",
            "00000000-0000-0000-0000-000000000001",
            "et-open-smoke-v1",
            "--json",
        ],
        paths=MeercataPaths.isolated(tmp_path),
        stdout=stdout,
        rules_factory=lambda _paths: FakeRuleProvider(),
    )

    value = json.loads(stdout.getvalue())
    assert result == 0
    assert value["status"] == "regression_passed"
    assert value["regression"]["pack_id"] == "et-open-smoke-v1"
