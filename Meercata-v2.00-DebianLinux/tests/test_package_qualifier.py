from __future__ import annotations

from collections.abc import Callable, Iterator
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile

import pytest

from meercata.command_runner import CommandRunner
from meercata.errors import PackagingError, QualificationError
from meercata.models import CommandResult
from meercata.package_builder import ProductionPackageBuilder
from meercata.package_qualifier import StagedImageQualifier, main


SOURCE_ROOT = Path(__file__).parents[1]


@pytest.fixture
def workspace() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="meercata-qualifier-tests-") as directory:
        yield Path(directory)


def _stage(workspace: Path, source: Path = SOURCE_ROOT) -> Path:
    root = workspace / "stage"
    ProductionPackageBuilder(source, root).stage()
    return root


def _fingerprint(root: Path) -> dict[str, tuple[str, int]]:
    result = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        content = path.read_bytes()
        result[str(path.relative_to(root))] = (
            hashlib.sha256(content).hexdigest(),
            path.stat().st_mode & 0o777,
        )
    return result


def _source_copy(workspace: Path) -> Path:
    target = workspace / "source"
    shutil.copytree(
        SOURCE_ROOT,
        target,
        ignore=shutil.ignore_patterns(".pytest*", "__pycache__", "*.pyc"),
    )
    return target


def test_qualifier_passes_all_disposable_root_checks_without_changing_stage(
    workspace: Path,
) -> None:
    stage = _stage(workspace)
    before = _fingerprint(stage)

    report = StagedImageQualifier(SOURCE_ROOT, stage).qualify()

    assert report["status"] == "staged-qualified"
    assert report["version"] == "2.0.0.dev25"
    assert [item["check_id"] for item in report["checks"]] == [
        "package.manifest",
        "python.imports",
        "sudoers.syntax",
        "systemd.units",
        "sysusers.materialize",
        "tmpfiles.dry-run",
    ]
    assert all(item["status"] == "passed" for item in report["checks"])
    assert "root ownership" in report["limitations"][0]
    assert _fingerprint(stage) == before


def test_qualification_report_conforms_to_versioned_schema(workspace: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    stage = _stage(workspace)
    report = StagedImageQualifier(SOURCE_ROOT, stage).qualify()
    schema = json.loads(
        (SOURCE_ROOT / "schemas/qualification-v1.schema.json").read_text()
    )

    jsonschema.validate(report, schema)


def test_qualifier_cli_emits_one_json_report(workspace: Path) -> None:
    stage = _stage(workspace)
    stdout = io.StringIO()

    result = main(
        [str(stage), "--source-root", str(SOURCE_ROOT)], stdout=stdout
    )

    assert result == 0
    assert json.loads(stdout.getvalue())["status"] == "staged-qualified"


def test_qualifier_rejects_tampered_stage_before_host_tools(workspace: Path) -> None:
    stage = _stage(workspace)
    (stage / "usr/bin/meercata").write_text("tampered\n")

    with pytest.raises(PackagingError, match="verification failed"):
        StagedImageQualifier(SOURCE_ROOT, stage).qualify()


class _FailedRunner:
    def __init__(self, command_id: str, command) -> None:
        self.command_id = command_id
        self.command = command

    def run(self, command_id: str) -> CommandResult:
        return CommandResult(
            command_id,
            self.command.argv,
            1,
            "",
            "injected failure",
            False,
            False,
            False,
            "2026-08-13T00:00:00Z",
            0.1,
        )


def test_qualifier_fails_closed_when_external_validator_fails(
    workspace: Path,
) -> None:
    stage = _stage(workspace)

    def factory(commands):
        command_id, command = next(iter(commands.items()))
        if command_id == "systemd.units":
            return _FailedRunner(command_id, command)
        return CommandRunner(commands)

    with pytest.raises(QualificationError, match="systemd.units failed"):
        StagedImageQualifier(
            SOURCE_ROOT, stage, runner_factory=factory
        ).qualify()


@pytest.mark.parametrize(
    "relative,mutate,expected",
    [
        (
            "packaging/sudoers.d/meercata",
            lambda path: path.write_text("invalid sudoers policy\n"),
            "sudoers.syntax failed",
        ),
        (
            "packaging/systemd/system/meercata-health.service",
            lambda path: path.write_text("invalid systemd unit\n"),
            "systemd.units failed",
        ),
        (
            "packaging/sysusers.d/meercata.conf",
            lambda path: path.write_text(
                path.read_text() + "m meercata meercata-operators\n"
            ),
            "separation policy",
        ),
        (
            "packaging/tmpfiles.d/meercata.conf",
            lambda path: path.write_text(
                "\n".join(
                    line
                    for line in path.read_text().splitlines()
                    if "/run/meercata" not in line
                )
                + "\n"
            ),
            "omitted a managed directory",
        ),
        (
            "packaging/tmpfiles.d/meercata.conf",
            lambda path: path.write_text(
                path.read_text().replace(
                    "/var/lib/meercata/privileged                  0700",
                    "/var/lib/meercata/privileged                  0755",
                )
            ),
            "mode or ownership is invalid",
        ),
        (
            "meercata/health.py",
            lambda path: path.write_text("this is invalid Python\n"),
            "python.imports failed",
        ),
    ],
)
def test_qualifier_detects_validly_packaged_but_invalid_host_policy(
    workspace: Path,
    relative: str,
    mutate: Callable[[Path], object],
    expected: str,
) -> None:
    source = _source_copy(workspace)
    target = source / relative
    target.chmod(0o644)
    mutate(target)
    stage = _stage(workspace, source)

    with pytest.raises(QualificationError, match=expected):
        StagedImageQualifier(source, stage).qualify()
