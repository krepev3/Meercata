import os
import sys
from pathlib import Path

import pytest

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import InvalidCommandError, UnknownCommandError


def definition(code: str, *, timeout: float = 2.0) -> CommandDefinition:
    return CommandDefinition.fixed(
        (sys.executable, "-c", code),
        timeout_seconds=timeout,
        working_directory=Path("/"),
    )


def test_command_runner_returns_structured_result() -> None:
    runner = CommandRunner({"test.ok": definition("print('ready')")})

    result = runner.run("test.ok")

    assert result.succeeded
    assert result.stdout == "ready\n"
    assert result.stderr == ""
    assert result.argv[0] == sys.executable


def test_command_runner_denies_unknown_command() -> None:
    runner = CommandRunner({"test.ok": definition("pass")})

    with pytest.raises(UnknownCommandError):
        runner.run("caller-controlled")


def test_command_runner_rejects_relative_executable() -> None:
    with pytest.raises(InvalidCommandError):
        CommandRunner({"unsafe": CommandDefinition.fixed(("python3", "-V"))})


def test_command_runner_uses_allowlisted_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEERCATA_TEST_SECRET", "must-not-leak")
    runner = CommandRunner(
        {
            "test.env": definition(
                "import os; print(os.environ.get('MEERCATA_TEST_SECRET', 'absent'))"
            )
        }
    )

    result = runner.run("test.env")

    assert result.stdout == "absent\n"


def test_command_runner_passes_only_explicitly_allowed_build_environment() -> None:
    runner = CommandRunner(
        {
            "test.env": CommandDefinition.fixed(
                (
                    sys.executable,
                    "-c",
                    "import os; print(os.environ['SOURCE_DATE_EPOCH'])",
                ),
                environment={"SOURCE_DATE_EPOCH": "1786579200"},
            )
        }
    )

    assert runner.run("test.env").stdout == "1786579200\n"


@pytest.mark.parametrize(
    "environment",
    [
        {"LD_PRELOAD": "/tmp/unsafe.so"},
        {"SOURCE_DATE_EPOCH": ""},
        {"SOURCE_DATE_EPOCH": "x" * 129},
    ],
)
def test_command_runner_rejects_unsafe_build_environment(environment) -> None:
    with pytest.raises(InvalidCommandError, match="environment"):
        CommandRunner(
            {
                "unsafe": CommandDefinition.fixed(
                    (sys.executable, "-V"), environment=environment
                )
            }
        )


def test_command_runner_bounds_stdout_and_stderr() -> None:
    runner = CommandRunner(
        {
            "test.output": definition(
                "import sys; sys.stdout.write('a'*10000); sys.stderr.write('b'*10000)"
            )
        },
        max_output_bytes=128,
    )

    result = runner.run("test.output")

    assert len(result.stdout.encode()) == 128
    assert len(result.stderr.encode()) == 128
    assert result.stdout_truncated
    assert result.stderr_truncated


def test_command_runner_terminates_timed_out_process_group() -> None:
    runner = CommandRunner(
        {"test.timeout": definition("import time; time.sleep(10)", timeout=0.1)},
        termination_grace_seconds=0.1,
    )

    result = runner.run("test.timeout")

    assert result.timed_out
    assert not result.succeeded
    assert result.duration_seconds < 2


def test_command_definition_rejects_nul_argument() -> None:
    with pytest.raises(InvalidCommandError):
        CommandRunner(
            {"unsafe": CommandDefinition.fixed((sys.executable, "bad\x00argument"))}
        )
