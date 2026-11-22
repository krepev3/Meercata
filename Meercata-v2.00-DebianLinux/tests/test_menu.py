from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from meercata.cli import main
from meercata.errors import RuleOperationError
from meercata.health_models import HealthCheck, HealthReport, HealthStatus
from meercata.menu import TerminalMenu
from meercata.paths import MeercataPaths

ID = "11111111-2222-4333-8444-555555555555"


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def plain_terminal(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")


def exercise(tmp_path, script, *, invoke=None):
    calls = []
    output, errors = Terminal(), Terminal()

    def record(argv, stdout, stderr):
        calls.append(tuple(argv))
        if invoke:
            return invoke(argv, stdout, stderr)
        print(json.dumps({"status": "test-result"}), file=stdout)
        return 0

    menu = TerminalMenu(MeercataPaths.isolated(tmp_path), record, Terminal(script), output, errors)
    code = menu.run()
    return code, output.getvalue(), errors.getvalue(), calls


@pytest.mark.parametrize("argv", [[], ["menu"]])
def test_interactive_entry_opens_without_installation_or_state(tmp_path, argv):
    output = Terminal()

    def forbidden(_paths):
        pytest.fail("merely opening the menu must not initialize a backend")

    assert main(argv, paths=MeercataPaths.isolated(tmp_path), stdin=Terminal("0\n"),
                stdout=output, health_factory=forbidden, rules_factory=forbidden,
                monitor_factory=forbidden, delivery_factory=forbidden) == 0
    text = output.getvalue()
    assert "MEERCATA v2.00" in text
    assert "UNCONFIGURED / UNREADABLE" in text
    assert "1) Suricata control" in text
    assert "2) Threat Monitoring" in text
    assert "8) Transactions / recovery" in text
    assert "Bye." in text
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("input_tty,output_tty", [(False, False), (False, True), (True, False)])
def test_explicit_menu_refuses_noninteractive_streams(tmp_path, input_tty, output_tty):
    stdin = Terminal("0\n") if input_tty else io.StringIO("0\n")
    stdout = Terminal() if output_tty else io.StringIO()
    stderr = io.StringIO()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=stdin,
                stdout=stdout, stderr=stderr) == 2
    assert "requires an interactive" in stderr.getvalue()
    assert "Select option" not in stdout.getvalue()


def test_noninteractive_no_arguments_retains_help(tmp_path):
    stdout = io.StringIO()
    assert main([], paths=MeercataPaths.isolated(tmp_path), stdin=io.StringIO(), stdout=stdout) == 2
    assert "usage:" in stdout.getvalue()
    assert "Select option" not in stdout.getvalue()


def test_gate_entries_never_dispatch_a_command(tmp_path):
    script = "1\n1\n\n2\n\n0\n3\n6\n\n7\n\n0\n4\n2\n\n0\n5\n4\n\n0\n2\n1\n\n0\n0\n"
    code, output, _, calls = exercise(tmp_path, script)
    assert code == 0
    assert calls == []
    assert output.count("[UNAVAILABLE]") == 7
    assert "not packet alerts" in output
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("script,expected", [
    ("2\n2\n\n0\n0\n", ("monitor", "status", "--json")),
    ("2\n3\n\n0\n0\n", ("monitor", "events", "--json", "--limit", "20")),
    ("2\n5\n\n0\n0\n", ("monitor", "freshness", "--json")),
    ("2\n7\n1\n\n0\n0\n0\n", ("monitor", "delivery-status", "--json")),
    ("2\n7\n2\n\n0\n0\n0\n", ("monitor", "delivery-health", "--json")),
    ("2\n7\n3\n\n0\n0\n0\n", ("monitor", "dead-letters", "--json", "--limit", "20")),
    ("3\n1\n\n0\n0\n", ("rules", "status", "--json")),
    (f"3\n3\n{ID}\n\n0\n0\n", ("rules", "diff", ID, "--json")),
    ("8\n1\n\n0\n0\n", ("transactions", "list")),
    ("8\n2\n\n0\n0\n", ("transactions", "list", "--incomplete")),
    ("8\n3\n\n0\n0\n", ("transactions", "list", "--recovery-required")),
    (f"8\n4\n{ID}\n\n0\n0\n", ("transactions", "show", ID, "--json")),
])
def test_menu_routes_existing_read_commands(tmp_path, script, expected):
    code, output, _, calls = exercise(tmp_path, script)
    assert code == 0
    assert calls == [expected]
    assert "Command exit code: 0" in output


@pytest.mark.parametrize("prefix,suffix,expected", [
    ("2\n4\n", "\n0\n0\n", ("monitor", "run", "--json")),
    ("2\n7\n4\n", "\n0\n0\n0\n", ("monitor", "deliver", "--json")),
    ("3\n2\n", "\n0\n0\n", ("rules", "stage", "--json")),
    (f"3\n4\n{ID}\n", "\n0\n0\n", ("rules", "validate", ID, "--json")),
    (f"3\n5\n{ID}\nproduction-baseline-v1\n", "\n0\n0\n",
     ("rules", "regress", ID, "production-baseline-v1", "--json")),
])
@pytest.mark.parametrize("answer,allowed", [("", False), ("n", False), ("maybe", False), ("yes", True)])
def test_mutating_actions_require_explicit_confirmation(tmp_path, prefix, suffix, expected, answer, allowed):
    code, output, _, calls = exercise(tmp_path, prefix + answer + "\n" + suffix)
    assert code == 0
    assert calls == ([expected] if allowed else [])
    if not allowed:
        assert "Cancelled." in output


@pytest.mark.parametrize("value", ["--help", "../../etc/passwd", "not-a-uuid", ID.replace("-", "")])
def test_bad_candidate_input_cannot_become_options_or_paths(tmp_path, value):
    code, output, _, calls = exercise(tmp_path, f"3\n3\n{value}\n\n0\n0\n")
    assert code == 0
    assert calls == []
    assert "canonical lowercase UUID" in output


@pytest.mark.parametrize("value", ["--help", "../pack", "pack;id", "a b"])
def test_bad_pack_input_cannot_reach_backend(tmp_path, value):
    _, output, _, calls = exercise(tmp_path, f"3\n5\n{ID}\n{value}\n\n0\n0\n")
    assert calls == []
    assert "Pack ID" in output


def test_blank_candidate_cancels_without_backend_call(tmp_path):
    _, output, _, calls = exercise(tmp_path, "3\n3\n\n\n0\n0\n")
    assert calls == []
    assert "Cancelled." in output


def test_pack_identifier_matches_existing_regression_contract(tmp_path):
    _, _, _, calls = exercise(tmp_path, f"3\n5\n{ID}\nsite.v1\nyes\n\n0\n0\n")
    assert calls == [("rules", "regress", ID, "site.v1", "--json")]


def test_health_snapshot_uses_existing_provider_and_updates_dashboard(tmp_path):
    report = HealthReport("ids", (HealthCheck("service", HealthStatus.DEGRADED, "service is starting"),))

    class Health:
        def collect(self):
            return report

    output = Terminal()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=Terminal("7\n\n0\n"),
                stdout=output, health_factory=lambda _paths: Health()) == 0
    assert "Health: DEGRADED | mode=ids | exit=1" in output.getvalue()
    assert "Last health   : DEGRADED at" in output.getvalue()
    assert "Last service  : service is starting" in output.getvalue()


def test_missing_configuration_health_is_unknown_and_menu_survives(tmp_path):
    output = Terminal()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=Terminal("7\n\n0\n"), stdout=output) == 0
    assert "Health: UNKNOWN" in output.getvalue()
    assert "Last health   : UNKNOWN at" in output.getvalue()
    assert list(tmp_path.iterdir()) == []


def test_watch_interrupt_returns_to_menu_and_preserves_provider(tmp_path):
    calls = []

    class Health:
        def collect(self):
            calls.append("collect")
            return HealthReport("ids", (HealthCheck("service", HealthStatus.HEALTHY, "running"),))

    def interrupt(_seconds):
        raise KeyboardInterrupt

    output = Terminal()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=Terminal("1\n4\n\n0\n0\n"),
                stdout=output, health_factory=lambda _paths: Health(), sleeper=interrupt) == 0
    assert calls == ["collect"]
    assert "Watch stopped." in output.getvalue()
    assert "Bye." in output.getvalue()


def test_cli_error_is_visible_sanitized_and_does_not_exit_menu(tmp_path):
    class Rules:
        def status(self):
            raise RuleOperationError("unsafe display \x1b[2J")

    output, errors = Terminal(), Terminal()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=Terminal("3\n1\n\n0\n0\n"),
                stdout=output, stderr=errors, rules_factory=lambda _paths: Rules()) == 0
    assert "unsafe display \\x1b[2J" in errors.getvalue()
    assert "\x1b" not in errors.getvalue()
    assert "Command exit code: 3" in output.getvalue()


def test_permission_failure_preserves_menu(tmp_path):
    def fail(*args):
        raise PermissionError("protected state")

    code, output, _, _ = exercise(tmp_path, "8\n1\n\n0\n0\n", invoke=fail)
    assert code == 0
    assert "Access denied" in output
    assert "Bye." in output


def test_eof_during_confirmation_cancels_without_dispatch(tmp_path):
    code, output, _, calls = exercise(tmp_path, "3\n2\n")
    assert code == 0
    assert calls == []
    assert "Input closed" in output


def test_ctrl_c_at_main_prompt_exits_cleanly(tmp_path):
    class Interrupted(Terminal):
        def readline(self, *args):
            raise KeyboardInterrupt

    output = Terminal()
    assert main(["menu"], paths=MeercataPaths.isolated(tmp_path), stdin=Interrupted(), stdout=output) == 130
    assert "Bye." in output.getvalue()


def test_invalid_selection_can_be_retried(tmp_path):
    code, output, _, calls = exercise(tmp_path, "wrong\n\n0\n")
    assert code == 0
    assert calls == []
    assert "Invalid selection" in output


def test_configuration_view_does_not_print_delivery_credentials(tmp_path):
    paths = MeercataPaths.isolated(tmp_path)
    paths.config_dir.mkdir(parents=True)
    paths.controller_config_file.write_text(
        'schema_version=1\n[health]\nmode="ids"\ninterface="eth0"\n'
        '[monitor_delivery]\nendpoint="https://private-collector.example/secret-path"\n'
        'token_file="/etc/meercata/credentials/private-token"\n'
    )
    before = paths.controller_config_file.read_bytes()
    code, output, _, calls = exercise(tmp_path, "6\n\n0\n")
    assert code == 0
    assert calls == [("paths",)]
    assert "interface: eth0" in output
    assert "secret-path" not in output
    assert "private-token" not in output
    assert paths.controller_config_file.read_bytes() == before


def test_no_color_environment_disables_banner_color(tmp_path, monkeypatch):
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("NO_COLOR", "")
    _, output, _, _ = exercise(tmp_path, "0\n")
    assert "\x1b[38;5;208m" not in output
