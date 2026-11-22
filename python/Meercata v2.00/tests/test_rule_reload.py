from __future__ import annotations

from pathlib import Path

import pytest

from meercata.errors import RuleOperationError
from meercata.rule_reload import (
    RuleReloadController,
    RuleReloadSocketClient,
)


class FakeSession:
    def __init__(self, responses):
        self.responses = {key: list(value) for key, value in responses.items()}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def request(self, command):
        self.calls.append(command)
        values = self.responses[command]
        return values.pop(0) if len(values) > 1 else values[0]


def test_reload_controller_polls_completion_and_verifies_statistics() -> None:
    session = FakeSession(
        {
            "ruleset-reload-time": ["old", "old", "new"],
            "ruleset-reload-nonblocking": ["done"],
            "ruleset-stats": [{"rules_loaded": 42}],
            "ruleset-failed-rules": [[]],
        }
    )
    sleeps = []
    controller = RuleReloadController(
        lambda: session,
        timeout_seconds=10,
        poll_seconds=1,
        clock=lambda: 0,
        sleeper=sleeps.append,
    )

    result = controller.reload_and_verify()

    assert result["reload_time_after"] == "new"
    assert result["ruleset_stats"] == {"rules_loaded": 42}
    assert result["failed_rules"] == 0
    assert sleeps == [1, 1]


def test_reload_controller_times_out() -> None:
    session = FakeSession(
        {
            "ruleset-reload-time": ["unchanged"],
            "ruleset-reload-nonblocking": ["done"],
        }
    )
    times = iter([0, 1, 3])
    controller = RuleReloadController(
        lambda: session,
        timeout_seconds=2,
        poll_seconds=1,
        clock=lambda: next(times),
        sleeper=lambda _seconds: None,
    )

    with pytest.raises(RuleOperationError, match="timed out"):
        controller.reload_and_verify()


def test_reload_controller_rejects_failed_rules_and_invalid_response() -> None:
    failed = FakeSession(
        {
            "ruleset-reload-time": [1, 2],
            "ruleset-reload-nonblocking": ["done"],
            "ruleset-stats": [{}],
            "ruleset-failed-rules": [[{"sid": 1}]],
        }
    )
    controller = RuleReloadController(
        lambda: failed,
        timeout_seconds=2,
        poll_seconds=1,
        clock=lambda: 0,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(RuleOperationError, match="1 failed rules"):
        controller.reload_and_verify()

    invalid = FakeSession(
        {
            "ruleset-reload-time": [1, 2],
            "ruleset-reload-nonblocking": ["done"],
            "ruleset-stats": [{}],
            "ruleset-failed-rules": [{"bad": "shape"}],
        }
    )
    controller = RuleReloadController(
        lambda: invalid,
        timeout_seconds=2,
        poll_seconds=1,
        clock=lambda: 0,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(RuleOperationError, match="invalid failed-rule"):
        controller.reload_and_verify()


def test_reload_socket_client_denies_non_rule_command() -> None:
    client = RuleReloadSocketClient(Path("/run/suricata/test.socket"), 1)

    with pytest.raises(RuleOperationError, match="not RuleOps allowlisted"):
        client.request("shutdown")
