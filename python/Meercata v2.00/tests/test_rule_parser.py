from __future__ import annotations

import pytest

from meercata.errors import RuleParseError
from meercata.rule_parser import compare_rulesets, summarize_ruleset


def test_summarize_ruleset_handles_comments_quotes_and_continuations() -> None:
    data = b'''# metadata comment
alert tcp any any -> any 80 (msg:"contains ; sid:999;"; \\
  flow:to_server; sid:1001; rev:2;)
# drop tcp any any -> any 443 (sid:1002; rev:1;)
pass udp any any -> any 53 (gid:2; sid:3; rev:1;)
'''

    summary = summarize_ruleset(data)

    assert summary.active_rules == 2
    assert summary.disabled_rules == 1
    assert summary.action_counts == {"alert": 1, "pass": 1}
    assert [(rule.gid, rule.sid, rule.rev) for rule in summary.signatures] == [
        (1, 1001, 2),
        (2, 3, 1),
    ]


def test_summarize_ruleset_handles_quote_inside_pcre_character_class() -> None:
    data = (
        b'alert http any any -> any any (msg:"ET fixture"; '
        b'pcre:"/^["\']?post/Ri"; sid:2029732; rev:2;)\n'
    )

    summary = summarize_ruleset(data)

    assert summary.active_rules == 1
    assert [(rule.gid, rule.sid, rule.rev) for rule in summary.signatures] == [
        (1, 2029732, 2)
    ]


def test_summarize_ruleset_rejects_duplicate_active_identity() -> None:
    rules = b"""alert ip any any -> any any (sid:1; rev:1;)\npass ip any any -> any any (sid:1; rev:2;)\n"""

    with pytest.raises(RuleParseError, match="duplicate active rule identity 1:1"):
        summarize_ruleset(rules)


def test_summarize_ruleset_rejects_active_rule_without_sid_and_invalid_utf8() -> None:
    with pytest.raises(RuleParseError, match="has no numeric sid"):
        summarize_ruleset(b'alert ip any any -> any any (msg:"bad";)\n')
    with pytest.raises(RuleParseError, match="has no numeric sid"):
        summarize_ruleset(b'alert ip any any -> any any (msg:"bad; sid:7;)\n')
    with pytest.raises(RuleParseError, match="UTF-8"):
        summarize_ruleset(b"\xff")


def test_compare_rulesets_reports_added_removed_changed_and_reduction_policy() -> None:
    baseline = summarize_ruleset(
        b"""alert ip any any -> any any (sid:1; rev:1;)\nalert ip any any -> any any (sid:2; rev:1;)\n"""
    )
    candidate = summarize_ruleset(
        b"""drop ip any any -> any any (sid:1; rev:2;)\nalert ip any any -> any any (sid:3; rev:1;)\n"""
    )

    difference = compare_rulesets(
        baseline,
        candidate,
        minimum_rule_count=3,
        maximum_reduction_percent=5,
    )

    assert difference.added == ("1:3",)
    assert difference.removed == ("1:2",)
    assert difference.changed == ("1:1",)
    assert not difference.policy_allowed
    assert "minimum is 3" in difference.policy_reasons[0]


def test_compare_rulesets_blocks_unexpected_reduction() -> None:
    baseline = summarize_ruleset(
        b"".join(
            f"alert ip any any -> any any (sid:{sid}; rev:1;)\n".encode()
            for sid in range(1, 11)
        )
    )
    candidate = summarize_ruleset(
        b"".join(
            f"alert ip any any -> any any (sid:{sid}; rev:1;)\n".encode()
            for sid in range(1, 9)
        )
    )

    difference = compare_rulesets(
        baseline,
        candidate,
        minimum_rule_count=1,
        maximum_reduction_percent=5,
    )

    assert difference.reduction_percent == 20
    assert not difference.policy_allowed


def test_rule_diff_serialization_is_bounded() -> None:
    baseline = summarize_ruleset(b"")
    candidate = summarize_ruleset(
        b"".join(
            f"alert ip any any -> any any (sid:{sid}; rev:1;)\n".encode()
            for sid in range(1, 6)
        )
    )
    difference = compare_rulesets(
        baseline,
        candidate,
        minimum_rule_count=1,
        maximum_reduction_percent=5,
    )

    value = difference.to_dict(max_identities=2)

    assert value["added"] == ["1:1", "1:2"]
    assert value["added_total"] == 5
    assert value["identity_lists_truncated"] is True
