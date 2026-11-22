import json
from pathlib import Path

import pytest

from meercata.audit import AuditLogger
from meercata.errors import AuditError
from meercata.models import Actor


ACTOR = Actor(uid=1000, gid=1000, invocation_source="test", pid=123)


def test_audit_writes_one_structured_json_line(tmp_path: Path) -> None:
    path = tmp_path / "log" / "audit.jsonl"

    AuditLogger(path).record(
        "transaction.requested",
        actor=ACTOR,
        outcome="requested",
        transaction_id="11111111-1111-1111-1111-111111111111",
        operation="rules.update",
        data={"secret": "[redacted]"},
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["schema_version"] == 1
    assert record["actor"]["uid"] == 1000
    assert record["data"]["secret"] == "[redacted]"


def test_audit_appends_without_overwriting(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.record("one", actor=ACTOR, outcome="success")
    logger.record("two", actor=ACTOR, outcome="failure")

    assert [json.loads(line)["event"] for line in path.read_text().splitlines()] == [
        "one",
        "two",
    ]


def test_audit_rejects_nonserializable_data(tmp_path: Path) -> None:
    with pytest.raises(AuditError):
        AuditLogger(tmp_path / "audit.jsonl").record(
            "invalid",
            actor=ACTOR,
            outcome="failure",
            data={"bad": object()},
        )


def test_audit_rejects_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("preserve", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)

    with pytest.raises(AuditError):
        AuditLogger(link).record("event", actor=ACTOR, outcome="success")
    assert target.read_text(encoding="utf-8") == "preserve"
