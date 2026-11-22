"""Bounded Suricata rule indexing and deterministic policy differences."""

from __future__ import annotations

import hashlib
import re
from collections import Counter

from meercata.errors import RuleParseError
from meercata.rule_models import RuleDiff, RuleSetSummary, RuleSignature

MAX_RULESET_BYTES = 128 * 1024 * 1024
_ACTIONS = {"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
_OPTION = re.compile(r"(?:^|[;(])\s*(gid|sid|rev)\s*:\s*([0-9]+)\s*(?=;|$)", re.IGNORECASE)


def summarize_ruleset(data: bytes) -> RuleSetSummary:
    if len(data) > MAX_RULESET_BYTES:
        raise RuleParseError("ruleset exceeds the 128 MiB indexing limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuleParseError("ruleset is not valid UTF-8") from exc

    signatures: list[RuleSignature] = []
    action_counts: Counter[str] = Counter()
    disabled = 0
    active_keys: set[tuple[int, int]] = set()
    for line_number, logical in _logical_lines(text):
        stripped = logical.strip()
        if not stripped:
            continue
        enabled = not stripped.startswith("#")
        body = stripped if enabled else stripped[1:].lstrip()
        action = body.partition(" ")[0].lower()
        if action not in _ACTIONS:
            continue
        options = _extract_options(body)
        if "sid" not in options:
            if enabled:
                raise RuleParseError(f"active rule at line {line_number} has no numeric sid")
            continue
        gid = options.get("gid", 1)
        sid = options["sid"]
        rev = options.get("rev", 0)
        if min(gid, sid) < 1 or rev < 0:
            raise RuleParseError(f"rule at line {line_number} has an invalid gid, sid, or rev")
        normalized = " ".join(body.split())
        signature = RuleSignature(
            gid,
            sid,
            rev,
            action,
            enabled,
            hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        )
        if enabled:
            if signature.key in active_keys:
                raise RuleParseError(f"duplicate active rule identity {gid}:{sid}")
            active_keys.add(signature.key)
            action_counts[action] += 1
            signatures.append(signature)
        else:
            disabled += 1

    signatures.sort(key=lambda item: item.key)
    return RuleSetSummary(
        hashlib.sha256(data).hexdigest(),
        len(data),
        len(signatures),
        disabled,
        dict(action_counts),
        tuple(signatures),
    )


def compare_rulesets(
    baseline: RuleSetSummary,
    candidate: RuleSetSummary,
    *,
    minimum_rule_count: int,
    maximum_reduction_percent: float,
) -> RuleDiff:
    before = {item.key: item for item in baseline.signatures}
    after = {item.key: item for item in candidate.signatures}
    added_keys = sorted(after.keys() - before.keys())
    removed_keys = sorted(before.keys() - after.keys())
    changed_keys = sorted(
        key
        for key in before.keys() & after.keys()
        if (
            before[key].rev,
            before[key].action,
            before[key].fingerprint,
        )
        != (
            after[key].rev,
            after[key].action,
            after[key].fingerprint,
        )
    )
    reduction = 0.0
    if baseline.active_rules and candidate.active_rules < baseline.active_rules:
        reduction = round(
            (baseline.active_rules - candidate.active_rules) * 100 / baseline.active_rules,
            6,
        )
    reasons: list[str] = []
    if candidate.active_rules < minimum_rule_count:
        reasons.append(
            f"candidate has {candidate.active_rules} active rules; minimum is {minimum_rule_count}"
        )
    if reduction > maximum_reduction_percent:
        reasons.append(
            f"rule count reduction {reduction:g}% exceeds {maximum_reduction_percent:g}%"
        )
    return RuleDiff(
        baseline.active_rules,
        candidate.active_rules,
        tuple(_format_key(key) for key in added_keys),
        tuple(_format_key(key) for key in removed_keys),
        tuple(_format_key(key) for key in changed_keys),
        reduction,
        not reasons,
        tuple(reasons),
    )


def _logical_lines(text: str):
    buffer = ""
    start = 1
    for number, physical in enumerate(text.splitlines(), 1):
        if not buffer:
            start = number
        trimmed = physical.rstrip()
        continued = trimmed.endswith("\\") and not trimmed.endswith("\\\\")
        buffer += trimmed[:-1] + " " if continued else physical
        if not continued:
            yield start, buffer
            buffer = ""
    if buffer:
        yield start, buffer


def _extract_options(body: str) -> dict[str, int]:
    # Skip quoted values so strings such as msg:"sid:1;" cannot impersonate
    # structural options. PCRE character classes may contain an unescaped quote.
    fast = _suffix_options(body)
    if fast is not None:
        return fast
    values: dict[str, int] = {}
    index = 0
    option_start = 0
    while index < len(body):
        character = body[index]
        if index == 0 or character in "(;":
            match = _OPTION.match(body, index)
            if match is not None:
                name = match.group(1).lower()
                if name in values:
                    raise RuleParseError(f"rule contains duplicate {name} options")
                values[name] = int(match.group(2))
                index = match.end()
                continue
            if character in "(;":
                option_start = index + 1
        if character != '"':
            index += 1
            continue
        end = (
            _pcre_quote_end(body, index)
            if body[option_start:index].strip().lower() == "pcre:"
            else _generic_quote_end(body, index)
        )
        if end is None:
            return {}
        index = end + 1
    return values


def _suffix_options(body: str) -> dict[str, int] | None:
    last_quote = body.rfind('"')
    if last_quote < 0:
        return _collect_option_matches(body)
    if not body[last_quote + 1 :].lstrip().startswith(";"):
        return None
    prefix = body[: last_quote + 1].lower()
    if any(name in prefix for name in ("gid:", "sid:", "rev:")):
        return None
    values = _collect_option_matches(body, last_quote + 1)
    return values if "sid" in values else None


def _collect_option_matches(body: str, start: int = 0) -> dict[str, int]:
    values: dict[str, int] = {}
    for match in _OPTION.finditer(body, start):
        name = match.group(1).lower()
        if name in values:
            raise RuleParseError(f"rule contains duplicate {name} options")
        values[name] = int(match.group(2))
    return values


def _generic_quote_end(body: str, start: int) -> int | None:
    escaped = False
    for index in range(start + 1, len(body)):
        character = body[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            return index
    return None


def _pcre_quote_end(body: str, start: int) -> int | None:
    escaped = False
    character_class = False
    for index in range(start + 1, len(body)):
        character = body[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            character_class = True
        elif character == "]" and character_class:
            character_class = False
        elif character == '"' and not character_class:
            return index
    return None


def _format_key(key: tuple[int, int]) -> str:
    return f"{key[0]}:{key[1]}"
