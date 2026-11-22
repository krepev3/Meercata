"""Deterministic, owned nftables policy for fail-open NFQUEUE IPS."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from meercata.errors import NftablesPolicyError
from meercata.health_config import INTERFACE_PATTERN
from meercata.ips_config import IpsConfig

NFT_FAMILY = "inet"
NFT_TABLE = "meercata"
NFT_CHAIN = "forward"
NFT_HOOK_PRIORITY = 10
OWNERSHIP_PREFIX = "meercata-managed:v1"
_OWNER_PATTERN = re.compile(
    rf"{re.escape(OWNERSHIP_PREFIX)}:([0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})\Z"
)


@dataclass(frozen=True, slots=True)
class NftablesPolicy:
    transaction_id: str
    interface: str
    queue: int
    fail_open: bool = True

    @classmethod
    def from_config(cls, transaction_id: str, config: IpsConfig) -> "NftablesPolicy":
        config.validate()
        return cls(transaction_id, config.interface, config.queue, True).validated()

    def validated(self) -> "NftablesPolicy":
        try:
            parsed = uuid.UUID(self.transaction_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise NftablesPolicyError("nftables transaction ID must be a UUID") from exc
        if str(parsed) != self.transaction_id:
            raise NftablesPolicyError("nftables transaction ID must be a canonical lowercase UUID")
        if not isinstance(self.interface, str) or INTERFACE_PATTERN.fullmatch(self.interface) is None:
            raise NftablesPolicyError("nftables interface is invalid")
        if type(self.queue) is not int or not 0 <= self.queue <= 65535:
            raise NftablesPolicyError("nftables queue must be an integer from 0 to 65535")
        if self.fail_open is not True:
            raise NftablesPolicyError("nftables NFQUEUE bypass is mandatory")
        return self

    @property
    def owner_comment(self) -> str:
        return f"{OWNERSHIP_PREFIX}:{self.transaction_id}"

    def render_apply(self, *, replace_owned_table: bool) -> str:
        self.validated()
        lines: list[str] = []
        if replace_owned_table:
            lines.append(f"delete table {NFT_FAMILY} {NFT_TABLE}")
        lines.extend(
            (
                f'add table {NFT_FAMILY} {NFT_TABLE} {{ comment "{self.owner_comment}"; }}',
                f'add chain {NFT_FAMILY} {NFT_TABLE} {NFT_CHAIN} '
                f'{{ type filter hook forward priority {NFT_HOOK_PRIORITY}; policy accept; '
                f'comment "{OWNERSHIP_PREFIX}"; }}',
                _render_rule("iifname", self.interface, self.queue, "in"),
                _render_rule("oifname", self.interface, self.queue, "out"),
            )
        )
        return "\n".join(lines) + "\n"

    def render_remove(self) -> str:
        self.validated()
        return f"delete table {NFT_FAMILY} {NFT_TABLE}\n"


@dataclass(frozen=True, slots=True)
class NftablesInspection:
    transaction_id: str
    interface: str
    queue: int
    fail_open: bool
    semantic_sha256: str


def inspect_owned_table(value: Any) -> NftablesInspection:
    """Validate the complete table and fingerprint stable semantics, not counters/handles."""
    if not isinstance(value, Mapping) or not isinstance(value.get("nftables"), list):
        raise NftablesPolicyError("nftables JSON root is invalid")

    tables: list[Mapping[str, Any]] = []
    chains: list[Mapping[str, Any]] = []
    rules: list[Mapping[str, Any]] = []
    for item in value["nftables"]:
        if not isinstance(item, Mapping):
            raise NftablesPolicyError("nftables JSON contains a non-object item")
        if "metainfo" in item:
            if set(item) != {"metainfo"}:
                raise NftablesPolicyError("nftables metadata item contains another object")
            continue
        recognized = [name for name in ("table", "chain", "rule") if name in item]
        if len(recognized) != 1 or not isinstance(item[recognized[0]], Mapping):
            raise NftablesPolicyError("Meercata table contains an unsupported nftables object")
        target = {"table": tables, "chain": chains, "rule": rules}[recognized[0]]
        target.append(item[recognized[0]])

    if len(tables) != 1:
        raise NftablesPolicyError("expected exactly one Meercata table declaration")
    table = tables[0]
    _require_exact_keys(table, {"family", "name", "handle", "comment"}, "table")
    if table.get("family") != NFT_FAMILY or table.get("name") != NFT_TABLE:
        raise NftablesPolicyError("nftables table is outside Meercata ownership")
    owner = table.get("comment")
    match = _OWNER_PATTERN.fullmatch(owner) if isinstance(owner, str) else None
    if match is None:
        raise NftablesPolicyError("Meercata table ownership metadata is missing or invalid")
    transaction_id = match.group(1)
    try:
        if str(uuid.UUID(transaction_id)) != transaction_id:
            raise ValueError
    except ValueError as exc:
        raise NftablesPolicyError("Meercata table owner transaction is invalid") from exc

    if len(chains) != 1:
        raise NftablesPolicyError("Meercata table must contain exactly one chain")
    chain = chains[0]
    _require_exact_keys(
        chain,
        {
            "family",
            "table",
            "name",
            "handle",
            "comment",
            "type",
            "hook",
            "prio",
            "policy",
        },
        "chain",
    )
    expected_chain = {
        "family": NFT_FAMILY,
        "table": NFT_TABLE,
        "name": NFT_CHAIN,
        "comment": OWNERSHIP_PREFIX,
        "type": "filter",
        "hook": "forward",
        "prio": NFT_HOOK_PRIORITY,
        "policy": "accept",
    }
    if any(chain.get(key) != expected for key, expected in expected_chain.items()):
        raise NftablesPolicyError("Meercata forward chain does not match the approved policy")

    if len(rules) != 2:
        raise NftablesPolicyError("Meercata forward chain must contain exactly two rules")
    normalized_rules = [_inspect_rule(rule) for rule in rules]
    by_direction = {rule["direction"]: rule for rule in normalized_rules}
    if set(by_direction) != {"in", "out"} or len(by_direction) != 2:
        raise NftablesPolicyError("Meercata table requires one inbound and one outbound rule")
    inbound = by_direction["in"]
    outbound = by_direction["out"]
    if inbound["interface"] != outbound["interface"]:
        raise NftablesPolicyError("Meercata NFQUEUE rules must use one interface")
    if inbound["queue"] != outbound["queue"]:
        raise NftablesPolicyError("Meercata NFQUEUE rules must use one queue")

    semantics = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "family": NFT_FAMILY,
        "table": NFT_TABLE,
        "chain": NFT_CHAIN,
        "hook": "forward",
        "priority": NFT_HOOK_PRIORITY,
        "policy": "accept",
        "interface": inbound["interface"],
        "queue": inbound["queue"],
        "fail_open": True,
        "directions": ["in", "out"],
    }
    encoded = json.dumps(semantics, sort_keys=True, separators=(",", ":")).encode()
    return NftablesInspection(
        transaction_id=transaction_id,
        interface=inbound["interface"],
        queue=inbound["queue"],
        fail_open=True,
        semantic_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _render_rule(meta_key: str, interface: str, queue: int, direction: str) -> str:
    return (
        f'add rule {NFT_FAMILY} {NFT_TABLE} {NFT_CHAIN} {meta_key} "{interface}" '
        f'counter queue flags bypass to {queue} comment "{OWNERSHIP_PREFIX}:{direction}"'
    )


def _inspect_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    _require_exact_keys(
        rule,
        {"family", "table", "chain", "handle", "comment", "expr"},
        "rule",
    )
    if any(
        rule.get(key) != expected
        for key, expected in {
            "family": NFT_FAMILY,
            "table": NFT_TABLE,
            "chain": NFT_CHAIN,
        }.items()
    ):
        raise NftablesPolicyError("rule is outside the Meercata forward chain")
    comment = rule.get("comment")
    expected_comments = {
        f"{OWNERSHIP_PREFIX}:in": ("in", "iifname"),
        f"{OWNERSHIP_PREFIX}:out": ("out", "oifname"),
    }
    if comment not in expected_comments:
        raise NftablesPolicyError("Meercata rule ownership metadata is invalid")
    direction, expected_meta = expected_comments[comment]
    expressions = rule.get("expr")
    if not isinstance(expressions, list) or len(expressions) != 3:
        raise NftablesPolicyError("Meercata rule expression layout is invalid")

    match, counter, queue = expressions
    if (
        not isinstance(match, Mapping)
        or set(match) != {"match"}
        or not isinstance(match.get("match"), Mapping)
    ):
        raise NftablesPolicyError("Meercata interface match is missing")
    match_value = match["match"]
    left = match_value.get("left")
    interface = match_value.get("right")
    if (
        set(match_value) != {"op", "left", "right"}
        or
        match_value.get("op") != "=="
        or not isinstance(left, Mapping)
        or set(left) != {"meta"}
        or not isinstance(left.get("meta"), Mapping)
        or set(left["meta"]) != {"key"}
        or left["meta"].get("key") != expected_meta
        or not isinstance(interface, str)
        or INTERFACE_PATTERN.fullmatch(interface) is None
    ):
        raise NftablesPolicyError("Meercata interface match is invalid")
    if (
        not isinstance(counter, Mapping)
        or set(counter) != {"counter"}
        or not isinstance(counter.get("counter"), Mapping)
        or set(counter["counter"]) != {"packets", "bytes"}
        or any(
            type(counter["counter"].get(name)) is not int
            or counter["counter"][name] < 0
            for name in ("packets", "bytes")
        )
    ):
        raise NftablesPolicyError("Meercata rule counter is missing")
    queue_value = (
        queue.get("queue")
        if isinstance(queue, Mapping) and set(queue) == {"queue"}
        else None
    )
    if not isinstance(queue_value, Mapping):
        raise NftablesPolicyError("Meercata NFQUEUE expression is missing")
    if set(queue_value) != {"num", "flags"}:
        raise NftablesPolicyError("Meercata NFQUEUE expression has unknown fields")
    number = queue_value.get("num")
    flags = queue_value.get("flags")
    if type(number) is not int or not 0 <= number <= 65535:
        raise NftablesPolicyError("Meercata NFQUEUE number is invalid")
    if flags != "bypass" and flags != ["bypass"]:
        raise NftablesPolicyError("Meercata NFQUEUE bypass flag is missing")
    return {
        "direction": direction,
        "interface": interface,
        "queue": number,
    }


def _require_exact_keys(
    value: Mapping[str, Any], allowed: set[str], object_name: str
) -> None:
    if set(value) != allowed:
        raise NftablesPolicyError(
            f"Meercata {object_name} fields do not match the approved policy"
        )
