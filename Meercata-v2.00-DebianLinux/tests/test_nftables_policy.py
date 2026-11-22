import copy

import pytest

from meercata.errors import NftablesPolicyError
from meercata.ips_config import IpsConfig
from meercata.nftables_policy import NftablesPolicy, inspect_owned_table

TX = "a0000000-0000-0000-0000-000000000017"


def policy() -> NftablesPolicy:
    return NftablesPolicy.from_config(TX, IpsConfig("enp1s0", 42))


def observed() -> dict:
    return {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {
                "table": {
                    "family": "inet",
                    "name": "meercata",
                    "handle": 9,
                    "comment": f"meercata-managed:v1:{TX}",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "meercata",
                    "name": "forward",
                    "handle": 10,
                    "comment": "meercata-managed:v1",
                    "type": "filter",
                    "hook": "forward",
                    "prio": 10,
                    "policy": "accept",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "meercata",
                    "chain": "forward",
                    "handle": 11,
                    "comment": "meercata-managed:v1:in",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": "enp1s0",
                            }
                        },
                        {"counter": {"packets": 1, "bytes": 100}},
                        {"queue": {"num": 42, "flags": "bypass"}},
                    ],
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "meercata",
                    "chain": "forward",
                    "handle": 12,
                    "comment": "meercata-managed:v1:out",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "oifname"}},
                                "right": "enp1s0",
                            }
                        },
                        {"counter": {"packets": 2, "bytes": 200}},
                        {"queue": {"num": 42, "flags": ["bypass"]}},
                    ],
                }
            },
        ]
    }


def test_policy_renders_deterministic_atomic_native_scripts() -> None:
    value = policy()
    initial = value.render_apply(replace_owned_table=False)
    replacement = value.render_apply(replace_owned_table=True)

    assert initial.startswith('add table inet meercata { comment "meercata-managed:v1:')
    assert not initial.startswith("delete")
    assert replacement.startswith("delete table inet meercata\nadd table")
    assert initial.count("queue flags bypass to 42") == 2
    assert 'iifname "enp1s0"' in initial
    assert 'oifname "enp1s0"' in initial
    assert "flush ruleset" not in replacement
    assert value.render_remove() == "delete table inet meercata\n"


@pytest.mark.parametrize(
    "value",
    [
        NftablesPolicy("NOT-A-UUID", "eth0", 1),
        NftablesPolicy(TX.upper(), "eth0", 1),
        NftablesPolicy(TX, "eth0; flush ruleset", 1),
        NftablesPolicy(TX, "eth0", -1),
        NftablesPolicy(TX, "eth0", 1, False),
    ],
)
def test_policy_rejects_injection_invalid_queue_and_fail_closed(value: NftablesPolicy) -> None:
    with pytest.raises(NftablesPolicyError):
        value.render_apply(replace_owned_table=False)


def test_inspection_accepts_exact_owned_table_and_ignores_live_counters() -> None:
    first = inspect_owned_table(observed())
    changed = observed()
    changed["nftables"][3]["rule"]["handle"] = 999
    changed["nftables"][3]["rule"]["expr"][1]["counter"]["packets"] = 9999
    second = inspect_owned_table(changed)

    assert first.transaction_id == TX
    assert first.interface == "enp1s0"
    assert first.queue == 42
    assert first.fail_open is True
    assert first.semantic_sha256 == second.semantic_sha256


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["nftables"][1]["table"].update(comment="admin-table"),
        lambda value: value["nftables"][2]["chain"].update(prio=0),
        lambda value: value["nftables"][3]["rule"].update(comment="admin-rule"),
        lambda value: value["nftables"][3]["rule"]["expr"][2]["queue"].update(flags=[]),
        lambda value: value["nftables"][4]["rule"]["expr"][2]["queue"].update(num=7),
        lambda value: value["nftables"].append({"set": {"name": "unexpected"}}),
        lambda value: value["nftables"].append(copy.deepcopy(value["nftables"][3])),
        lambda value: value["nftables"][3]["rule"].update(foreign=True),
    ],
)
def test_inspection_fails_closed_on_foreign_or_drifted_state(mutate) -> None:
    value = observed()
    mutate(value)

    with pytest.raises(NftablesPolicyError):
        inspect_owned_table(value)
