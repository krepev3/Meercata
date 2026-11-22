from __future__ import annotations

import json
from pathlib import Path

import pytest

from meercata.container_qualifier import DEBIAN_13_IMAGE_DIGEST
from meercata.errors import QualificationError
from meercata.nftables_namespace_qualifier import (
    CONFIRMATION,
    _require_disposable_network_namespace,
    _semantic_table_hash,
)

SOURCE_ROOT = Path(__file__).parents[1]


def fixture_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    marker = tmp_path / ".dockerenv"
    marker.write_text("")
    release = tmp_path / "os-release"
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    interfaces = tmp_path / "net"
    (interfaces / "lo").mkdir(parents=True)
    routes = tmp_path / "route"
    routes.write_text("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n")
    return marker, release, tmp_path / "systemd-absent", interfaces, routes


def test_namespace_guard_requires_root_debian_container_and_no_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker, release, systemd, interfaces, routes = fixture_paths(tmp_path)
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.os.geteuid", lambda: 0)
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.os.getegid", lambda: 0)
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.NFT", Path("/bin/true"))
    monkeypatch.setattr(
        "meercata.nftables_namespace_qualifier._namespace_identity",
        lambda _path: "net:[123]",
    )

    value = _require_disposable_network_namespace(
        CONFIRMATION,
        DEBIAN_13_IMAGE_DIGEST,
        marker=marker,
        release_path=release,
        systemd_runtime=systemd,
        interfaces_path=interfaces,
        ipv4_route_path=routes,
    )

    assert value["interfaces"] == ["lo"]
    assert value["ipv4_routes"] == 0


@pytest.mark.parametrize("change,message", [("interface", "network none"), ("route", "network none")])
def test_namespace_guard_rejects_connected_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    message: str,
) -> None:
    marker, release, systemd, interfaces, routes = fixture_paths(tmp_path)
    if change == "interface":
        (interfaces / "eth0").mkdir()
    else:
        routes.write_text("header\neth0 00000000 0100007F 0003 0 0 0 00000000 0 0 0\n")
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.os.geteuid", lambda: 0)
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.os.getegid", lambda: 0)
    monkeypatch.setattr("meercata.nftables_namespace_qualifier.NFT", Path("/bin/true"))

    with pytest.raises(QualificationError, match=message):
        _require_disposable_network_namespace(
            CONFIRMATION,
            DEBIAN_13_IMAGE_DIGEST,
            marker=marker,
            release_path=release,
            systemd_runtime=systemd,
            interfaces_path=interfaces,
            ipv4_route_path=routes,
        )


def test_unrelated_table_hash_ignores_handle_and_counter_progress() -> None:
    first = {
        "nftables": [
            {"metainfo": {"version": "1"}},
            {"table": {"family": "inet", "name": "operator_guard", "handle": 1}},
            {
                "rule": {
                    "family": "inet",
                    "table": "operator_guard",
                    "chain": "input",
                    "handle": 2,
                    "expr": [{"counter": {"packets": 1, "bytes": 2}}, {"accept": None}],
                }
            },
        ]
    }
    second = json.loads(json.dumps(first))
    second["nftables"][1]["table"]["handle"] = 99
    second["nftables"][2]["rule"]["handle"] = 100
    second["nftables"][2]["rule"]["expr"][0]["counter"]["packets"] = 500

    assert _semantic_table_hash(first) == _semantic_table_hash(second)


def test_recorded_nftables_namespace_evidence_conforms_to_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (SOURCE_ROOT / "schemas/nftables-namespace-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (SOURCE_ROOT / "qualification-evidence/nftables-namespace-dev17.json").read_text()
    )

    jsonschema.validate(evidence, schema)
    assert evidence["status"] == "nftables-namespace-qualified"
