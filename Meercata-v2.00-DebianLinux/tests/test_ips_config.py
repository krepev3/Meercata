from pathlib import Path

import pytest

from meercata.errors import IpsConfigurationError
from meercata.ips_config import IpsConfig, load_ips_config
from meercata.paths import MeercataPaths


def write_config(paths: MeercataPaths, text: str) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.controller_config_file.write_text(text, encoding="utf-8")


def valid_config() -> str:
    return """schema_version = 1
[health]
mode = "ips"
interface = "enp1s0"
queue = 42
[ips]
fail_policy = "open"
traffic_scope = "gateway-forward"
"""


def test_load_ips_config_uses_shared_health_interface_and_queue(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config())

    assert load_ips_config(paths) == IpsConfig("enp1s0", 42)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('mode = "ips"', 'mode = "ids"', "health.mode"),
        ('fail_policy = "open"', 'fail_policy = "closed"', "only fail-open"),
        ('traffic_scope = "gateway-forward"', 'traffic_scope = "host"', "gateway-forward"),
        ('interface = "enp1s0"', 'interface = "bad interface"', "interface"),
        ("queue = 42", "queue = 65536", "queue"),
    ],
)
def test_ips_config_rejects_unapproved_or_invalid_values(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config().replace(old, new))

    with pytest.raises(IpsConfigurationError, match=message):
        load_ips_config(paths)


def test_ips_config_rejects_unknown_keys_and_missing_table(tmp_path: Path) -> None:
    paths = MeercataPaths.isolated(tmp_path)
    write_config(paths, valid_config().replace('fail_policy = "open"', 'unsafe = true'))
    with pytest.raises(IpsConfigurationError, match="unknown ips"):
        load_ips_config(paths)

    write_config(paths, valid_config().split("[ips]")[0])
    with pytest.raises(IpsConfigurationError, match=r"\[ips\]"):
        load_ips_config(paths)
