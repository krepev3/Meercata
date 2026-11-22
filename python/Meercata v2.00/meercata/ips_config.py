"""Strict configuration for the initial fail-open NFQUEUE IPS scope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from meercata.errors import IpsConfigurationError
from meercata.health_config import INTERFACE_PATTERN, _read_config
from meercata.paths import MeercataPaths

_TOP_LEVEL_KEYS = {"schema_version", "health", "rules", "ips", "monitor_delivery"}
_IPS_KEYS = {"fail_policy", "traffic_scope"}


@dataclass(frozen=True, slots=True)
class IpsConfig:
    interface: str
    queue: int
    fail_policy: str = "open"
    traffic_scope: str = "gateway-forward"

    def validate(self) -> None:
        if not isinstance(self.interface, str) or INTERFACE_PATTERN.fullmatch(self.interface) is None:
            raise IpsConfigurationError("IPS interface is invalid")
        if type(self.queue) is not int or not 0 <= self.queue <= 65535:
            raise IpsConfigurationError("IPS queue must be an integer from 0 to 65535")
        if self.fail_policy != "open":
            raise IpsConfigurationError(
                "only fail-open IPS is approved; fail-closed requires a separate HA/bypass approval"
            )
        if self.traffic_scope != "gateway-forward":
            raise IpsConfigurationError(
                "only the gateway-forward IPS traffic scope is approved"
            )


def load_ips_config(paths: MeercataPaths) -> IpsConfig:
    try:
        raw = _read_config(paths.controller_config_file)
    except IpsConfigurationError:
        raise
    except Exception as exc:
        raise IpsConfigurationError(str(exc)) from exc

    unknown_top = set(raw) - _TOP_LEVEL_KEYS
    if unknown_top:
        raise IpsConfigurationError(
            f"unknown top-level configuration keys: {', '.join(sorted(unknown_top))}"
        )
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        raise IpsConfigurationError("configuration schema_version must be integer 1")

    health = raw.get("health")
    if not isinstance(health, dict):
        raise IpsConfigurationError("configuration requires a [health] table")
    if health.get("mode") != "ips":
        raise IpsConfigurationError("health.mode must be 'ips' before IPS policy can be prepared")
    interface = health.get("interface")
    queue = health.get("queue", 0)

    values = raw.get("ips")
    if not isinstance(values, dict):
        raise IpsConfigurationError("configuration requires an [ips] table")
    unknown = set(values) - _IPS_KEYS
    if unknown:
        raise IpsConfigurationError(
            f"unknown ips configuration keys: {', '.join(sorted(unknown))}"
        )
    fail_policy = _required_string(values, "fail_policy")
    traffic_scope = _required_string(values, "traffic_scope")
    config = IpsConfig(interface, queue, fail_policy, traffic_scope)
    config.validate()
    return config


def _required_string(values: dict[str, Any], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value:
        raise IpsConfigurationError(f"ips.{name} must be a non-empty string")
    return value
