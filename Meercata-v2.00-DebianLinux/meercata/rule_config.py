"""Strict, fixed-path configuration for the RuleOps pipeline."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from meercata.errors import RuleConfigurationError, UnsafePathError
from meercata.health_config import _read_config
from meercata.paths import MeercataPaths, require_within

ALLOWED_SOURCES = {"et/open"}
_RULE_KEYS = {
    "source",
    "minimum_rule_count",
    "maximum_reduction_percent",
    "update_timeout_seconds",
    "validation_timeout_seconds",
    "regression_timeout_seconds",
    "reload_timeout_seconds",
    "reload_poll_seconds",
    "active_rules_path",
    "suricata_config_path",
}


@dataclass(frozen=True, slots=True)
class RuleConfig:
    source: str
    minimum_rule_count: int
    maximum_reduction_percent: float
    update_timeout_seconds: float
    validation_timeout_seconds: float
    reload_timeout_seconds: float
    reload_poll_seconds: float
    active_rules_path: Path
    suricata_config_path: Path
    regression_timeout_seconds: float = 300.0


def load_rule_config(paths: MeercataPaths) -> RuleConfig:
    try:
        raw = _read_config(paths.controller_config_file)
    except Exception as exc:
        if isinstance(exc, RuleConfigurationError):
            raise
        raise RuleConfigurationError(str(exc)) from exc
    unknown_top = set(raw) - {
        "schema_version",
        "health",
        "rules",
        "ips",
        "monitor_delivery",
    }
    if unknown_top:
        raise RuleConfigurationError(
            f"unknown top-level configuration keys: {', '.join(sorted(unknown_top))}"
        )
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        raise RuleConfigurationError("configuration schema_version must be integer 1")
    values = raw.get("rules")
    if not isinstance(values, dict):
        raise RuleConfigurationError("configuration requires a [rules] table")
    unknown = set(values) - _RULE_KEYS
    if unknown:
        raise RuleConfigurationError(
            f"unknown rules configuration keys: {', '.join(sorted(unknown))}"
        )

    source = values.get("source", "et/open")
    if not isinstance(source, str) or source not in ALLOWED_SOURCES:
        raise RuleConfigurationError("rules.source must be the allowlisted value 'et/open'")
    minimum = _integer(values.get("minimum_rule_count", 1), "minimum_rule_count", 1, 1_000_000)
    reduction = _number(values.get("maximum_reduction_percent", 5.0), "maximum_reduction_percent", 0, 100)
    update_timeout = _number(values.get("update_timeout_seconds", 600.0), "update_timeout_seconds", 1, 3600)
    validation_timeout = _number(values.get("validation_timeout_seconds", 120.0), "validation_timeout_seconds", 1, 3600)
    regression_timeout = _number(values.get("regression_timeout_seconds", 300.0), "regression_timeout_seconds", 1, 3600)
    reload_timeout = _number(values.get("reload_timeout_seconds", 120.0), "reload_timeout_seconds", 1, 1800)
    reload_poll = _number(values.get("reload_poll_seconds", 1.0), "reload_poll_seconds", 0.1, 30)
    if reload_poll >= reload_timeout:
        raise RuleConfigurationError("rules.reload_poll_seconds must be below reload_timeout_seconds")

    active = _managed_path(
        values.get("active_rules_path", str(paths.suricata_rules_dir / "suricata.rules")),
        "active_rules_path",
        paths.suricata_rules_dir,
    )
    suricata_config = _managed_path(
        values.get("suricata_config_path", str(paths.suricata_config_file)),
        "suricata_config_path",
        paths.suricata_config_dir,
    )
    return RuleConfig(
        source,
        minimum,
        reduction,
        update_timeout,
        validation_timeout,
        reload_timeout,
        reload_poll,
        active,
        suricata_config,
        regression_timeout,
    )


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuleConfigurationError(
            f"rules.{name} must be an integer from {minimum} to {maximum}"
        )
    return value


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if type(value) not in {int, float}:
        raise RuleConfigurationError(f"rules.{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise RuleConfigurationError(
            f"rules.{name} must be between {minimum:g} and {maximum:g}"
        )
    return number


def _managed_path(value: Any, name: str, root: Path) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise RuleConfigurationError(f"rules.{name} must be an absolute path")
    try:
        return require_within(Path(value), root)
    except (UnsafePathError, OSError, ValueError) as exc:
        raise RuleConfigurationError(f"rules.{name} is outside {root}") from exc
