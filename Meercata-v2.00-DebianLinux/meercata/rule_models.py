"""Immutable RuleOps summaries, differences, and candidate manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class RuleSignature:
    gid: int
    sid: int
    rev: int
    action: str
    enabled: bool
    fingerprint: str

    @property
    def key(self) -> tuple[int, int]:
        return (self.gid, self.sid)

    def identity(self) -> str:
        return f"{self.gid}:{self.sid}"


@dataclass(frozen=True, slots=True)
class RuleSetSummary:
    sha256: str
    size_bytes: int
    active_rules: int
    disabled_rules: int
    action_counts: Mapping[str, int]
    signatures: tuple[RuleSignature, ...]

    def to_dict(self, *, include_signatures: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "active_rules": self.active_rules,
            "disabled_rules": self.disabled_rules,
            "action_counts": dict(sorted(self.action_counts.items())),
        }
        if include_signatures:
            value["signatures"] = [
                {
                    "gid": item.gid,
                    "sid": item.sid,
                    "rev": item.rev,
                    "action": item.action,
                    "enabled": item.enabled,
                    "fingerprint": item.fingerprint,
                }
                for item in self.signatures
            ]
        return value


@dataclass(frozen=True, slots=True)
class RuleDiff:
    baseline_count: int
    candidate_count: int
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    reduction_percent: float
    policy_allowed: bool
    policy_reasons: tuple[str, ...]

    def to_dict(self, *, max_identities: int = 1000) -> dict[str, Any]:
        if type(max_identities) is not int or max_identities < 0 or max_identities > 10_000:
            raise ValueError("max_identities must be an integer from 0 to 10000")
        added = self.added[:max_identities]
        removed = self.removed[:max_identities]
        changed = self.changed[:max_identities]
        return {
            "baseline_count": self.baseline_count,
            "candidate_count": self.candidate_count,
            "added": list(added),
            "removed": list(removed),
            "changed": list(changed),
            "added_total": len(self.added),
            "removed_total": len(self.removed),
            "changed_total": len(self.changed),
            "identity_lists_truncated": any(
                len(values) > max_identities
                for values in (self.added, self.removed, self.changed)
            ),
            "reduction_percent": self.reduction_percent,
            "policy_allowed": self.policy_allowed,
            "policy_reasons": list(self.policy_reasons),
        }
