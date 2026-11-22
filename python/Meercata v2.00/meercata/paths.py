"""Fixed production paths and isolated test paths."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from meercata.errors import StateStoreError, UnsafePathError


@dataclass(frozen=True, slots=True)
class MeercataPaths:
    config_dir: Path
    package_dir: Path
    state_dir: Path
    log_dir: Path
    run_dir: Path

    @classmethod
    def production(cls) -> MeercataPaths:
        return cls(
            config_dir=Path("/etc/meercata"),
            package_dir=Path("/usr/lib/meercata"),
            state_dir=Path("/var/lib/meercata"),
            log_dir=Path("/var/log/meercata"),
            run_dir=Path("/run/meercata"),
        )

    @classmethod
    def isolated(cls, root: Path) -> MeercataPaths:
        root = root.resolve(strict=False)
        if root == Path("/"):
            raise UnsafePathError("isolated root cannot be the filesystem root")
        return cls(
            config_dir=root / "etc" / "meercata",
            package_dir=root / "usr" / "lib" / "meercata",
            state_dir=root / "var" / "lib" / "meercata",
            log_dir=root / "var" / "log" / "meercata",
            run_dir=root / "run" / "meercata",
        )

    @property
    def transactions_dir(self) -> Path:
        return self.state_dir / "transactions"

    @property
    def last_known_good_file(self) -> Path:
        return self.state_dir / "last-known-good.json"

    @property
    def audit_file(self) -> Path:
        return self.log_dir / "controller-audit.jsonl"

    @property
    def controller_lock_file(self) -> Path:
        return self.run_dir / "controller.lock"

    @property
    def controller_config_file(self) -> Path:
        return self.config_dir / "meercata.toml"

    @property
    def suricata_log_dir(self) -> Path:
        if self == MeercataPaths.production():
            return Path("/var/log/suricata")
        return self.log_dir.parent / "suricata"

    @property
    def suricata_run_dir(self) -> Path:
        if self == MeercataPaths.production():
            return Path("/run/suricata")
        return self.run_dir.parent / "suricata"

    @property
    def suricata_config_dir(self) -> Path:
        if self == MeercataPaths.production():
            return Path("/etc/suricata")
        return self.config_dir.parent / "suricata"

    @property
    def suricata_config_file(self) -> Path:
        return self.suricata_config_dir / "suricata.yaml"

    @property
    def suricata_state_dir(self) -> Path:
        if self == MeercataPaths.production():
            return Path("/var/lib/suricata")
        return self.state_dir.parent / "suricata"

    @property
    def suricata_rules_dir(self) -> Path:
        return self.suricata_state_dir / "rules"

    @property
    def ruleops_dir(self) -> Path:
        return self.state_dir / "ruleops"

    @property
    def rule_candidates_dir(self) -> Path:
        return self.ruleops_dir / "candidates"

    @property
    def regression_packs_dir(self) -> Path:
        return self.package_dir / "regression-packs"

    @property
    def privileged_state_dir(self) -> Path:
        return self.state_dir / "privileged"

    @property
    def privileged_transactions_dir(self) -> Path:
        return self.privileged_state_dir / "transactions"

    @property
    def privileged_audit_file(self) -> Path:
        return self.log_dir / "privileged" / "audit.jsonl"

    @property
    def installed_helper_file(self) -> Path:
        return self.package_dir / "bin" / "meercata-helper"

    @property
    def monitor_state_dir(self) -> Path:
        return self.state_dir / "monitor"

    @property
    def monitor_state_file(self) -> Path:
        return self.monitor_state_dir / "state.json"

    @property
    def monitor_log_dir(self) -> Path:
        return self.log_dir / "monitor"

    @property
    def monitor_events_file(self) -> Path:
        return self.monitor_log_dir / "transitions.jsonl"

    @property
    def monitor_run_dir(self) -> Path:
        return self.run_dir / "monitor"

    @property
    def monitor_lock_file(self) -> Path:
        return self.monitor_run_dir / "monitor.lock"

    @property
    def monitor_outbox_dir(self) -> Path:
        return self.monitor_state_dir / "outbox"

    @property
    def monitor_dead_letter_dir(self) -> Path:
        return self.monitor_state_dir / "dead-letter"

    @property
    def monitor_receipts_file(self) -> Path:
        return self.monitor_log_dir / "delivery-receipts.jsonl"

    @property
    def monitor_delivery_lock_file(self) -> Path:
        return self.monitor_run_dir / "delivery.lock"

    @property
    def monitor_delivery_token_dir(self) -> Path:
        return self.config_dir / "credentials"

    @property
    def monitor_delivery_token_file(self) -> Path:
        return self.monitor_delivery_token_dir / "monitor-token"


def require_within(path: Path, root: Path) -> Path:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if resolved_path == resolved_root or resolved_root not in resolved_path.parents:
        raise UnsafePathError(f"path is outside allowlisted root: {path}")
    return resolved_path


def ensure_secure_directory(path: Path, mode: int = 0o750) -> None:
    """Create/open an absolute directory path without following symlinks."""
    if not path.is_absolute():
        raise StateStoreError("managed directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            try:
                os.mkdir(component, mode=mode, dir_fd=directory_fd)
            except FileExistsError:
                pass
            try:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise StateStoreError(
                        f"managed directory component is unsafe: {path}"
                    ) from exc
                raise
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise StateStoreError(f"managed path is not a directory: {path}")
            os.close(directory_fd)
            directory_fd = next_fd
    except StateStoreError:
        raise
    except OSError as exc:
        raise StateStoreError(f"cannot prepare managed directory {path}: {exc}") from exc
    finally:
        os.close(directory_fd)
