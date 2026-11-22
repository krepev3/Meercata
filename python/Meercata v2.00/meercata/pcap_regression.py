"""Immutable PCAP regression packs and bounded EVE alert evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.errors import RuleOperationError
from meercata.models import CommandResult, utc_now
from meercata.paths import MeercataPaths, ensure_secure_directory, require_within
from meercata.rule_config import RuleConfig
from meercata.rule_store import RuleCandidateStore

SURICATA = Path("/usr/bin/suricata")
MAX_PACK_MANIFEST_BYTES = 1024 * 1024
MAX_PCAP_BYTES = 512 * 1024 * 1024
MAX_EVE_BYTES = 128 * 1024 * 1024
MAX_EVE_LINE_BYTES = 2 * 1024 * 1024
MAX_CASES = 128
MAX_EXPECTATIONS = 4096
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
PCAP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.pcap(?:ng)?\Z")
RunnerFactory = Callable[[dict[str, CommandDefinition]], CommandRunner]


@dataclass(frozen=True, slots=True)
class AlertExpectation:
    gid: int
    sid: int
    minimum: int = 1
    maximum: int | None = None

    @property
    def key(self) -> tuple[int, int]:
        return (self.gid, self.sid)


@dataclass(frozen=True, slots=True)
class RegressionCase:
    case_id: str
    pcap_file: str
    pcap_sha256: str
    expected: tuple[AlertExpectation, ...]
    forbidden: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class RegressionPack:
    pack_id: str
    description: str
    manifest_sha256: str
    cases: tuple[RegressionCase, ...]


class RegressionPackStore:
    def __init__(self, paths: MeercataPaths) -> None:
        self.paths = paths

    def load(self, pack_id: str) -> RegressionPack:
        _validate_identifier(pack_id, "pack ID")
        _require_directory(self.paths.regression_packs_dir, "regression pack root")
        requested_dir = self.paths.regression_packs_dir / pack_id
        _require_directory(requested_dir, "regression pack directory")
        try:
            pack_dir = require_within(
                requested_dir,
                self.paths.regression_packs_dir,
            )
        except Exception as exc:
            raise RuleOperationError("regression pack path is unsafe") from exc
        manifest_path = pack_dir / "manifest.json"
        _require_production_trust(self.paths, pack_dir, is_directory=True)
        _require_production_trust(self.paths, manifest_path, is_directory=False)
        raw = _read_regular(manifest_path, MAX_PACK_MANIFEST_BYTES, "pack manifest")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuleOperationError("regression pack manifest is invalid JSON") from exc
        return _parse_pack(value, pack_id, hashlib.sha256(raw).hexdigest())

    def pcap_path(self, pack_id: str, case: RegressionCase) -> Path:
        _validate_identifier(pack_id, "pack ID")
        _require_directory(self.paths.regression_packs_dir, "regression pack root")
        requested_dir = self.paths.regression_packs_dir / pack_id
        _require_directory(requested_dir, "regression pack directory")
        try:
            pack_dir = require_within(
                requested_dir,
                self.paths.regression_packs_dir,
            )
            requested_pcap = pack_dir / case.pcap_file
            _require_regular_path(requested_pcap, "regression PCAP")
            path = require_within(requested_pcap, pack_dir)
        except Exception as exc:
            raise RuleOperationError("regression PCAP path is unsafe") from exc
        _require_production_trust(self.paths, path, is_directory=False)
        digest = _hash_regular(path, MAX_PCAP_BYTES, "PCAP")
        if digest != case.pcap_sha256:
            raise RuleOperationError(
                f"regression PCAP hash mismatch for case {case.case_id}"
            )
        return path


class PcapRegressionRunner:
    def __init__(
        self,
        paths: MeercataPaths,
        config: RuleConfig,
        candidates: RuleCandidateStore,
        *,
        runner_factory: RunnerFactory = CommandRunner,
    ) -> None:
        self.paths = paths
        self.config = config
        self.candidates = candidates
        self.packs = RegressionPackStore(paths)
        self._runner_factory = runner_factory

    def run(self, candidate_id: str, pack_id: str) -> dict[str, Any]:
        candidate_dir = self.candidates.candidate_dir(candidate_id)
        candidate_path = require_within(self.candidates.rules_file(candidate_id), candidate_dir)
        return self.run_rule_file(
            candidate_path,
            candidate_dir / "regression",
            pack_id,
        )

    def run_rule_file(
        self,
        rule_path: Path,
        output_root: Path,
        pack_id: str,
    ) -> dict[str, Any]:
        pack = self.packs.load(pack_id)
        candidate_sha256 = hashlib.sha256(
            _read_regular(rule_path, MAX_PCAP_BYTES, "candidate rules")
        ).hexdigest()
        run_id = str(uuid.uuid4())
        ensure_secure_directory(output_root)
        run_dir = require_within(output_root / run_id, output_root)
        ensure_secure_directory(run_dir)
        results: list[dict[str, Any]] = []
        passed = True
        for case in pack.cases:
            pcap_path = self.packs.pcap_path(pack_id, case)
            output_dir = require_within(run_dir / case.case_id, run_dir)
            ensure_secure_directory(output_dir)
            command_id = f"rules.regression.{case.case_id}"
            command = CommandDefinition.fixed(
                (
                    str(SURICATA),
                    "-c",
                    str(self.config.suricata_config_path),
                    "-S",
                    str(rule_path),
                    "-r",
                    str(pcap_path),
                    "-l",
                    str(output_dir),
                    "--runmode",
                    "single",
                    "--init-errors-fatal",
                    "--set",
                    "unix-command.enabled=no",
                ),
                timeout_seconds=self.config.regression_timeout_seconds,
                working_directory=output_dir,
            )
            result = self._runner_factory({command_id: command}).run(command_id)
            evaluation = _evaluate_case(case, output_dir / "eve.json", result)
            results.append(evaluation)
            passed = passed and evaluation["status"] == "passed"
        return {
            "status": "passed" if passed else "failed",
            "pack_id": pack.pack_id,
            "pack_manifest_sha256": pack.manifest_sha256,
            "candidate_sha256": candidate_sha256,
            "description": pack.description,
            "run_id": run_id,
            "completed_utc": utc_now(),
            "case_count": len(results),
            "passed_cases": sum(item["status"] == "passed" for item in results),
            "failed_cases": sum(item["status"] == "failed" for item in results),
            "cases": results,
        }


def _parse_pack(value: Any, requested_id: str, digest: str) -> RegressionPack:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "pack_id",
        "description",
        "cases",
    }:
        raise RuleOperationError("regression pack manifest has an invalid schema")
    if value.get("schema_version") != 1 or value.get("pack_id") != requested_id:
        raise RuleOperationError("regression pack schema or ID does not match")
    description = value.get("description")
    if not isinstance(description, str) or not 1 <= len(description) <= 512:
        raise RuleOperationError("regression pack description is invalid")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= MAX_CASES:
        raise RuleOperationError(f"regression pack must contain 1 to {MAX_CASES} cases")
    cases: list[RegressionCase] = []
    seen: set[str] = set()
    total_expectations = 0
    for raw_case in raw_cases:
        case = _parse_case(raw_case)
        if case.case_id in seen:
            raise RuleOperationError(f"duplicate regression case ID: {case.case_id}")
        seen.add(case.case_id)
        total_expectations += len(case.expected) + len(case.forbidden)
        cases.append(case)
    if total_expectations > MAX_EXPECTATIONS:
        raise RuleOperationError("regression pack contains too many alert expectations")
    return RegressionPack(requested_id, description, digest, tuple(cases))


def _parse_case(value: Any) -> RegressionCase:
    if not isinstance(value, dict) or set(value) != {
        "case_id",
        "pcap_file",
        "pcap_sha256",
        "expected_alerts",
        "forbidden_alerts",
    }:
        raise RuleOperationError("regression case has an invalid schema")
    case_id = value.get("case_id")
    _validate_identifier(case_id, "case ID")
    pcap_file = value.get("pcap_file")
    if not isinstance(pcap_file, str) or PCAP_NAME.fullmatch(pcap_file) is None:
        raise RuleOperationError("regression PCAP filename is invalid")
    pcap_sha256 = value.get("pcap_sha256")
    if not isinstance(pcap_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", pcap_sha256) is None:
        raise RuleOperationError("regression PCAP SHA-256 is invalid")
    expected_raw = value.get("expected_alerts")
    forbidden_raw = value.get("forbidden_alerts")
    if not isinstance(expected_raw, list) or not isinstance(forbidden_raw, list):
        raise RuleOperationError("regression alert expectations must be arrays")
    if not expected_raw and not forbidden_raw:
        raise RuleOperationError("regression case requires an expected or forbidden alert")
    expected = tuple(_parse_expectation(item) for item in expected_raw)
    forbidden = tuple(_parse_identity(item, allow_counts=False) for item in forbidden_raw)
    expected_keys = [item.key for item in expected]
    if len(set(expected_keys)) != len(expected_keys) or len(set(forbidden)) != len(forbidden):
        raise RuleOperationError("regression case contains duplicate alert identities")
    if set(expected_keys) & set(forbidden):
        raise RuleOperationError("an alert cannot be both expected and forbidden")
    return RegressionCase(case_id, pcap_file, pcap_sha256, expected, forbidden)


def _parse_expectation(value: Any) -> AlertExpectation:
    if not isinstance(value, dict) or set(value) - {"gid", "sid", "minimum", "maximum"}:
        raise RuleOperationError("expected alert has an invalid schema")
    gid, sid = _parse_identity(value, allow_counts=True)
    minimum = value.get("minimum", 1)
    maximum = value.get("maximum")
    if type(minimum) is not int or minimum < 1 or minimum > 1_000_000:
        raise RuleOperationError("expected alert minimum is invalid")
    if maximum is not None and (
        type(maximum) is not int or maximum < minimum or maximum > 1_000_000
    ):
        raise RuleOperationError("expected alert maximum is invalid")
    return AlertExpectation(gid, sid, minimum, maximum)


def _parse_identity(value: Any, *, allow_counts: bool) -> tuple[int, int]:
    if not isinstance(value, Mapping):
        raise RuleOperationError("alert identity must be an object")
    allowed = {"gid", "sid", "minimum", "maximum"} if allow_counts else {"gid", "sid"}
    if set(value) - allowed:
        raise RuleOperationError("alert identity contains unknown keys")
    gid = value.get("gid")
    sid = value.get("sid")
    if type(gid) is not int or type(sid) is not int or gid < 1 or sid < 1:
        raise RuleOperationError("alert gid and sid must be positive integers")
    return gid, sid


def _evaluate_case(
    case: RegressionCase,
    eve_path: Path,
    result: CommandResult,
) -> dict[str, Any]:
    failures: list[str] = []
    counts: Counter[tuple[int, int]] = Counter()
    if result.return_code != 0 or result.timed_out:
        failures.append("Suricata offline replay failed or timed out")
    else:
        try:
            counts = _read_alert_counts(eve_path)
        except RuleOperationError as exc:
            failures.append(str(exc))
    for expectation in case.expected:
        observed = counts[expectation.key]
        if observed < expectation.minimum:
            failures.append(
                f"{expectation.gid}:{expectation.sid} observed {observed}; minimum {expectation.minimum}"
            )
        if expectation.maximum is not None and observed > expectation.maximum:
            failures.append(
                f"{expectation.gid}:{expectation.sid} observed {observed}; maximum {expectation.maximum}"
            )
    for identity in case.forbidden:
        if counts[identity]:
            failures.append(f"forbidden alert {identity[0]}:{identity[1]} observed {counts[identity]}")
    relevant = {item.key for item in case.expected} | set(case.forbidden)
    observed = [
        {"gid": gid, "sid": sid, "count": count}
        for (gid, sid), count in sorted(counts.items())
        if (gid, sid) in relevant
    ]
    return {
        "case_id": case.case_id,
        "status": "passed" if not failures else "failed",
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "duration_seconds": result.duration_seconds,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "observed_relevant_alerts": observed,
        "observed_identities_total": len(counts),
        "failures": failures[:256],
        "failures_truncated": len(failures) > 256,
    }


def _read_alert_counts(path: Path) -> Counter[tuple[int, int]]:
    raw = _read_regular(path, MAX_EVE_BYTES, "EVE output")
    counts: Counter[tuple[int, int]] = Counter()
    for line_number, line in enumerate(raw.splitlines(), 1):
        if len(line) > MAX_EVE_LINE_BYTES:
            raise RuleOperationError(f"EVE line {line_number} exceeds 2 MiB")
        try:
            event = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuleOperationError(f"EVE line {line_number} is invalid JSON") from exc
        if not isinstance(event, dict) or event.get("event_type") != "alert":
            continue
        alert = event.get("alert")
        if not isinstance(alert, dict):
            raise RuleOperationError(f"EVE alert at line {line_number} has an invalid shape")
        gid = alert.get("gid", 1)
        sid = alert.get("signature_id")
        if type(gid) is not int or type(sid) is not int or gid < 1 or sid < 1:
            raise RuleOperationError(f"EVE alert at line {line_number} has an invalid identity")
        counts[(gid, sid)] += 1
    return counts


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuleOperationError(f"{label} is not a regular file")
            if metadata.st_size > limit:
                raise RuleOperationError(f"{label} exceeds its size limit")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
    except RuleOperationError:
        raise
    except OSError as exc:
        raise RuleOperationError(f"cannot read {label}: {exc}") from exc
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise RuleOperationError(f"{label} exceeds its size limit")
    return raw


def _hash_regular(path: Path, limit: int, label: str) -> str:
    return hashlib.sha256(_read_regular(path, limit, label)).hexdigest()


def _validate_identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise RuleOperationError(f"regression {label} is invalid")


def _require_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuleOperationError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuleOperationError(f"{label} is not a real directory")


def _require_regular_path(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuleOperationError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RuleOperationError(f"{label} is not a real regular file")


def _require_production_trust(
    paths: MeercataPaths,
    path: Path,
    *,
    is_directory: bool,
) -> None:
    if paths != MeercataPaths.production():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuleOperationError(f"cannot inspect production regression path: {exc}") from exc
    expected = stat.S_ISDIR(metadata.st_mode) if is_directory else stat.S_ISREG(metadata.st_mode)
    if not expected or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuleOperationError(
            "production regression packs must be root-owned and not group/world writable"
        )
