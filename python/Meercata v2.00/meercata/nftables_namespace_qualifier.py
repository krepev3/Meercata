"""Live nftables policy qualification inside a disposable Debian 13 netns."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence, TextIO

from meercata.command_runner import CommandDefinition, CommandRunner
from meercata.container_qualifier import DEBIAN_13_IMAGE_DIGEST, _read_os_release
from meercata.errors import NftablesPolicyError, QualificationError
from meercata.nftables_policy import NftablesPolicy, inspect_owned_table

CONFIRMATION = "I_UNDERSTAND_THIS_MUTATES_ONLY_A_DISPOSABLE_CONTAINER_NETNS"
NFT = Path("/usr/sbin/nft")
FIRST_TRANSACTION = "a0000000-0000-0000-0000-000000000017"
SECOND_TRANSACTION = "b0000000-0000-0000-0000-000000000017"


class NftablesNamespaceQualifier:
    def __init__(self, *, confirmation: str, image_digest: str) -> None:
        self.confirmation = confirmation
        self.image_digest = image_digest

    def qualify(self) -> dict[str, Any]:
        platform = _require_disposable_network_namespace(
            self.confirmation, self.image_digest
        )
        first = NftablesPolicy(FIRST_TRANSACTION, "eth0", 42)
        second = NftablesPolicy(SECOND_TRANSACTION, "eth0", 42)
        checks: list[dict[str, Any]] = [_passed("platform.namespace", platform)]

        with tempfile.TemporaryDirectory(prefix="meercata-nft-") as temporary:
            root = Path(temporary)
            try:
                _apply_text(root, "foreign-add", _foreign_table_script())
                foreign_before = _semantic_table_hash(_list_table("operator_guard"))

                _apply_text(
                    root,
                    "unowned-add",
                    "add table inet meercata\n",
                )
                rejected = False
                try:
                    inspect_owned_table(_list_table("meercata"))
                except NftablesPolicyError:
                    rejected = True
                if not rejected:
                    raise QualificationError("unowned Meercata table was accepted")
                _apply_text(root, "unowned-remove", first.render_remove())
                checks.append(
                    _passed(
                        "ownership.foreign-rejected",
                        {"unowned_table_rejected": True},
                    )
                )

                first_script = first.render_apply(replace_owned_table=False)
                _check_text(root, "initial-check", first_script)
                checks.append(
                    _passed(
                        "policy.syntax",
                        {
                            "nft_version": _nft_version(),
                            "script_sha256": _sha256_text(first_script),
                        },
                    )
                )
                _apply_text(root, "initial-apply", first_script)
                first_observed = inspect_owned_table(_list_table("meercata"))
                _require_policy(first_observed, first)
                _require_foreign_unchanged(foreign_before)
                checks.append(
                    _passed(
                        "policy.initial-apply",
                        {
                            "transaction_id": first_observed.transaction_id,
                            "semantic_sha256": first_observed.semantic_sha256,
                            "fail_open": first_observed.fail_open,
                        },
                    )
                )

                replacement = second.render_apply(replace_owned_table=True)
                _check_text(root, "replacement-check", replacement)
                _apply_text(root, "replacement-apply", replacement)
                second_observed = inspect_owned_table(_list_table("meercata"))
                _require_policy(second_observed, second)
                _require_foreign_unchanged(foreign_before)
                checks.append(
                    _passed(
                        "policy.atomic-replace",
                        {
                            "previous_transaction_id": first.transaction_id,
                            "transaction_id": second_observed.transaction_id,
                            "semantic_sha256": second_observed.semantic_sha256,
                        },
                    )
                )

                _apply_text(
                    root,
                    "drift-add",
                    'add rule inet meercata forward counter accept comment "foreign-drift"\n',
                )
                rejected = False
                try:
                    inspect_owned_table(_list_table("meercata"))
                except NftablesPolicyError:
                    rejected = True
                if not rejected:
                    raise QualificationError("externally drifted Meercata table was accepted")
                checks.append(
                    _passed(
                        "ownership.drift-rejected",
                        {"unexpected_rule_rejected": True},
                    )
                )

                _apply_text(root, "emergency-remove", second.render_remove())
                if _table_exists("meercata"):
                    raise QualificationError("Meercata table remains after emergency removal")
                _require_foreign_unchanged(foreign_before)
                checks.append(
                    _passed(
                        "policy.remove-isolated",
                        {
                            "meercata_table_removed": True,
                            "unrelated_table_preserved": True,
                            "unrelated_semantic_sha256": foreign_before,
                        },
                    )
                )
            finally:
                _best_effort_delete(root, "meercata")
                _best_effort_delete(root, "operator_guard")

        if len(checks) != 7:
            raise QualificationError("nftables qualification check count is invalid")
        return {
            "schema_version": 1,
            "status": "nftables-namespace-qualified",
            "platform": platform,
            "policy": {
                "family": "inet",
                "table": "meercata",
                "chain": "forward",
                "priority": 10,
                "interface": "eth0",
                "queue": 42,
                "fail_policy": "open",
                "traffic_scope": "gateway-forward",
            },
            "checks": checks,
            "limitations": [
                "the run used a disposable container network namespace and did not alter the host network namespace",
                "Suricata and a userspace NFQUEUE listener were not started, so packet verdict correctness was not exercised",
                "listener-loss connectivity, queue overload, throughput, and latency remain unqualified",
                "the privileged transaction helper, service lifecycle, reboot recovery, and public IPS CLI remain gated",
            ],
        }


def _require_disposable_network_namespace(
    confirmation: str,
    image_digest: str,
    *,
    expected_confirmation: str = CONFIRMATION,
    marker: Path = Path("/.dockerenv"),
    release_path: Path = Path("/etc/os-release"),
    systemd_runtime: Path = Path("/run/systemd/system"),
    interfaces_path: Path = Path("/sys/class/net"),
    ipv4_route_path: Path = Path("/proc/net/route"),
) -> dict[str, Any]:
    if confirmation != expected_confirmation:
        raise QualificationError("disposable-network-namespace confirmation is missing")
    if image_digest != DEBIAN_13_IMAGE_DIGEST:
        raise QualificationError("Debian 13 image digest is not the approved pinned digest")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise QualificationError("nftables namespace qualification requires effective root")
    try:
        if not stat.S_ISREG(marker.lstat().st_mode):
            raise QualificationError("Docker container marker is invalid")
    except FileNotFoundError as exc:
        raise QualificationError("refusing to qualify outside a Docker container") from exc
    release = _read_os_release(release_path)
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise QualificationError("qualification requires Debian 13")
    if systemd_runtime.exists():
        raise QualificationError("refusing a container with a running systemd manager")
    try:
        interfaces = sorted(path.name for path in interfaces_path.iterdir())
        route_lines = [line for line in ipv4_route_path.read_text().splitlines()[1:] if line.strip()]
    except OSError as exc:
        raise QualificationError("cannot verify isolated network namespace") from exc
    if interfaces != ["lo"] or route_lines:
        raise QualificationError("qualification container must use --network none")
    if not NFT.is_file() or not os.access(NFT, os.X_OK):
        raise QualificationError("approved nft executable is unavailable")
    return {
        "os_id": "debian",
        "version_id": "13",
        "architecture": os.uname().machine,
        "image_digest": image_digest,
        "effective_uid": 0,
        "effective_gid": 0,
        "interfaces": interfaces,
        "ipv4_routes": 0,
        "network_namespace": _namespace_identity(Path("/proc/self/ns/net")),
    }


def _namespace_identity(path: Path) -> str:
    try:
        value = os.readlink(path)
    except OSError as exc:
        raise QualificationError("cannot identify the network namespace") from exc
    if not value.startswith("net:[") or not value.endswith("]"):
        raise QualificationError("network namespace identity is invalid")
    return value


def _check_text(root: Path, check_id: str, text: str) -> None:
    path = _write_script(root, check_id, text)
    _run(check_id, (str(NFT), "-c", "-f", str(path)))


def _apply_text(root: Path, check_id: str, text: str) -> None:
    path = _write_script(root, check_id, text)
    _run(check_id, (str(NFT), "-f", str(path)))


def _write_script(root: Path, name: str, text: str) -> Path:
    if not name.replace("-", "").isalnum() or len(text.encode()) > 64 * 1024:
        raise QualificationError("nftables qualification script is invalid")
    path = root / f"{name}.nft"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def _run(check_id: str, argv: tuple[str, ...]):
    result = CommandRunner(
        {check_id: CommandDefinition.fixed(argv, timeout_seconds=15)}
    ).run(check_id)
    if not result.succeeded or result.stdout_truncated or result.stderr_truncated:
        raise QualificationError(f"{check_id} failed")
    return result


def _list_table(name: str) -> Any:
    if name not in {"meercata", "operator_guard"}:
        raise QualificationError("nftables table name is not allowlisted")
    result = _run(
        f"list-{name}",
        (str(NFT), "-j", "list", "table", "inet", name),
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise QualificationError("nftables returned invalid JSON") from exc


def _table_exists(name: str) -> bool:
    result = CommandRunner(
        {
            "table-exists": CommandDefinition.fixed(
                (str(NFT), "list", "table", "inet", name), timeout_seconds=15
            )
        }
    ).run("table-exists")
    return result.return_code == 0


def _best_effort_delete(root: Path, name: str) -> None:
    if name not in {"meercata", "operator_guard"}:
        return
    if _table_exists(name):
        try:
            _apply_text(root, f"cleanup-{name}", f"delete table inet {name}\n")
        except Exception:
            pass


def _foreign_table_script() -> str:
    return (
        'add table inet operator_guard { comment "operator-owned"; }\n'
        'add chain inet operator_guard input { type filter hook input priority 0; policy accept; }\n'
        'add rule inet operator_guard input counter accept comment "operator-rule"\n'
    )


def _semantic_table_hash(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("nftables"), list):
        raise QualificationError("unrelated nftables table JSON is invalid")
    normalized: list[Any] = []
    for item in value["nftables"]:
        if not isinstance(item, dict) or "metainfo" in item:
            continue
        copied = json.loads(json.dumps(item))
        for details in copied.values():
            if isinstance(details, dict):
                details.pop("handle", None)
                for expression in details.get("expr", []):
                    if isinstance(expression, dict) and isinstance(expression.get("counter"), dict):
                        expression["counter"] = {"present": True}
        normalized.append(copied)
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require_foreign_unchanged(expected_hash: str) -> None:
    if _semantic_table_hash(_list_table("operator_guard")) != expected_hash:
        raise QualificationError("unrelated nftables state changed")


def _require_policy(observed: Any, expected: NftablesPolicy) -> None:
    if (
        observed.transaction_id != expected.transaction_id
        or observed.interface != expected.interface
        or observed.queue != expected.queue
        or observed.fail_open is not True
    ):
        raise QualificationError("observed Meercata nftables policy does not match intent")


def _nft_version() -> str:
    result = _run("nft-version", (str(NFT), "--version"))
    value = result.stdout.strip()
    if not value.startswith("nftables v") or len(value) > 128:
        raise QualificationError("nftables version output is invalid")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _passed(check_id: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"check_id": check_id, "status": "passed", "details": details}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m meercata.nftables_namespace_qualifier",
        description="Qualify owned fail-open nftables policy in a disposable container netns",
    )
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    arguments = build_parser().parse_args(argv)
    try:
        report = NftablesNamespaceQualifier(
            confirmation=arguments.confirm,
            image_digest=arguments.image_digest,
        ).qualify()
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if arguments.output is not None:
            arguments.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="", file=stdout)
        return 0
    except (QualificationError, NftablesPolicyError) as exc:
        print(f"meercata-nftables-namespace-qualifier: {exc}", file=stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
