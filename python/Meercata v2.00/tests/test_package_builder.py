from __future__ import annotations

from collections.abc import Iterator
import io
import json
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from meercata.errors import PackagingError
from meercata.package_builder import MANIFEST_PATH, ProductionPackageBuilder, main


SOURCE_ROOT = Path(__file__).parents[1]


def _target(root: Path, absolute_path: str) -> Path:
    return root.joinpath(*Path(absolute_path).parts[1:])


@pytest.fixture
def stage_parent() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="meercata-package-tests-") as directory:
        yield Path(directory)


def test_builder_stages_and_verifies_complete_deterministic_image(
    stage_parent: Path,
) -> None:
    first_root = stage_parent / "first"
    second_root = stage_parent / "second"
    first = ProductionPackageBuilder(SOURCE_ROOT, first_root)
    second = ProductionPackageBuilder(SOURCE_ROOT, second_root)

    manifest = first.stage()
    second.stage()
    verification = first.verify()

    paths = {item["path"] for item in manifest["files"]}
    assert manifest["package"] == "meercata"
    assert manifest["ownership"] == {"user": "root", "group": "root"}
    assert "/usr/bin/meercata" in paths
    assert "/usr/lib/meercata/python/meercata/menu.py" in paths
    assert "/usr/lib/meercata/bin/meercata-helper" in paths
    assert "/usr/lib/meercata/bin/meercata-ruleops-vm-qualifier" in paths
    assert "/usr/lib/meercata/bin/meercata-recovery-vm-qualifier" in paths
    assert "/usr/lib/meercata/bin/meercata-ips-systemd-vm-qualifier" in paths
    assert "/usr/lib/meercata/bin/meercata-monitor-qualifier" in paths
    assert "/usr/lib/meercata/bin/meercata-monitor-delivery-qualifier" in paths
    assert "/usr/lib/meercata/bin/meercata-monitor-tls-qualifier" in paths
    assert "/usr/share/meercata/schemas/monitor-tls-qualification-v1.schema.json" in paths
    assert "/usr/lib/meercata/bin/meercata-ips-engine" in paths
    assert "/usr/lib/meercata/bin/meercata-ips-bootstrap" in paths
    assert "/usr/lib/meercata/bin/meercata-ips-guard" in paths
    assert (
        "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification.pcap"
        in paths
    )
    assert (
        "/usr/lib/meercata/regression-packs/dev13-ruleops-v1/qualification-a.rules"
        in paths
    )
    assert (
        "/usr/lib/meercata/regression-packs/production-baseline-v1/manifest.json"
        in paths
    )
    assert (
        "/usr/lib/meercata/regression-packs/production-baseline-v1/tls-benign.pcap"
        in paths
    )
    assert "/etc/sudoers.d/meercata" in paths
    assert "/usr/lib/systemd/system/meercata-health.timer" in paths
    assert "/usr/lib/systemd/system/meercata-monitor.service" in paths
    assert "/usr/lib/systemd/system/meercata-monitor.timer" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-freshness.service" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-freshness.timer" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-delivery.service" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-delivery.timer" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-delivery-health.service" in paths
    assert "/usr/lib/systemd/system/meercata-monitor-delivery-health.timer" in paths
    assert "/etc/logrotate.d/meercata-monitor" in paths
    assert "/usr/lib/systemd/system/meercata-suricata-ips.service" in paths
    assert "/usr/lib/systemd/system/meercata-ips-activate.service" in paths
    assert "/usr/lib/systemd/system/meercata-ips-guard.service" in paths
    assert "/usr/lib/systemd/system/meercata-ips.target" in paths
    assert "/usr/share/meercata/schemas/health-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/monitor-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/monitor-delivery-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/monitor-delivery-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/monitor-freshness-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/monitor-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/ips-systemd-vm-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/package-manifest-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/ruleops-vm-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/recovery-vm-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/nftables-namespace-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/nftables-transaction-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/nfqueue-functional-qualification-v1.schema.json" in paths
    assert "/usr/share/meercata/schemas/nfqueue-load-qualification-v1.schema.json" in paths
    assert "/usr/share/doc/meercata/NFTABLES-NAMESPACE.md" in paths
    assert "/usr/share/doc/meercata/NFTABLES-TRANSACTIONS.md" in paths
    assert "/usr/share/doc/meercata/NFQUEUE-FUNCTIONAL.md" in paths
    assert "/usr/share/doc/meercata/NFQUEUE-LOAD.md" in paths
    assert "/usr/share/doc/meercata/IPS-SYSTEMD.md" in paths
    assert "/usr/share/doc/meercata/MONITORING.md" in paths
    assert "/usr/share/doc/meercata/PACKAGING.md" in paths
    assert verification["status"] == "verified"
    assert verification["verified_files"] == len(manifest["files"])
    assert {
        item["path"] for item in manifest["directories"]
    } >= {
        "/usr/lib/systemd/system/suricata.service.d",
        "/usr/lib/meercata/regression-packs/dev13-ruleops-v1",
        "/usr/lib/meercata/regression-packs/production-baseline-v1",
    }
    assert _target(first_root, str(MANIFEST_PATH)).read_bytes() == _target(
        second_root, str(MANIFEST_PATH)
    ).read_bytes()

    expected_modes = {
        "/usr/bin/meercata": 0o755,
        "/usr/lib/meercata/bin/meercata-helper": 0o755,
        "/usr/lib/meercata/bin/meercata-ips-engine": 0o755,
        "/etc/sudoers.d/meercata": 0o440,
        "/usr/lib/systemd/system/meercata-health.service": 0o644,
    }
    for path, expected in expected_modes.items():
        assert stat.S_IMODE(_target(first_root, path).stat().st_mode) == expected


def test_builder_rejects_live_root_and_source_overlap() -> None:
    with pytest.raises(PackagingError, match="live filesystem root"):
        ProductionPackageBuilder(SOURCE_ROOT, Path("/"))

    with pytest.raises(PackagingError, match="must not overlap"):
        ProductionPackageBuilder(SOURCE_ROOT, SOURCE_ROOT / "build-image")

    with pytest.raises(PackagingError, match="must be absolute"):
        ProductionPackageBuilder(SOURCE_ROOT, Path("relative-image"))


def test_builder_rejects_unowned_collision_before_writing_package(
    stage_parent: Path,
) -> None:
    root = stage_parent / "image"
    collision = root / "usr" / "bin" / "meercata"
    collision.parent.mkdir(parents=True)
    collision.write_text("administrator file\n")
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)

    with pytest.raises(PackagingError, match="unowned destination"):
        builder.stage()

    assert collision.read_text() == "administrator file\n"
    assert not _target(root, str(MANIFEST_PATH)).exists()


def test_builder_does_not_change_mode_of_shared_parent_directory(
    stage_parent: Path,
) -> None:
    root = stage_parent / "image"
    shared = root / "etc" / "sudoers.d"
    shared.mkdir(parents=True)
    shared.chmod(0o750)

    ProductionPackageBuilder(SOURCE_ROOT, root).stage()

    assert stat.S_IMODE(shared.stat().st_mode) == 0o750


def test_builder_rejects_symlinked_destination_component(stage_parent: Path) -> None:
    root = stage_parent / "image"
    outside = stage_parent / "outside"
    outside.mkdir()
    (root / "usr").mkdir(parents=True)
    (root / "usr" / "bin").symlink_to(outside, target_is_directory=True)
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)

    with pytest.raises(PackagingError, match="directory component is unsafe"):
        builder.stage()

    assert list(outside.iterdir()) == []


def test_builder_rejects_symlinked_source_asset(stage_parent: Path) -> None:
    source = stage_parent / "source"
    shutil.copytree(
        SOURCE_ROOT,
        source,
        ignore=shutil.ignore_patterns(".pytest*", "__pycache__", "*.pyc"),
    )
    configuration = source / "config" / "meercata.example.toml"
    configuration.unlink()
    outside = stage_parent / "outside.toml"
    outside.write_text("untrusted = true\n")
    configuration.symlink_to(outside)
    builder = ProductionPackageBuilder(source, stage_parent / "image")

    with pytest.raises(PackagingError, match="not a regular file"):
        builder.stage()


def test_upgrade_refuses_modified_managed_file_and_removal_plan_preserves_it(
    stage_parent: Path,
) -> None:
    root = stage_parent / "image"
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)
    manifest = builder.stage()
    cli = _target(root, "/usr/bin/meercata")
    cli.write_text("locally modified\n")

    with pytest.raises(PackagingError, match="managed file was modified"):
        builder.stage()

    plan = builder.removal_plan()
    assert plan["status"] == "review-required"
    assert "/usr/bin/meercata" in plan["preserve_modified_files"]
    assert len(plan["removable_files"]) == len(manifest["files"]) - 1
    assert plan["preserve_runtime_roots"] == [
        "/etc/meercata",
        "/var/lib/meercata",
        "/var/log/meercata",
    ]
    assert plan["remove_manifest_last"] == str(MANIFEST_PATH)


def test_upgrade_rejects_unowned_entry_in_installed_code_directory(
    stage_parent: Path,
) -> None:
    root = stage_parent / "image"
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)
    builder.stage()
    injected = _target(
        root, "/usr/lib/meercata/python/meercata/unowned_extension.py"
    )
    injected.write_text("raise RuntimeError('must not be loaded')\n")

    with pytest.raises(PackagingError, match="unowned entry"):
        builder.stage()


def test_verify_detects_hash_mode_and_missing_file_failures(
    stage_parent: Path,
) -> None:
    root = stage_parent / "image"
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)
    builder.stage()
    cli = _target(root, "/usr/bin/meercata")
    cli.write_text("tampered\n")
    health = _target(root, "/usr/lib/systemd/system/meercata-health.service")
    health.chmod(0o600)
    timer = _target(root, "/usr/lib/systemd/system/meercata-health.timer")
    timer.unlink()

    with pytest.raises(PackagingError) as failure:
        builder.verify()

    message = str(failure.value)
    assert "/usr/bin/meercata: SHA-256 mismatch" in message
    assert "meercata-health.service: mode mismatch" in message
    assert "meercata-health.timer" in message


def test_manifest_cannot_claim_unowned_removal_target(stage_parent: Path) -> None:
    root = stage_parent / "image"
    builder = ProductionPackageBuilder(SOURCE_ROOT, root)
    builder.stage()
    manifest_path = _target(root, str(MANIFEST_PATH))
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][0]["path"] = "/etc/passwd"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(PackagingError, match="outside owned targets"):
        builder.removal_plan()


def test_package_builder_cli_stages_and_verifies_json(stage_parent: Path) -> None:
    root = stage_parent / "image"
    stdout = io.StringIO()

    result = main(
        ["stage", str(root), "--source-root", str(SOURCE_ROOT)], stdout=stdout
    )

    assert result == 0
    assert json.loads(stdout.getvalue())["package"] == "meercata"
    stdout = io.StringIO()
    assert main(
        ["verify", str(root), "--source-root", str(SOURCE_ROOT)], stdout=stdout
    ) == 0
    assert json.loads(stdout.getvalue())["status"] == "verified"


def test_package_builder_cli_rejects_live_root() -> None:
    stderr = io.StringIO()

    result = main(
        ["stage", "/", "--source-root", str(SOURCE_ROOT)], stderr=stderr
    )

    assert result == 3
    assert "live filesystem root" in stderr.getvalue()
