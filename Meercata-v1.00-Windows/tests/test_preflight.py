from types import SimpleNamespace

import preflight


def test_full_check_reports_missing_core_requirements(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "IS_WINDOWS", False)
    monkeypatch.setattr(preflight, "IS_LINUX", True)
    monkeypatch.setattr(preflight, "suricata_executable", lambda: None)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    checks = preflight.collect_requirements(
        command="check",
        config=str(tmp_path / "missing.yaml"),
        full=True,
    )

    assert not preflight.required_ok(checks)
    missing = {check.name for check in checks if check.required and not check.ok}
    assert "suricata" in missing
    assert "Suricata NFQ support" in missing
    assert "Suricata configuration" in missing
    assert "firewall backend" in missing


def test_read_only_rule_listing_does_not_require_suricata(tmp_path, monkeypatch):
    config = tmp_path / "suricata.yaml"
    config.write_text("rule-files: []\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "IS_WINDOWS", False)
    monkeypatch.setattr(preflight, "IS_LINUX", True)
    monkeypatch.setattr(preflight, "suricata_executable", lambda: None)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    checks = preflight.collect_requirements(command="rules", config=str(config))

    assert preflight.required_ok(checks)
    suricata = next(check for check in checks if check.name == "suricata")
    assert not suricata.ok and not suricata.required


def test_applied_ips_requires_nfq_backend_and_root(tmp_path, monkeypatch):
    config = tmp_path / "suricata.yaml"
    config.write_text("rule-files: []\n", encoding="utf-8")
    available = {"suricata": "/usr/bin/suricata", "nft": "/usr/sbin/nft"}
    monkeypatch.setattr(preflight, "IS_WINDOWS", False)
    monkeypatch.setattr(preflight, "IS_LINUX", True)
    monkeypatch.setattr(preflight, "suricata_executable", lambda: available["suricata"])
    monkeypatch.setattr(preflight, "is_administrator", lambda: True)
    monkeypatch.setattr(preflight, "valid_capture_target", lambda value: value == "eth0")
    monkeypatch.setattr(preflight.shutil, "which", lambda name: available.get(name))
    monkeypatch.setattr(preflight.Path, "exists", lambda self: True)

    def fake_run(cmd, **kwargs):
        if "--build-info" in cmd:
            return SimpleNamespace(returncode=0, stdout="NFQueue support: yes", stderr="")
        return SimpleNamespace(returncode=0, stdout="This is Suricata version 8", stderr="")

    monkeypatch.setattr(preflight.subprocess, "run", fake_run)
    checks = preflight.collect_requirements(
        command="ips",
        config=str(config),
        backend="nft",
        iface="eth0",
        apply=True,
    )

    assert preflight.required_ok(checks)


def test_requirement_report_labels_optional_items():
    report = preflight.render_requirements([
        preflight.Requirement("tail", False, False, "not found"),
    ])
    assert "OPTIONAL" in report
    assert "tail" in report


def test_missing_requirement_includes_install_suggestion():
    suggestion = preflight.render_suggestions([
        preflight.Requirement("suricata", False, True, "not found"),
    ])
    assert "Install Suricata" in suggestion
    assert "Suggested actions" in suggestion
