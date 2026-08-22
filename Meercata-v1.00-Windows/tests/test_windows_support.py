import os
import subprocess

import platform_support
import preflight
import suricata_ctl


def test_binary_feature_detection_reads_windows_build_marker(tmp_path):
    binary = tmp_path / "suricata.exe"
    binary.write_bytes(b"prefix\x00WinDivert enabled:                       no\x00suffix")

    assert platform_support.binary_feature_enabled("WinDivert", str(binary)) is False

    binary.write_bytes(b"prefix\x00WinDivert enabled: yes\x00suffix")
    assert platform_support.binary_feature_enabled("WinDivert", str(binary)) is True


def test_windows_capture_target_accepts_ip_and_npf(monkeypatch):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(platform_support, "capture_interfaces", lambda: {"192.0.2.8": ["Ethernet"]})

    assert platform_support.valid_capture_target("192.0.2.8")
    assert platform_support.valid_capture_target(r"\Device\NPF_{D53813F6-9382-4292-93A0-DA131DA66D9F}")
    assert not platform_support.valid_capture_target("Ethernet")


def test_suricata_child_environment_adds_npcap_without_global_change(tmp_path, monkeypatch):
    executable = tmp_path / "suricata.exe"
    executable.write_bytes(b"")
    npcap = tmp_path / "Npcap"
    npcap.mkdir()
    (npcap / "wpcap.dll").write_bytes(b"")
    original_path = os.environ.get("PATH", "")
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(platform_support, "npcap_directory", lambda: npcap)

    child = platform_support.suricata_env(str(executable))

    assert str(npcap) in child["PATH"]
    assert str(tmp_path) in child["PATH"]
    assert os.environ.get("PATH", "") == original_path


def test_windows_runtime_probe_is_deferred_for_admin_only_npcap(tmp_path, monkeypatch):
    config = tmp_path / "suricata.yaml"
    config.write_text("rule-files: []\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "IS_WINDOWS", True)
    monkeypatch.setattr(preflight, "IS_LINUX", False)
    monkeypatch.setattr(preflight, "suricata_executable", lambda: r"C:\Suricata\suricata.exe")
    monkeypatch.setattr(preflight, "suricata_version_hint", lambda path: "8.0.6")
    monkeypatch.setattr(preflight, "npcap_admin_only", lambda: True)
    monkeypatch.setattr(preflight, "npcap_status", lambda: (True, "driver running; administrator-only capture access"))
    monkeypatch.setattr(preflight, "is_administrator", lambda: False)
    monkeypatch.setattr(preflight, "valid_capture_target", lambda value: True)
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("runtime probe must be deferred")),
    )

    checks = preflight.collect_requirements(
        command="ids",
        config=str(config),
        iface="192.0.2.8",
        apply=True,
    )

    runtime = next(check for check in checks if check.name == "Suricata runtime")
    assert runtime.ok
    assert "deferred until elevated" in runtime.detail
    missing = {check.name for check in checks if check.required and not check.ok}
    assert missing == {"Administrator privileges"}


def test_windows_applied_ips_requires_windivert(tmp_path, monkeypatch):
    config = tmp_path / "suricata.yaml"
    config.write_text("rule-files: []\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "IS_WINDOWS", True)
    monkeypatch.setattr(preflight, "IS_LINUX", False)
    monkeypatch.setattr(preflight, "suricata_executable", lambda: r"C:\Suricata\suricata.exe")
    monkeypatch.setattr(preflight, "suricata_version_hint", lambda path: "8.0.6")
    monkeypatch.setattr(preflight, "binary_feature_enabled", lambda feature, path: False)
    monkeypatch.setattr(preflight, "npcap_admin_only", lambda: False)
    monkeypatch.setattr(preflight, "npcap_status", lambda: (True, "driver running"))
    monkeypatch.setattr(preflight, "is_administrator", lambda: True)
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="Suricata 8.0.6", stderr=""),
    )

    checks = preflight.collect_requirements(command="ips", config=str(config), apply=True)

    missing = {check.name for check in checks if check.required and not check.ok}
    assert missing == {"Suricata WinDivert support"}


def test_windows_ips_uses_windivert_and_no_linux_hooks(monkeypatch):
    calls = []
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", True)
    monkeypatch.setattr(suricata_ctl, "active_managed_services", lambda: [])
    monkeypatch.setattr(suricata_ctl, "suricata_stop", lambda apply: True)
    monkeypatch.setattr(suricata_ctl, "suricata_test", lambda apply, cfg: True)
    monkeypatch.setattr(suricata_ctl, "suricata_command", lambda: r"C:\Suricata\suricata.exe")
    monkeypatch.setattr(suricata_ctl, "suricata_env", lambda executable: {"PATH": "test"})
    monkeypatch.setattr(suricata_ctl, "suricata_working_directory", lambda executable: r"C:\Suricata")
    monkeypatch.setattr(suricata_ctl, "restore_pre_run_state", lambda *args: True)
    monkeypatch.setattr(suricata_ctl, "flush_xt", lambda *args: (_ for _ in ()).throw(AssertionError("Linux hook called")))
    monkeypatch.setattr(suricata_ctl, "flush_nft", lambda *args: (_ for _ in ()).throw(AssertionError("Linux hook called")))
    monkeypatch.setattr(suricata_ctl, "run", lambda command, apply, **kwargs: calls.append((command, kwargs)) or True)

    assert suricata_ctl.suricata_ips(
        True,
        "",
        r"C:\Suricata\suricata.yaml",
        "auto",
        0,
        windivert_filter="tcp or icmp",
        forward=True,
    )

    assert calls[0][0] == [
        r"C:\Suricata\suricata.exe",
        "-c",
        r"C:\Suricata\suricata.yaml",
        "--windivert-forward",
        "tcp or icmp",
    ]


def test_windows_process_list_parses_tasklist(monkeypatch):
    output = '"suricata.exe","4321","Console","1","120,000 K"\n'
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", True)
    monkeypatch.setattr(suricata_ctl.subprocess, "check_output", lambda *args, **kwargs: output)

    assert suricata_ctl.suricata_processes() == ["4321 suricata.exe"]


def test_windows_threat_monitor_uses_python_follower(monkeypatch, tmp_path):
    calls = []
    evidence = tmp_path / "evidence.txt"
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", True)
    monkeypatch.setattr(suricata_ctl, "_follow_file_python", lambda path, lines: calls.append((path, lines)))

    assert suricata_ctl.follow_evidence_log(str(evidence), 25)
    assert calls == [(str(evidence), 25)]
