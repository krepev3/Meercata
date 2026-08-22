import pytest

import suricata_ctl


@pytest.fixture(autouse=True)
def linux_mode(monkeypatch):
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", False)
    monkeypatch.setattr(suricata_ctl, "suricata_command", lambda: "suricata")
    monkeypatch.setattr(suricata_ctl, "suricata_env", lambda executable: {})
    monkeypatch.setattr(suricata_ctl, "suricata_working_directory", lambda executable: None)


def test_stop_matches_suricata_executable_command_line(monkeypatch):
    calls = []
    monkeypatch.setattr(suricata_ctl, "run", lambda cmd, apply, **kwargs: calls.append(cmd) or True)

    assert suricata_ctl.suricata_stop(False)

    assert ["pkill", "-f", suricata_ctl.SURICATA_PROCESS_PATTERN] in calls


def test_ips_rolls_back_xt_hooks_after_start_failure(monkeypatch):
    flushed = []
    monkeypatch.setattr(suricata_ctl, "pick_backend", lambda preference: "xt")
    monkeypatch.setattr(suricata_ctl, "active_managed_services", lambda: [])
    monkeypatch.setattr(suricata_ctl, "suricata_stop", lambda apply: True)
    monkeypatch.setattr(suricata_ctl, "suricata_test", lambda apply, cfg: True)
    monkeypatch.setattr(suricata_ctl, "flush_nft", lambda apply: True)
    monkeypatch.setattr(suricata_ctl, "flush_xt", lambda apply, queue, iface: flushed.append((apply, queue, iface)) or True)
    monkeypatch.setattr(suricata_ctl, "install_xt", lambda *args: True)
    monkeypatch.setattr(suricata_ctl, "run", lambda *args, **kwargs: False)

    assert not suricata_ctl.suricata_ips(True, "eth0", "suricata.yaml", "xt", 4)
    assert flushed[-1] == (True, 4, "eth0")


def test_ips_dry_run_does_not_perform_final_cleanup(monkeypatch):
    flush_count = 0

    def flush_xt(*args):
        nonlocal flush_count
        flush_count += 1
        return True

    monkeypatch.setattr(suricata_ctl, "pick_backend", lambda preference: "xt")
    monkeypatch.setattr(suricata_ctl, "suricata_stop", lambda apply: True)
    monkeypatch.setattr(suricata_ctl, "suricata_test", lambda apply, cfg: True)
    monkeypatch.setattr(suricata_ctl, "flush_nft", lambda apply: True)
    monkeypatch.setattr(suricata_ctl, "flush_xt", flush_xt)
    monkeypatch.setattr(suricata_ctl, "install_xt", lambda *args: True)
    monkeypatch.setattr(suricata_ctl, "run", lambda *args, **kwargs: True)

    assert suricata_ctl.suricata_ips(False, "eth0", "suricata.yaml", "xt", 0)
    assert flush_count == 1


def test_ids_ctrl_c_cleans_hooks_and_restores_active_service(monkeypatch):
    calls = []
    flushed = []
    monkeypatch.setattr(
        suricata_ctl,
        "active_managed_services",
        lambda: ["suricata.service"],
    )
    monkeypatch.setattr(
        suricata_ctl,
        "suricata_stop",
        lambda apply: calls.append(("stop", apply)) or True,
    )
    monkeypatch.setattr(suricata_ctl, "suricata_test", lambda apply, cfg: True)
    monkeypatch.setattr(
        suricata_ctl,
        "flush_xt",
        lambda apply, queue, iface: flushed.append(("xt", apply, queue, iface)) or True,
    )
    monkeypatch.setattr(
        suricata_ctl,
        "flush_nft",
        lambda apply: flushed.append(("nft", apply)) or True,
    )

    def fake_run(command, apply, **kwargs):
        calls.append(command)
        if command[0] == "suricata":
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(suricata_ctl, "run", fake_run)

    with pytest.raises(KeyboardInterrupt):
        suricata_ctl.suricata_ids(True, "wlan0", "suricata.yaml", 4)

    assert ("xt", True, 4, "wlan0") in flushed
    assert ("nft", True) in flushed
    assert ["systemctl", "start", "suricata.service"] in calls


def test_ips_ctrl_c_cleans_all_hooks_and_restores_inline_service(monkeypatch):
    calls = []
    flushed = []
    monkeypatch.setattr(suricata_ctl, "pick_backend", lambda preference: "nft")
    monkeypatch.setattr(
        suricata_ctl,
        "active_managed_services",
        lambda: ["suricata-inline.service"],
    )
    monkeypatch.setattr(
        suricata_ctl,
        "suricata_stop",
        lambda apply: calls.append(("stop", apply)) or True,
    )
    monkeypatch.setattr(suricata_ctl, "suricata_test", lambda apply, cfg: True)
    monkeypatch.setattr(suricata_ctl, "install_nft", lambda *args: True)
    monkeypatch.setattr(
        suricata_ctl,
        "flush_xt",
        lambda apply, queue, iface: flushed.append(("xt", apply, queue, iface)) or True,
    )
    monkeypatch.setattr(
        suricata_ctl,
        "flush_nft",
        lambda apply: flushed.append(("nft", apply)) or True,
    )

    def fake_run(command, apply, **kwargs):
        calls.append(command)
        if command[0] == "suricata":
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(suricata_ctl, "run", fake_run)

    with pytest.raises(KeyboardInterrupt):
        suricata_ctl.suricata_ips(True, "wlan0", "suricata.yaml", "nft", 4)

    assert ("xt", True, 4, "wlan0") in flushed
    assert ("nft", True) in flushed
    assert ["systemctl", "start", "suricata-inline.service"] in calls


def test_builtin_monitor_receives_trigger_log_path(monkeypatch):
    calls = []
    monkeypatch.setattr(
        suricata_ctl,
        "run",
        lambda command, apply, **kwargs: calls.append(command) or True,
    )

    suricata_ctl.live_monitor(
        "/var/log/suricata/eve.json",
        "builtin",
        trigger_log_path="./Trigger Drop-Alert.txt",
    )

    assert calls
    assert calls[0][1].endswith("suricatamon.py")
    assert calls[0][-2:] == ["--trigger-log", "./Trigger Drop-Alert.txt"]


def test_threat_monitor_follows_last_100_lines(monkeypatch, tmp_path):
    calls = []
    evidence = tmp_path / "Trigger Drop-Alert.txt"
    monkeypatch.setattr(suricata_ctl.shutil, "which", lambda name: "/usr/bin/tail" if name == "tail" else None)
    monkeypatch.setattr(
        suricata_ctl.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )

    assert suricata_ctl.follow_evidence_log(str(evidence), lines=100)

    assert evidence.exists()
    assert calls == [["tail", "-n", "100", "-F", "--", str(evidence)]]
