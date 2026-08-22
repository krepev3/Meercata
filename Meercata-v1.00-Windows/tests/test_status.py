import subprocess

import main
import suricata_ctl


def test_status_handles_missing_systemctl_and_pgrep(monkeypatch, capsys):
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", False)
    monkeypatch.setattr(suricata_ctl.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("systemctl")))
    monkeypatch.setattr(suricata_ctl.subprocess, "check_output", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("pgrep")))
    monkeypatch.setattr(suricata_ctl, "show_counters", lambda apply: None)
    monkeypatch.setattr(suricata_ctl.shutil, "which", lambda name: None)

    suricata_ctl.status()

    output = capsys.readouterr().out
    assert "unavailable" in output
    assert "[Processes] none" in output


def test_suricata_processes_returns_foreground_engine(monkeypatch):
    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", False)
    monkeypatch.setattr(
        suricata_ctl.subprocess,
        "check_output",
        lambda *args, **kwargs: "123 suricata -c /etc/suricata/suricata.yaml -q 4\n",
    )

    assert suricata_ctl.suricata_processes() == [
        "123 suricata -c /etc/suricata/suricata.yaml -q 4"
    ]


def test_service_status_queries_requested_unit(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[-1] == "missing-inline.service":
            return subprocess.CompletedProcess(command, 4, stdout="inactive\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="active\n", stderr="")

    monkeypatch.setattr(suricata_ctl, "IS_WINDOWS", False)
    monkeypatch.setattr(suricata_ctl.subprocess, "run", fake_run)

    assert main._service_status("suricata-inline.service") == "active"
    assert main._service_status("missing-inline.service") == "inactive"
    assert calls == [
        ["systemctl", "is-active", "suricata-inline.service"],
        ["systemctl", "is-active", "missing-inline.service"],
    ]


def test_diag_reports_standard_and_inline_services(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(main, "IS_WINDOWS", False)
    states = {
        "suricata.service": "inactive",
        "suricata-inline.service": "active",
    }
    monkeypatch.setattr(main, "_service_status", lambda unit: states[unit])
    monkeypatch.setattr(main, "suricata_processes", lambda: [])
    monkeypatch.setattr(main, "firewall_capabilities", lambda: [])
    monkeypatch.setattr(main, "existing_hooks", lambda queue, iface: [])

    main.diag_status(str(tmp_path / "suricata.yaml"), "wlan0", 4)

    output = capsys.readouterr().out
    assert "[Diag] Suricata service (standard): inactive" in output
    assert "[Diag] Meercata inline service: active" in output
