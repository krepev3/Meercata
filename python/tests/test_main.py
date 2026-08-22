import main
from preflight import Requirement


def test_startup_requirement_check_blocks_and_suggests(monkeypatch, capsys):
    monkeypatch.setattr(
        main,
        "collect_requirements",
        lambda **kwargs: [Requirement("suricata", False, True, "not found")],
    )

    assert not main.startup_requirement_check("suricata.yaml", "auto", "eth0")

    output = capsys.readouterr().out
    assert "cannot start" in output
    assert "Install Suricata" in output


def test_front_menu_routes_threat_monitoring(monkeypatch, capsys):
    launched = []
    answers = iter(["2", "0"])
    monkeypatch.setattr(main, "_load_defaults", lambda: ("suricata.yaml", "wlan0", 4, "nft"))
    monkeypatch.setattr(main.subprocess, "check_output", lambda *args, **kwargs: "This is Suricata 8")
    monkeypatch.setattr(main, "_clear_screen", lambda: None)
    monkeypatch.setattr(main, "_print_banner", lambda: None)
    monkeypatch.setattr(main, "_iface_ips", lambda: {"wlan0": ["192.0.2.10"]})
    monkeypatch.setattr(main, "_cfg_status", lambda cfg: "ok")
    monkeypatch.setattr(main, "_service_status", lambda: "inactive")
    monkeypatch.setattr(main, "_pause", lambda: None)
    monkeypatch.setattr(
        main,
        "launch_threat_monitor",
        lambda: launched.append(True),
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    main.interactive_menu()

    assert launched == [True]
    assert "2) Threat Monitoring (tail evidence continuously)" in capsys.readouterr().out
