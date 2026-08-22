from types import SimpleNamespace
from unittest.mock import Mock

import hooks


def _only_iptables(name: str):
    return f"/usr/sbin/{name}" if name == "iptables" else None


def test_install_xt_uses_managed_chains_and_bypass(monkeypatch):
    calls = []
    monkeypatch.setattr(hooks.shutil, "which", _only_iptables)
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: calls.append(cmd) or True)

    assert hooks.install_xt(False, 7, "eth0", fail_open=True)

    assert ["iptables", "--wait", "-N", "MEERCATA_INPUT"] in calls
    assert any("meercata-managed" in cmd and "MEERCATA_INPUT" in cmd for cmd in calls)
    assert any("NFQUEUE" in cmd and "--queue-bypass" in cmd and "eth0" in cmd for cmd in calls)


def test_install_xt_closed_mode_omits_bypass(monkeypatch):
    calls = []
    monkeypatch.setattr(hooks.shutil, "which", _only_iptables)
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: calls.append(cmd) or True)

    assert hooks.install_xt(False, 0, "eth0", fail_open=False)

    nfqueue_calls = [cmd for cmd in calls if "NFQUEUE" in cmd]
    assert nfqueue_calls
    assert all("--queue-bypass" not in cmd for cmd in nfqueue_calls)


def test_flush_includes_legacy_interface_input_and_output(monkeypatch):
    calls = []
    monkeypatch.setattr(hooks.shutil, "which", _only_iptables)
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: calls.append(cmd) or True)

    assert hooks.flush_xt(False, 3, "enp1s0")

    assert ["iptables", "--wait", "-D", "INPUT", "-i", "enp1s0", "-j", "NFQUEUE", "--queue-num", "3"] in calls
    assert ["iptables", "--wait", "-D", "OUTPUT", "-o", "enp1s0", "-j", "NFQUEUE", "--queue-num", "3"] in calls


def test_allowlist_rejects_port_without_transport(monkeypatch):
    run_mock = Mock(return_value=True)
    monkeypatch.setattr(hooks, "run", run_mock)
    assert not hooks.allowlist_insert(False, "in", "all", "", "443")
    run_mock.assert_not_called()


def test_allowlist_uses_only_matching_address_family(monkeypatch):
    calls = []
    monkeypatch.setattr(hooks.shutil, "which", lambda name: f"/sbin/{name}")
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: calls.append(cmd) or True)

    assert hooks.allowlist_insert(False, "out", "tcp", "2001:db8::/32", "443")

    assert len(calls) == 1
    assert calls[0][0] == "ip6tables"
    assert "-d" in calls[0]


def test_nft_fail_modes(monkeypatch):
    scripts = []
    monkeypatch.setattr(hooks.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, stdin=None, **kwargs: scripts.append(stdin) or True)

    assert hooks.install_nft(False, 2, "eth0", True)
    assert "queue flags bypass to 2" in scripts[-1]
    assert hooks.install_nft(False, 2, "eth0", False)
    assert "queue to 2" in scripts[-1]
    assert "queue flags bypass" not in scripts[-1]


def test_backup_includes_managed_nft_table(tmp_path, monkeypatch):
    monkeypatch.setattr(hooks.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    monkeypatch.setattr(
        hooks.subprocess,
        "run",
        lambda args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"table inet {args[-1]} {{\n}}\n",
            stderr="",
        ),
    )

    assert hooks.backup_rules(True, str(tmp_path))
    assert (tmp_path / "nft-meercata.nft").read_text(encoding="utf-8") == "table inet meercata {\n}\n"
    assert (tmp_path / "nft-suri.nft").read_text(encoding="utf-8") == "table inet suri {\n}\n"


def test_restore_validates_and_loads_nft_backup(tmp_path, monkeypatch):
    (tmp_path / "nft-meercata.nft").write_text("table inet meercata {\n}\n", encoding="utf-8")
    run_calls = []
    monkeypatch.setattr(hooks.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    monkeypatch.setattr(
        hooks.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(hooks, "flush_nft", lambda apply: True)
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: run_calls.append((cmd, kwargs.get("stdin"))) or True)

    assert hooks.restore_rules(True, str(tmp_path))
    assert (["nft", "-f", "-"], "table inet meercata {\n}\n") in run_calls


def test_restore_supports_legacy_suri_table(tmp_path, monkeypatch):
    legacy = "table inet suri {\n}\n"
    (tmp_path / "nft-suri.nft").write_text(legacy, encoding="utf-8")
    run_calls = []
    monkeypatch.setattr(hooks.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    monkeypatch.setattr(
        hooks.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(hooks, "run", lambda cmd, apply, **kwargs: run_calls.append((cmd, kwargs.get("stdin"))) or True)

    assert hooks.restore_rules(True, str(tmp_path))
    assert (["nft", "delete", "table", "inet", "suri"], None) in run_calls
    assert (["nft", "-f", "-"], legacy) in run_calls
