from pathlib import Path

import pytest

import yaml_tools


SAMPLE = """vars:
  address-groups:
    HOME_NET: \"[192.168.1.0/24]\"
    EXTERNAL_NET: \"!$HOME_NET\"
af-packet:
  - interface: eth0
    cluster-id: 10
    threads: auto
  - interface: eth1
    cluster-id: 11
nfq:
  mode: accept
  repeat-mark: 1
  repeat-mask: 1
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  # - \"disabled.rules\" # retained comment
runmode: workers
"""


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr(yaml_tools.shutil, "which", lambda name: None)
    monkeypatch.setattr(yaml_tools, "suricata_executable", lambda: None)
    path = tmp_path / "suricata.yaml"
    path.write_text(SAMPLE, encoding="utf-8")
    return path


def test_af_packet_parser_finds_multiple_interfaces(config):
    entries = yaml_tools.yaml_af_packet_entries(str(config))
    assert [(state, iface) for state, iface, _ in entries] == [
        ("enabled", "eth0"),
        ("enabled", "eth1"),
    ]


def test_rule_state_noop_does_not_create_backup(config):
    assert not yaml_tools.yaml_set_rule_state(str(config), "suricata.rules", "enabled")
    assert not list(config.parent.glob("*.bak"))


def test_rule_state_dry_run_does_not_write(config):
    original = config.read_text(encoding="utf-8")
    assert yaml_tools.yaml_set_rule_state(str(config), "suricata.rules", "disabled", apply=False)
    assert config.read_text(encoding="utf-8") == original
    assert not list(config.parent.glob("*.bak"))


def test_rule_state_preserves_disabled_line_content(config):
    assert yaml_tools.yaml_set_rule_state(str(config), "disabled.rules", "enabled")
    assert '  - "disabled.rules" # retained comment' in config.read_text(encoding="utf-8")
    assert len(list(config.parent.glob("*.bak"))) == 1


def test_nfq_noop_does_not_create_backup(config):
    yaml_tools.yaml_set_nfq_kv(str(config), "mode", "accept")
    assert not list(config.parent.glob("*.bak"))


def test_summary_reads_all_nfq_keys_and_interfaces(config, capsys):
    yaml_tools.yaml_summary(str(config))
    output = capsys.readouterr().out
    assert "eth0" in output and "eth1" in output
    assert "mode" in output and "repeat-mark" in output and "repeat-mask" in output


def test_rule_filename_cannot_escape_rules_directory(config):
    with pytest.raises(ValueError):
        yaml_tools.yaml_add_rulefile(str(config), "../escape.rules")


def test_backups_are_unique(config):
    yaml_tools.yaml_set_rule_state(str(config), "suricata.rules", "disabled")
    yaml_tools.yaml_set_rule_state(str(config), "suricata.rules", "enabled")
    assert len(list(config.parent.glob("*.bak"))) == 2
