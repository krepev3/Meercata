from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_packaging_templates_have_install_safe_source_modes() -> None:
    expected_modes = {
        ROOT / "packaging" / "bin" / "meercata": 0o755,
        ROOT / "packaging" / "bin" / "meercata-helper": 0o755,
        ROOT / "packaging" / "bin" / "meercata-package-lifecycle": 0o755,
        ROOT / "packaging" / "bin" / "meercata-ips-engine": 0o755,
        ROOT / "packaging" / "bin" / "meercata-ips-bootstrap": 0o755,
        ROOT / "packaging" / "bin" / "meercata-ips-guard": 0o755,
        ROOT / "packaging" / "bin" / "meercata-systemd-vm-qualifier": 0o755,
        ROOT / "packaging" / "bin" / "meercata-ruleops-vm-qualifier": 0o755,
        ROOT / "packaging" / "bin" / "meercata-ips-systemd-vm-qualifier": 0o755,
        ROOT / "packaging" / "bin" / "meercata-monitor-qualifier": 0o755,
        ROOT / "packaging" / "bin" / "meercata-monitor-delivery-qualifier": 0o755,
        ROOT / "packaging" / "sudoers.d" / "meercata": 0o440,
        ROOT / "packaging" / "sysusers.d" / "meercata.conf": 0o644,
        ROOT / "packaging" / "tmpfiles.d" / "meercata.conf": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-health.service": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-health.timer": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor.service": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor.timer": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-freshness.service": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-freshness.timer": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-delivery.service": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-delivery.timer": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-delivery-health.service": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "meercata-monitor-delivery-health.timer": 0o644,
        ROOT / "packaging" / "logrotate.d" / "meercata-monitor": 0o644,
        ROOT / "packaging" / "systemd" / "system" / "meercata-suricata-ips.service": 0o644,
        ROOT / "packaging" / "systemd" / "system" / "meercata-ips-activate.service": 0o644,
        ROOT / "packaging" / "systemd" / "system" / "meercata-ips-guard.service": 0o644,
        ROOT / "packaging" / "systemd" / "system" / "meercata-ips.target": 0o644,
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "suricata.service.d"
        / "50-meercata-production.conf": 0o644,
        ROOT / "packaging" / "debian" / "control.in": 0o644,
        ROOT / "packaging" / "debian" / "changelog.in": 0o644,
        ROOT / "packaging" / "debian" / "copyright": 0o644,
        ROOT / "packaging" / "debian" / "meercata.1": 0o644,
        ROOT / "packaging" / "apt" / "debian-backports.sources": 0o644,
        ROOT / "packaging" / "debian" / "preinst": 0o755,
        ROOT / "packaging" / "debian" / "postinst": 0o755,
        ROOT / "packaging" / "debian" / "prerm": 0o755,
        ROOT / "packaging" / "debian" / "postrm": 0o755,
    }

    for path, expected_mode in expected_modes.items():
        assert path.stat().st_mode & 0o777 == expected_mode


def test_sudoers_template_allows_only_fixed_ruleops_uuid_shape() -> None:
    policy = (ROOT / "packaging" / "sudoers.d" / "meercata").read_text()

    assert "/usr/lib/meercata/bin/meercata-helper" in policy
    assert "rules\\.(snapshot|activate|rollback|reload)" in policy
    assert "health.socket-snapshot" in policy
    assert "nftables\\.(snapshot|apply|verify|rollback)" in policy
    assert "emergency\\.bypass" in policy
    assert "listener-loss|queue-overload|recovery-failed" in policy
    assert "NOPASSWD: MEERCATA_RULEOPS, MEERCATA_HEALTH, MEERCATA_NFTABLES, MEERCATA_BYPASS" in policy
    assert "ALL=(ALL)" not in policy
    assert "*" not in policy


def test_tmpfiles_protects_privileged_state_with_root_only_mode() -> None:
    policy = (ROOT / "packaging" / "tmpfiles.d" / "meercata.conf").read_text()

    assert "/var/lib/meercata/privileged                  0700 root root" in policy
    assert "/var/lib/meercata                             1770 root meercata-operators" in policy
    assert "/var/log/meercata                             1770 root meercata-operators" in policy
    assert "/var/log/meercata/privileged                  0700 root root" in policy
    assert "/var/lib/meercata/monitor                     0700 meercata meercata" in policy
    assert "/var/lib/meercata/monitor/outbox              0700 meercata meercata" in policy
    assert "/var/lib/meercata/monitor/dead-letter         0700 meercata meercata" in policy
    assert "/etc/meercata/credentials                    0750 root meercata" in policy
    assert "/var/log/meercata/monitor                     0700 meercata meercata" in policy
    assert "/run/meercata/monitor                         0700 meercata meercata" in policy
    assert "a+ /var/lib/meercata" in policy and "u:meercata:--x" in policy
    assert "a+ /var/log/meercata" in policy
    assert "a+ /run/meercata" in policy


def test_production_helper_launcher_is_python_only() -> None:
    launcher = (ROOT / "packaging" / "bin" / "meercata-helper").read_text()

    assert launcher.startswith("#!/usr/bin/python3\n")
    assert "sys.dont_write_bytecode = True" in launcher
    assert 'sys.path.insert(0, "/usr/lib/meercata/python")' in launcher
    assert "meercata.privileged_helper import main" in launcher


def test_production_cli_launcher_is_python_only() -> None:
    launcher = (ROOT / "packaging" / "bin" / "meercata").read_text()

    assert launcher.startswith("#!/usr/bin/python3\n")
    assert "sys.dont_write_bytecode = True" in launcher
    assert 'sys.path.insert(0, "/usr/lib/meercata/python")' in launcher
    assert "meercata.cli import main" in launcher


def test_package_lifecycle_launcher_is_python_only() -> None:
    launcher = (
        ROOT / "packaging" / "bin" / "meercata-package-lifecycle"
    ).read_text()

    assert launcher.startswith("#!/usr/bin/python3\n")
    assert "sys.dont_write_bytecode = True" in launcher
    assert "meercata.debian_lifecycle import main" in launcher


def test_debian_hooks_are_narrow_idempotent_dispatchers() -> None:
    directory = ROOT / "packaging" / "debian"
    scripts = {
        name: (directory / name).read_text()
        for name in ("preinst", "postinst", "prerm", "postrm")
    }

    for script in scripts.values():
        assert script.startswith("#!/bin/sh\nset -eu\n")
        assert "eval " not in script
        assert "curl " not in script
        assert "wget " not in script
        assert "rm -rf" not in script
        assert "nft " not in script
        assert "suricata-command" not in script
    assert "preinst-upgrade" in scripts["preinst"]
    assert "postinst-configure" in scripts["postinst"]
    assert "prerm-remove" in scripts["prerm"]
    assert "disable" not in scripts["postinst"]
    assert "enable" not in scripts["postinst"]
    assert "start" not in scripts["postinst"]
    assert "/etc/sudoers.d/meercata" not in scripts["postrm"]
    assert "daemon-reload" in scripts["postrm"]


def test_debian_dependencies_cover_supported_suricata_and_ruleops_tool() -> None:
    control = (ROOT / "packaging" / "debian" / "control.in").read_text()

    assert "suricata (>= 8.0)" in control
    assert "suricata-update (>= 1.3.8)" in control
    assert "nftables" in control
    assert "logrotate" in control


def test_backports_source_is_inert_scoped_and_archive_authenticated() -> None:
    source = (ROOT / "packaging" / "apt" / "debian-backports.sources").read_text()

    assert source == (
        "Types: deb\n"
        "URIs: http://deb.debian.org/debian\n"
        "Suites: trixie-backports\n"
        "Components: main\n"
        "Enabled: yes\n"
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
    )
    assert "/etc/apt" not in source


def test_sysusers_separates_service_identity_from_operator_group() -> None:
    policy = (ROOT / "packaging" / "sysusers.d" / "meercata.conf").read_text()

    assert "g meercata-operators" in policy
    assert 'u meercata' in policy
    assert "/usr/sbin/nologin" in policy
    assert "m meercata meercata-operators" not in policy


def test_suricata_override_requires_readiness_validation_and_restart_limits() -> None:
    policy = (
        ROOT
        / "packaging"
        / "systemd"
        / "system"
        / "suricata.service.d"
        / "50-meercata-production.conf"
    ).read_text()

    assert "Type=notify" in policy
    assert "NotifyAccess=main" in policy
    assert "ExecStartPre=/usr/bin/suricata -T" in policy
    assert "--init-errors-fatal" in policy
    assert "ExecReload=\n" in policy
    assert "Restart=on-failure" in policy
    assert "RestartSec=10s" in policy
    assert "StartLimitIntervalSec=300" in policy
    assert "StartLimitBurst=3" in policy
    assert "TimeoutStartSec=90s" in policy
    assert "TimeoutStopSec=60s" in policy


def test_health_timer_is_unprivileged_bounded_and_explicitly_enabled() -> None:
    service = (
        ROOT / "packaging" / "systemd" / "system" / "meercata-health.service"
    ).read_text()
    timer = (
        ROOT / "packaging" / "systemd" / "system" / "meercata-health.timer"
    ).read_text()

    assert "User=meercata" in service
    assert "Group=meercata" in service
    assert "ExecStart=/usr/bin/meercata health --json" in service
    assert "TimeoutStartSec=30s" in service
    assert "ProtectSystem=strict" in service
    assert (
        "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_AUDIT_WRITE CAP_NET_ADMIN"
        in service
    )
    assert "RestrictSUIDSGID=true" not in service
    assert "NoNewPrivileges" not in service
    assert "OnUnitActiveSec=1min" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer


def test_private_ips_target_orders_listener_policy_guard_and_fail_open_stop() -> None:
    root = ROOT / "packaging" / "systemd" / "system"
    engine = (root / "meercata-suricata-ips.service").read_text()
    activation = (root / "meercata-ips-activate.service").read_text()
    guard = (root / "meercata-ips-guard.service").read_text()
    target = (root / "meercata-ips.target").read_text()

    assert "Before=meercata-ips-activate.service" in engine
    assert "ExecStart=/usr/lib/meercata/bin/meercata-ips-engine run" in engine
    assert "PartOf=meercata-ips.target" in engine
    assert "Conflicts=suricata.service" in engine
    assert "\n[Install]\n" not in engine
    assert "Requires=meercata-suricata-ips.service" in activation
    assert "After=meercata-suricata-ips.service" in activation
    assert "Before=meercata-ips-guard.service" in activation
    assert "ExecStop=/usr/lib/meercata/bin/meercata-ips-bootstrap deactivate" in activation
    assert "User=root" in activation
    assert "Group=meercata-operators" in activation
    assert "UMask=0027" in activation
    assert "\n[Install]\n" not in activation
    assert "After=meercata-ips-activate.service" in guard
    assert "ExecStopPost=/usr/lib/meercata/bin/meercata-ips-bootstrap failsafe" in guard
    assert "TimeoutStopSec=60s" in guard
    assert "PartOf=meercata-ips.target" in guard
    assert "\n[Install]\n" not in guard
    assert "Requires=meercata-suricata-ips.service meercata-ips-activate.service" in target
    assert "Wants=meercata-ips-guard.service" in target
    assert "WantedBy=multi-user.target" in target


def test_monitor_timer_is_deduplicated_sandboxed_and_retained() -> None:
    root = ROOT / "packaging"
    service = (root / "systemd/system/meercata-monitor.service").read_text()
    timer = (root / "systemd/system/meercata-monitor.timer").read_text()
    rotation = (root / "logrotate.d/meercata-monitor").read_text()
    freshness = (root / "systemd/system/meercata-monitor-freshness.service").read_text()
    freshness_timer = (root / "systemd/system/meercata-monitor-freshness.timer").read_text()
    delivery = (root / "systemd/system/meercata-monitor-delivery.service").read_text()
    delivery_timer = (root / "systemd/system/meercata-monitor-delivery.timer").read_text()
    delivery_health = (root / "systemd/system/meercata-monitor-delivery-health.service").read_text()
    delivery_health_timer = (root / "systemd/system/meercata-monitor-delivery-health.timer").read_text()

    assert "User=meercata" in service
    assert "ExecStart=/usr/bin/meercata monitor run --json" in service
    assert "ProtectSystem=strict" in service
    assert "ReadWritePaths=/var/lib/meercata/monitor /var/log/meercata/monitor /run/meercata/monitor" in service
    assert "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_AUDIT_WRITE CAP_NET_ADMIN" in service
    assert "Conflicts=meercata-health.timer" in timer
    assert "OnUnitActiveSec=1min" in timer
    assert "Persistent=true" in timer
    assert "Also=meercata-monitor-freshness.timer" in timer
    assert "ExecStart=/usr/bin/meercata monitor freshness --json" in freshness
    assert "NoNewPrivileges=true" in freshness
    assert "CapabilityBoundingSet=\n" in freshness
    assert "OnUnitActiveSec=1min" in freshness_timer
    assert "ExecStart=/usr/bin/meercata monitor deliver --json" in delivery
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in delivery
    assert "NoNewPrivileges=true" in delivery
    assert "CapabilityBoundingSet=\n" in delivery
    assert "OnUnitActiveSec=1min" in delivery_timer
    assert "WantedBy=timers.target" in delivery_timer
    assert "Also=meercata-monitor-delivery-health.timer" in delivery_timer
    assert "ExecStart=/usr/bin/meercata monitor delivery-health --json" in delivery_health
    assert "RestrictAddressFamilies=AF_UNIX" in delivery_health
    assert "ReadWritePaths=/run/meercata/monitor" in delivery_health
    assert "OnUnitActiveSec=1min" in delivery_health_timer
    assert "size 4M" in rotation
    assert "rotate 12" in rotation
    assert "create 0600 meercata meercata" in rotation
    assert "delivery-receipts.jsonl" in rotation


def test_private_ips_launchers_are_fixed_python_entrypoints() -> None:
    expected = {
        "meercata-ips-engine": "meercata.ips_engine import main",
        "meercata-ips-bootstrap": "meercata.ips_bootstrap import main",
        "meercata-ips-guard": "meercata.ips_guard import main",
    }
    for name, entrypoint in expected.items():
        launcher = (ROOT / "packaging" / "bin" / name).read_text()
        assert launcher.startswith("#!/usr/bin/python3\n")
        assert "sys.dont_write_bytecode = True" in launcher
        assert entrypoint in launcher
        assert "subprocess" not in launcher
