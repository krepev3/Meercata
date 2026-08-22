import os
import subprocess
from pathlib import Path

import pytest

from systemd_unit import render_env, render_hook, render_unit


def test_environment_records_fail_mode():
    result = render_env("eth0", 5, "auto", "/etc/suricata/suricata.yaml", "closed")
    assert "FAIL_MODE=closed" in result


@pytest.mark.skipif(os.name == "nt", reason="Bash syntax validation runs on Linux")
def test_hook_script_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n"], input=render_hook(), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_unit_validates_config_and_conflicts_with_standard_service():
    unit = render_unit()
    assert "Conflicts=suricata.service" in unit
    assert "suricata -T" in unit
    assert "ExecStopPost=" in unit


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher syntax validation runs on Linux")
def test_source_launcher_has_valid_shell_syntax():
    launcher = Path(__file__).resolve().parents[1] / "meercata"
    result = subprocess.run(["sh", "-n", str(launcher)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
