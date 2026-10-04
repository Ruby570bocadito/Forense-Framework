"""Installation helpers: `forense doctor`, configuration presets, health endpoint, frozen builds."""

from __future__ import annotations

import base64
import json
import sys

import pytest

from forense import doctor
from forense.cli import EXIT_ERROR, EXIT_OK, main
from forense.core.config import load_config, set_config, write_template
from forense.parsers import volatility
from forense.web import create_app


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSE_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("FORENSE_WORKSPACE", str(tmp_path / "cases"))
    set_config(None)
    yield
    set_config(None)


def test_doctor_reports_every_dependency(capsys):
    checks = doctor.run_checks()
    names = {c.name for c in checks}
    assert {dist for _, dist, _, _ in doctor.DEPENDENCIES} <= names and "Python" in names
    assert doctor.healthy(checks)
    assert all(c.status in ("ok", "warn", "missing", "error") and c.purpose for c in checks)
    assert main(["diagnostico", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "pytsk3" in out and "La instalación está lista." in out


def test_doctor_json_and_failure(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "DEPENDENCIES", doctor.DEPENDENCIES + (
        ("forense_no_such_module", "no-such-dist", "doctor.purpose.evtx", True),))
    assert main(["doctor", "--json"]) == EXIT_ERROR
    report = json.loads(capsys.readouterr().out)
    broken = [c for c in report["checks"] if c["status"] == "error"]
    assert not report["healthy"] and [c["name"] for c in broken] == ["no-such-dist"]
    assert "ModuleNotFoundError" in broken[0]["detail"]


def test_doctor_flags_missing_intelligence_and_bad_config(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("intel:\n  hash_lists: [/nonexistent/hashes.txt]\n", encoding="utf-8")
    checks = {c.name: c for c in doctor.run_checks(load_config(config))}
    assert checks["Hash lists"].status == "warn" and "hashes.txt" in checks["Hash lists"].detail
    config.write_text("intel: [unclosed\n", encoding="utf-8")
    assert any(c.status == "error" and c.name == "Configuration" for c in doctor.run_checks())


def test_config_init_presets_are_quoted(tmp_path, capsys):
    target = tmp_path / "preset.yaml"
    workspace = tmp_path / "Casos de O'Brien"
    assert main(["config", "init", str(target), "-w", str(workspace), "--analyst", "Ana \\ López"]) == EXIT_OK
    config = load_config(target)
    assert config.value("workspace") == str(workspace.resolve()) and config.value("analyst") == "Ana \\ López"
    assert config.value("web.port") == 8765  # the rest of the template is intact
    path = write_template(tmp_path / "win.yaml", workspace="C:\\Users\\ana\\Casos")
    assert load_config(path).value("workspace") == "C:\\Users\\ana\\Casos"


def test_health_endpoint_needs_no_password(tmp_path):
    client = create_app(tmp_path, password="s3cret").test_client()
    assert client.get("/healthz").get_json() == {"status": "ok"}
    assert client.get("/").status_code == 401
    auth = base64.b64encode(b"x:s3cret").decode()
    assert client.get("/", headers={"Authorization": f"Basic {auth}"}).status_code == 200


def test_volatility_command_in_a_frozen_build(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(volatility.shutil, "which", lambda name: "/usr/bin/python3" if name == "python3" else None)
    assert volatility.volatility_command("/opt/vol/vol.py") == ["/usr/bin/python3", "/opt/vol/vol.py"]
    assert volatility.volatility_command("C:\\vol\\vol.exe") == ["C:\\vol\\vol.exe"]
    command = volatility.volatility_command()
    assert command is None or sys.executable not in command  # never "forense.exe -c ..."
    monkeypatch.setattr(volatility.shutil, "which", lambda name: None)
    assert volatility.volatility_command("/opt/vol/vol.py") is None
