"""Webhook notifications after automation, and `sabueso update`."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from sabueso import __version__, update
from sabueso.automation import auto
from sabueso.cli import EXIT_ERROR, EXIT_OK, main
from sabueso.core.case import Case
from sabueso.core.config import load_config, set_config
from sabueso.core.errors import SabuesoError
from sabueso.notify import detect_format, payload


@pytest.fixture
def webhook():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()


@pytest.fixture(autouse=True)
def _config(tmp_path, monkeypatch):
    monkeypatch.setenv("SABUESO_CONFIG", str(tmp_path / "none.yaml"))
    set_config(None)
    yield
    set_config(None)


def _config_with(tmp_path, **notify):
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps({"notify": notify, "language": "es"}), encoding="utf-8")
    return load_config(path)


def test_formats_are_detected_from_the_url():
    assert detect_format("https://hooks.slack.com/services/T/B/x") == "slack"
    assert detect_format("https://chat.example.org/hooks/abc") == "slack"  # Mattermost
    assert detect_format("https://contoso.webhook.office.com/webhookb2/x") == "teams"
    assert detect_format("https://discord.com/api/webhooks/1/x") == "discord"
    assert detect_format("https://siem.example.org/sabueso") == "json"
    facts = {"case": "C", "case_id": "ID", "status": "ok", "findings": {"critical": 1, "high": 0, "medium": 0},
             "total_findings": 1, "top_findings": [], "steps": [], "reports": [], "path": "/x", "evidence": [],
             "exports": []}
    assert "*" in payload(facts, "slack")["text"] and payload(facts, "teams")["@type"] == "MessageCard"
    assert payload(facts, "teams")["themeColor"] == "B42318"  # critical findings
    assert payload(facts, "json")["event"] == "automation_finished"


def test_automation_sends_a_notification(tmp_path, evidence_dir, webhook):
    url, received = webhook
    config = _config_with(tmp_path, webhook=f"{url}/sabueso", format="json", min_severity="info")
    result = auto([evidence_dir], new_case=tmp_path / "case", playbook="triage", config=config)
    assert result.steps[-1].step == "notify" and result.steps[-1].status == "ok"
    path, body = received[0]
    assert path == "/sabueso" and body["event"] == "automation_finished" and body["case_id"].startswith("CASE-")
    assert "Análisis automático terminado" in body["text"]  # language of the configuration
    with Case.open(result.case_path) as case:
        entry = case.custody.entries()[-1]
        assert entry.action == "notification_sent" and entry.details["destination"] == "127.0.0.1"
        assert "sabueso" not in json.dumps(entry.details)  # the URL (and its token) is not stored
        assert case.custody.verify() == []


def test_a_failing_webhook_does_not_break_the_analysis(tmp_path, evidence_dir):
    config = _config_with(tmp_path, webhook="http://127.0.0.1:9/never", format="slack")
    result = auto([evidence_dir], new_case=tmp_path / "case", playbook="triage", config=config)
    assert [s.status for s in result.steps][-1] == "failed" and result.reports
    assert all(s.status in ("ok", "completed") for s in result.steps[:-1])


def test_cli_notify(tmp_path, evidence_dir, webhook, monkeypatch, capsys):
    url, received = webhook
    case = tmp_path / "case"
    assert main(["new", str(case), "-n", "N", "-i", "Ana"]) == EXIT_OK
    assert main(["-c", str(case), "notify"]) == EXIT_ERROR  # nothing configured
    config = tmp_path / "config.yaml"
    config.write_text(json.dumps({"notify": {"webhook": url, "format": "discord"}}), encoding="utf-8")
    capsys.readouterr()
    assert main(["--config", str(config), "-c", str(case), "notificar"]) == EXIT_OK
    assert "127.0.0.1" in capsys.readouterr().out and "content" in received[0][1]


# -- update ------------------------------------------------------------------------------------
def test_refs_only_keeps_main():
    """The retired development branch must not stay as an update fallback (refs-rama-heredada)."""
    assert update.REFS == ("main",)


def test_update_check_and_upgrade(monkeypatch):
    pages = {"main": None, "dev": '__version__ = "99.1.0"\n'}
    info = update.check(("main", "dev"), fetch=lambda url: pages["dev"] if "/dev/" in url else None)
    assert info.latest == "99.1.0" and info.ref == "dev" and info.available
    assert not update.check(("x",), fetch=lambda url: f'__version__ = "{__version__}"').available
    assert update.version_tuple("0.10.0") > update.version_tuple("0.9.9")
    calls = []
    pip_info = update.UpdateInfo("0.1.0", "99.1.0", "dev", "pip")
    command = update.upgrade(pip_info, run=lambda cmd, check: calls.append(cmd) or SimpleNamespace(returncode=0))
    assert command[1:4] == ["-m", "pip", "install"] and command[-1].endswith("/archive/refs/heads/dev.zip")
    with pytest.raises(SabuesoError):
        update.upgrade(pip_info, run=lambda cmd, check: SimpleNamespace(returncode=1))
    for mode, code in (("frozen", "error.update_frozen"), ("development", "error.update_development")):
        with pytest.raises(SabuesoError) as exc:
            update.upgrade(update.UpdateInfo("0.1.0", "99.1.0", "dev", mode))
        assert exc.value.code == code


def test_upgrade_keeps_the_volatility_extra(monkeypatch):
    """With Volatility 3 installed, the upgrade reinstalls the [memory] extra instead of a bare URL (H-002)."""
    monkeypatch.setattr("importlib.util.find_spec", lambda name: object() if name == "volatility3" else None)
    calls = []
    info = update.UpdateInfo("0.1.0", "99.1.0", "dev", "pip")
    command = update.upgrade(info, run=lambda cmd, check: calls.append(cmd) or SimpleNamespace(returncode=0))
    # built by parts: this sequence has been "eaten" twice by text layers between the analyst and the disk
    extra = "sabueso-framework[" + "m" + "emory]"
    assert command[-1] == f"{extra} @ https://github.com/{update.REPOSITORY}/archive/refs/heads/dev.zip"
    assert command[:4] == [sys.executable, "-m", "pip", "install"]


def test_cli_update(monkeypatch, capsys):
    monkeypatch.setattr(update, "check", lambda refs: update.UpdateInfo(__version__, __version__, "main", "pip"))
    assert main(["actualizar", "-L", "es"]) == EXIT_OK
    assert "Ya tiene la última versión" in capsys.readouterr().out
    monkeypatch.setattr(update, "check", lambda refs: update.UpdateInfo(__version__, "99.0.0", "main", "pip"))
    assert main(["update", "--check"]) == EXIT_OK
    assert "99.0.0" in capsys.readouterr().out
    monkeypatch.setattr(update, "check", lambda refs: update.UpdateInfo(__version__, None, None, "pip"))
    assert main(["update"]) == EXIT_ERROR


def test_simulated_upgrade_leaves_the_launcher_alone(monkeypatch, tmp_path):
    """A stand-in pip run must not rename the real sabueso.exe: nothing would write a new one (this test suite
    used to leave its own virtual environment without a launcher)."""
    launcher = tmp_path / "sabueso.exe"
    launcher.write_bytes(b"MZ")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    monkeypatch.setattr(sys, "platform", "win32")
    info = update.UpdateInfo("0.1.0", "99.1.0", "main", "pip")
    update.upgrade(info, run=lambda cmd, check: SimpleNamespace(returncode=0))
    assert launcher.is_file() and not (tmp_path / "sabueso.exe.old").exists()

