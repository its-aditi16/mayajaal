"""Mayajaal must protect any FastAPI app, not just the demo it was built around."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from conftest import AGENT, CHROME, client_for, drive

from mayajaal.alerts import Alerts
from mayajaal.bus import Bus
from mayajaal.cli import main as cli
from mayajaal.config import Settings
from mayajaal.memory import Memory
from mayajaal.models import Condition, Fix, Rule
from mayajaal.pipeline import Pipeline
from mayajaal.prove import Verifier
from mayajaal.safety import PromptScreen
from mayajaal.store import Store
from mayajaal.worker import build_pipeline, load_golden, load_object

CLINIC = Path(__file__).resolve().parent.parent / "examples" / "clinic_app"
WAITING = ("awaiting_approval", "needs_human", "error")


@pytest.fixture
def clinic(settings):
    sys.path.insert(0, str(CLINIC))
    sys.modules.pop("app", None)
    yield load_object("app:create_app")
    sys.path.remove(str(CLINIC))
    sys.modules.pop("app", None)


def clinic_pipeline(settings, store, factory) -> Pipeline:
    return Pipeline(settings, store, Memory(settings, store), _NoAI(), PromptScreen(settings), Alerts(settings),
                    factory, load_golden(str(CLINIC / "golden.json")))


class _NoAI:
    available = False
    label = "none"


def attack_clinic(app) -> None:
    client = client_for(app, AGENT, "192.0.2.10")
    for path in ("/robots.txt", "/.env", "/internal/admin-console", "/api/vault/keys/payments-master",
                 "/patients/export?limit=99999&format=sql", "/patients/103"):
        client.get(path)


def test_full_loop_on_a_different_app(settings, store, clinic):
    bus = Bus(settings, store)
    app = clinic(settings)
    pipeline = clinic_pipeline(settings, store, clinic)
    attack_clinic(app)
    incident = drive(pipeline, bus, WAITING)
    assert incident.status == "awaiting_approval", [t.message for t in incident.timeline]
    assert "/patients/export" in incident.blast_radius["data_routes"]
    assert incident.classification.label == "ai_agent"

    pipeline.approve(incident.fix_id, "tester")
    app.state.shield._loaded_at = 0.0
    assert client_for(app, AGENT, "192.0.2.99").get("/doctors").status_code == 403
    assert client_for(app, CHROME, "198.51.100.1").get("/doctors").status_code == 200
    # The billing script uses the same library as the attacker and must still work.
    assert client_for(app, {"user-agent": "python-httpx/0.28.1", "accept": "application/json"},
                      "198.51.100.2").get("/patients/export?limit=10").status_code == 200


def test_unusual_parameter_on_the_other_app_becomes_a_technique_rule(settings, store, clinic):
    bus = Bus(settings, store)
    app = clinic(settings)
    pipeline = clinic_pipeline(settings, store, clinic)
    attack_clinic(app)
    incident = drive(pipeline, bus, WAITING)
    rules = pipeline.store.get_fix(incident.fix_id).rules
    assert any(c.value == "format=sql" for r in rules if r.kind == "technique" for c in r.conditions)


def test_app_with_no_normal_traffic_cannot_get_a_fix_approved(settings, store, clinic):
    """Otherwise 'normal users still get through' would pass by testing nothing."""
    app = clinic(settings)
    attack_clinic(app)
    records = store.activity_since(0)
    fix = Fix(id="F", incident_id="I", rules=[Rule(id="r", kind="fingerprint", title="t", conditions=[
        Condition(field="fingerprint", op="eq", value=records[0].fingerprint)])])
    report = Verifier(settings, store, clinic, []).verify(fix, records)
    assert not report.passed
    assert "No normal traffic" in next(c for c in report.checks if c.name == "Normal users still get through").detail


def test_worker_loads_the_target_from_settings(settings, store, clinic, monkeypatch):
    settings.target_app = "app:create_app"
    settings.target_golden = str(CLINIC / "golden.json")
    pipeline = build_pipeline(settings, store)
    assert pipeline.verifier.app_factory is clinic and len(pipeline.golden) == 5


def test_default_target_is_the_demo(settings, store):
    pipeline = build_pipeline(settings, store)
    assert pipeline.verifier.app_factory.__module__ == "mayajaal.demo.app"
    assert len(pipeline.golden) == 15


def test_bad_target_specs_are_clear():
    with pytest.raises(ValueError, match="module:name"):
        load_object("no_colon_here")


def test_record_golden_keeps_normal_traffic_and_leaves_out_attackers(tmp_path, monkeypatch, clinic):
    settings = Settings(data_dir=tmp_path, secret_key="s", trust_forwarded_for=True, memory_backend="local",
                        llm_provider="none", _env_file=None)
    app = clinic(settings)
    store = Store(settings.db_path)
    bus = Bus(settings, store)
    normal = client_for(app, CHROME, "198.51.100.1")
    normal.get("/")
    normal.get("/doctors")
    normal.get("/doctors")  # Duplicates are dropped.
    normal.get("/patients/404404")  # Failures are not a normal baseline.
    attack_clinic(app)
    pipeline = clinic_pipeline(settings, store, clinic)
    for event in bus.consume():
        pipeline.handle_event(event)

    monkeypatch.setenv("MAYAJAAL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MAYAJAAL_SECRET_KEY", "s")
    out = tmp_path / "golden.json"
    assert cli(["record-golden", "--out", str(out)]) == 0
    golden = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(item["path"] for item in golden) == ["/", "/doctors"]
    assert not any("python-httpx" in item["headers"].get("user-agent", "") for item in golden)
    assert load_golden(str(out))[0].expect == 200


def test_recording_is_not_poisoned_by_signed_in_or_credentialed_requests(tmp_path, clinic):
    from mayajaal.prove import record_golden

    settings = Settings(data_dir=tmp_path, secret_key="s", trust_forwarded_for=True, _env_file=None)
    app = clinic(settings)
    client_for(app, CHROME, "198.51.100.1").get("/doctors", headers={"authorization": "Bearer real-user-token"})
    golden = record_golden(settings, Store(settings.db_path))
    assert golden == []
    assert "real-user-token" not in json.dumps(golden)


def test_core_import_needs_no_optional_packages():
    """`pip install mayajaal` alone must be enough to protect an app."""
    import subprocess

    code = (
        "import sys\n"
        "for blocked in ('streamlit', 'pandas', 'redis', 'mcp', 'hindsight_client', 'agent_framework'):\n"
        "    sys.modules[blocked] = None\n"
        "from fastapi import FastAPI\n"
        "from mayajaal import protect\n"
        "from mayajaal.config import Settings\n"
        "import tempfile\n"
        "protect(FastAPI(), settings=Settings(data_dir=tempfile.mkdtemp(), secret_key='s', _env_file=None))\n"
        "import mayajaal.worker\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert result.stdout.strip() == "ok", result.stderr[-800:]
