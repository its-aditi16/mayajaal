"""Website-specific decoys: suggested by AI or rules, filtered by code, deployed only by a person."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from conftest import AGENT, CHROME, client_for

from mayajaal.cli import main as cli
from mayajaal.config import Settings
from mayajaal.demo.app import create_app
from mayajaal.store import Store
from mayajaal.traps import site_bait, tokens
from mayajaal.traps.site_bait import Decoy

CLINIC = Path(__file__).resolve().parent.parent / "examples" / "clinic_app"


def test_unsafe_suggestions_are_dropped():
    real = ["/", "/patients", "/patients/{patient_id}", "/users/{name}/settings", "/doctors"]
    ideas = [
        Decoy(path="/patients-archive/export-all", kind="data"),   # Fine.
        Decoy(path="/patients", kind="data"),                       # A real page.
        Decoy(path="/patients/export-all", kind="data"),            # Real {patient_id} route answers it.
        Decoy(path="/users/admin/settings", kind="page"),           # A user called "admin" would be caught.
        Decoy(path="/Admin Panel", kind="page"),                    # Not a simple path.
        Decoy(path="/../etc/passwd", kind="secret"),
        Decoy(path="/.env", kind="secret"),                         # Already a built-in trap.
        Decoy(path="/patients-archive/export-all", kind="data"),   # Duplicate.
    ]
    accepted, rejected = site_bait.validate(ideas, real)
    assert [d.path for d in accepted] == ["/patients-archive/export-all"]
    assert len(rejected) == 7


def test_rules_fit_each_app_without_ai():
    demo = site_bait.app_paths(create_app(Settings(data_dir=Path(__import__("tempfile").mkdtemp()), secret_key="s",
                                                   _env_file=None)))
    accepted, _ = site_bait.validate(site_bait.rule_suggestions(demo), demo)
    assert accepted and any("customers" in d.path for d in accepted)


def test_ai_suggestions_are_parsed_and_still_filtered():
    raw = {"decoys": [{"path": "/billing-ledger/export-all", "kind": "data", "reason": "bulk invoices"},
                      {"path": "/api/customers", "kind": "data"}, {"nonsense": True},
                      {"path": "/x", "kind": "execute"}]}
    accepted, rejected = site_bait.validate(site_bait.parse_ai_suggestions(raw), ["/api/billing", "/api/customers"])
    assert [d.path for d in accepted] == ["/billing-ledger/export-all"]
    assert rejected == [("/api/customers", "a real page already uses this path")]


def test_generic_suggestions_are_dropped_because_they_do_not_fit_the_app():
    ideas = [Decoy(path="/admin", kind="page"), Decoy(path="/config", kind="secret"),
             Decoy(path="/patients-archive/export-all", kind="data")]
    accepted, rejected = site_bait.validate(ideas, ["/patients", "/doctors"])
    assert [d.path for d in accepted] == ["/patients-archive/export-all"]
    assert all("generic" in why for _, why in rejected)


@pytest.fixture
def baited(settings, tmp_path):
    decoys = tmp_path / "decoys.json"
    decoys.write_text(json.dumps([{"path": "/customers-archive/export-all", "kind": "data", "reason": "r"},
                                  {"path": "/backup/kirana-db.sql", "kind": "secret", "reason": "r"}]))
    settings.decoys_file = str(decoys)
    return create_app(settings)


def test_site_decoy_fires_and_hands_out_a_signed_key(baited, store, bus, settings):
    response = client_for(baited, AGENT).get("/customers-archive/export-all")
    key = response.json()["records"][0]["api_key"]
    assert tokens.verify(settings.secret, key, settings.token_prefix) == 7
    assert [a.trap_id for a in store.activity_since(0) if a.trap_id] == ["site_decoy"]
    assert bus.consume()[0]["trap_id"] == "site_decoy"
    client_for(baited, AGENT, "192.0.2.200").get("/products", headers={"x-api-key": key})
    assert [a.trap_id for a in store.activity_since(0) if a.trap_id] == ["site_decoy", "site_decoy"]


def test_site_decoys_do_not_disturb_normal_users(baited, store):
    client = client_for(baited, CHROME)
    for path in ("/", "/products", "/robots.txt"):
        assert client.get(path).status_code == 200
    assert [a.trap_id for a in store.activity_since(0) if a.trap_id] == []


def test_nothing_is_live_until_a_person_deploys_the_file(app, store):
    assert client_for(app, AGENT).get("/customers-archive/export-all").status_code == 404
    assert [a.trap_id for a in store.activity_since(0) if a.trap_id] == []


def test_suggest_command_writes_a_reviewable_file_and_deploys_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("MAYAJAAL_LLM_PROVIDER", "none")
    monkeypatch.setenv("MAYAJAAL_DATA_DIR", str(tmp_path))
    monkeypatch.chdir(CLINIC)
    sys.modules.pop("app", None)
    out = tmp_path / "decoys.json"
    assert cli(["suggest-traps", "--app", "app:create_app", "--out", str(out)]) == 0
    suggested = site_bait.load(out)
    assert suggested and all(d.path.startswith("/") for d in suggested)
    assert any("patients" in d.path for d in suggested)
    sys.modules.pop("app", None)
