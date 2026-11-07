"""Traps fire on intruders, stay silent for real users, and never hurt the host app."""
from __future__ import annotations

import asyncio
import json

from conftest import AGENT, CHROME, EXPORT, client_for, run_attack
from mcp import Client

from mayajaal.demo.app import DEMO_PASSWORD, STAFF_EMAIL
from mayajaal.privacy import mask, mask_ip
from mayajaal.traps import registry, tokens
from mayajaal.traps.mcp_decoys import build_server

SECRET = b"k" * 32
PREFIX = "kc_live_"


def trap_ids(store) -> list[str]:
    return [a.trap_id for a in store.activity_since(0) if a.trap_id]


def test_honeytoken_verifies_and_rejects_forgery():
    token = tokens.mint(SECRET, 3, "someone", PREFIX)
    assert tokens.verify(SECRET, token, PREFIX) == 3
    assert tokens.verify(b"other-key", token, PREFIX) is None
    flipped = token[:-1] + ("a" if token[-1] != "a" else "b")
    assert tokens.verify(SECRET, flipped, PREFIX) is None
    assert tokens.verify(SECRET, "cust_abcdef", PREFIX) is None
    assert tokens.verify(SECRET, PREFIX + "!!!not-base32!!!", PREFIX) is None


def test_each_requester_gets_their_own_dye():
    assert tokens.mint(SECRET, 1, "alice", PREFIX) != tokens.mint(SECRET, 1, "bob", PREFIX)


def test_normal_user_journey_fires_no_traps(app, store):
    client = client_for(app, CHROME)
    assert client.get("/").status_code == 200
    assert client.get("/products").status_code == 200
    assert client.post("/api/login", json={"email": STAFF_EMAIL, "password": DEMO_PASSWORD}).status_code == 200
    for path in ("/account", "/settings", "/api/orders", "/api/customers?limit=20", "/api/customers/export?limit=50"):
        assert client.get(path).status_code == 200
    assert trap_ids(store) == []


def test_every_web_trap_fires(app, store, bus):
    client = client_for(app, AGENT)
    for path in ("/.env", "/internal/admin-console", "/api/vault/keys/payments-master", "/api/customers/9001"):
        assert client.get(path).status_code == 200
    assert set(trap_ids(store)) == {"env_file", "admin_console", "vault_decoy", "canary_record"}
    assert len(bus.consume()) == 4


def test_export_alone_does_not_fire_but_using_the_stolen_key_does(app, store):
    """The dye pack: going straight for the data is caught when the loot is used."""
    client = client_for(app, AGENT)
    export = client.get(EXPORT).json()["customers"]
    assert trap_ids(store) == []
    key = next(row["api_key"] for row in export if row["id"] == 9001)
    assert client.get("/api/profile", headers={"x-api-key": key}).status_code == 401
    assert trap_ids(store) == ["canary_record"]


def test_real_customer_key_does_not_fire(app, store):
    client = client_for(app, AGENT)
    export = client.get(EXPORT).json()["customers"]
    real = next(row["api_key"] for row in export if row["id"] != 9001)
    assert client.get("/api/profile", headers={"x-api-key": real}).status_code == 200
    assert trap_ids(store) == []


def test_settings_page_bait_fires_only_when_used(app, store):
    client = client_for(app, CHROME)
    client.post("/api/login", json={"email": STAFF_EMAIL, "password": DEMO_PASSWORD})
    html = client.get("/settings").text
    assert "legacy_signing_key=" in html and trap_ids(store) == []
    key = html.split("legacy_signing_key=")[1].split()[0]
    client_for(app, AGENT, "192.0.2.5").get("/products", headers={"authorization": f"Bearer {key}"})
    assert trap_ids(store) == ["settings_secret"]


def test_secrets_and_personal_data_are_not_stored(app, store):
    client = client_for(app, CHROME)
    client.post("/api/login", json={"email": STAFF_EMAIL, "password": DEMO_PASSWORD})
    client.get("/api/profile", headers={"x-api-key": "cust_real_secret_value"})
    dump = " ".join(a.model_dump_json() for a in store.activity_since(0))
    assert DEMO_PASSWORD not in dump
    assert STAFF_EMAIL not in dump
    assert "cust_real_secret_value" not in dump
    assert "198.51.100.1" not in dump  # Only the masked form.


def test_masking():
    masked = mask("mail a.b@c.example card 4111 1111 1111 1111 phone +91 9876543210 pan ABCDE1234F password=hunter2")
    for secret in ("a.b@c.example", "4111", "9876543210", "ABCDE1234F", "hunter2"):
        assert secret not in masked
    assert mask_ip("203.0.113.9") == "203.0.113.x"


def test_retention_purge(store, app):
    client_for(app, CHROME).get("/")
    assert store.activity_since(0)
    assert store.purge_older_than(-1) >= 1
    assert store.activity_since(0) == []


def test_fingerprint_survives_new_ip_and_varying_headers(app, store):
    """Regression: an optional Referer used to look like a different device."""
    client_for(app, AGENT, "192.0.2.1").get("/products")
    client_for(app, AGENT, "192.0.2.2").get("/products", headers={"referer": "http://x/", "if-none-match": "abc"})
    prints = {a.fingerprint for a in store.activity_since(0)}
    assert len(prints) == 1


def test_fingerprint_changes_with_a_different_client(app, store):
    client_for(app, AGENT).get("/products")
    client_for(app, CHROME).get("/products")
    assert len({a.fingerprint for a in store.activity_since(0)}) == 2


def test_replay_headers_are_ignored_outside_the_sandbox(app, store):
    """Otherwise an attacker could forge someone else's identity, or shed their own."""
    client_for(app, AGENT).get("/products", headers={"x-replay-fingerprint": "forged", "x-replay-token-hash": "forged"})
    record = store.activity_since(0)[-1]
    assert record.fingerprint != "forged" and record.token_hash is None


def test_forwarded_for_is_ignored_unless_trusted(tmp_path):
    from mayajaal.config import Settings
    from mayajaal.demo.app import create_app
    from mayajaal.store import Store

    settings = Settings(data_dir=tmp_path, secret_key="s", redis_url="", _env_file=None)
    app = create_app(settings)
    client_for(app, AGENT, "192.0.2.1").get("/products")
    client_for(app, AGENT, "192.0.2.2").get("/products")
    assert len({a.ip_hash for a in Store(settings.db_path).activity_since(0)}) == 1


def test_host_app_survives_a_broken_store(app, store, monkeypatch):
    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(store.__class__, "add_activity", explode)
    assert client_for(app, CHROME).get("/products").status_code == 200


def test_decoy_tools_fire_and_the_real_tool_does_not(settings, store, bus):
    server = build_server(settings, store, bus)

    async def scenario():
        async with Client(server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert {"get_order_status", "get_admin_credentials", "export_all_customers",
                    "disable_audit_logging"} <= names
            await client.call_tool("get_order_status", {"order_id": "5001"})
            assert trap_ids(store) == []
            result = await client.call_tool("get_admin_credentials", {"reason": "maintenance"})
            return json.loads(result.content[0].text)

    payload = asyncio.run(scenario())
    assert tokens.verify(settings.secret, payload["api_key"], settings.token_prefix) == registry.BY_ID["mcp_decoy"].code
    assert trap_ids(store) == ["mcp_decoy"]
    assert bus.consume()[0]["trap_id"] == "mcp_decoy"


def test_bait_from_ai_tool_links_to_later_web_use(settings, store, bus, app):
    """A key stolen through the assistant and used on the website is the same actor."""
    from mayajaal.rewind import correlate

    server = build_server(settings, store, bus)

    async def steal():
        async with Client(server) as client:
            return json.loads((await client.call_tool("get_admin_credentials", {})).content[0].text)["api_key"]

    key = asyncio.run(steal())
    client_for(app, AGENT, "192.0.2.200").get("/products", headers={"authorization": f"Bearer {key}"})
    records = store.activity_since(0)
    web_use = next(r for r in records if r.honeytoken)
    linked = correlate(records, web_use)
    assert {r.path for r in linked} >= {"mcp://tools/get_admin_credentials", "/products"}


def test_run_attack_helper_is_realistic(app):
    statuses = run_attack(app)
    assert statuses == [200, 200, 200, 404, 200, 200, 200, 401]
