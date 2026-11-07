from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from mayajaal.alerts import Alerts
from mayajaal.bus import Bus
from mayajaal.config import Settings
from mayajaal.demo.app import create_app
from mayajaal.demo.golden import CHROME, GOLDEN, SAFARI
from mayajaal.memory import Memory
from mayajaal.pipeline import Pipeline
from mayajaal.safety import PromptScreen
from mayajaal.store import Store


class NoAI:
    """The defender AI is down."""
    available = False
    label = "none"
    provider = "none"

    def explain(self, facts):
        return None

    def draft_rules(self, facts):
        return None


class RecordingAI:
    """Stands in for the model: records what it was shown and returns a scripted draft."""
    available = True
    label = "fake-model"
    provider = "fake"

    def __init__(self, draft=None, explanation="The attacker probed and stole data."):
        self.draft, self.explanation = draft, explanation
        self.seen: list[dict] = []

    def explain(self, facts):
        self.seen.append(facts)
        return self.explanation

    def draft_rules(self, facts):
        self.seen.append(facts)
        return self.draft(facts) if callable(self.draft) else self.draft


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path, secret_key="test-secret", admin_token="test-admin", trust_forwarded_for=True,
        settle_seconds=0, shadow_seconds=0, shadow_seconds_proven=0, sandbox_backend="inprocess",
        memory_backend="local", llm_provider="none", redis_url="", _env_file=None,
    )


@pytest.fixture
def store(settings) -> Store:
    return Store(settings.db_path)


@pytest.fixture
def bus(settings, store) -> Bus:
    return Bus(settings, store)


@pytest.fixture
def app(settings):
    return create_app(settings)


def client_for(app, headers: dict[str, str], ip: str = "198.51.100.1") -> TestClient:
    client = TestClient(app, base_url="http://testserver", follow_redirects=False)
    client.headers.clear()
    client.headers.update({**headers, "x-forwarded-for": ip})
    return client


@pytest.fixture
def make_pipeline(settings, store):
    def build(ai=None, memory=None, golden=None) -> Pipeline:
        return Pipeline(settings, store, memory or Memory(settings, store), ai or NoAI(), PromptScreen(settings),
                        Alerts(settings), create_app, golden if golden is not None else GOLDEN)
    return build


AGENT = {"user-agent": "python-httpx/0.28.1", "accept": "*/*"}
AGENT_DISGUISED = {"user-agent": "Mozilla/5.0 (X11; Linux) Chrome/131.0 Safari/537.36", "accept": "application/json",
                   "x-client-trace": "scout"}
EXPORT = "/api/customers/export?limit=100000&include=api_key"


def run_attack(app, headers=AGENT, ip="192.0.2.10", referer: str | None = None, use_stolen: bool = True) -> list[int]:
    client = client_for(app, headers, ip)
    statuses = []
    for path in ("/robots.txt", "/.env", "/internal/admin-console", "/backup/db.sql", "/api/vault/keys/payments-master"):
        statuses.append(client.get(path).status_code)
    export = client.get(EXPORT, headers={"referer": referer} if referer else {})
    statuses.append(export.status_code)
    statuses.append(client.get("/api/customers/9001").status_code)
    if use_stolen and export.status_code == 200:
        key = next(row["api_key"] for row in export.json()["customers"] if row["id"] == 9001)
        statuses.append(client.get("/api/profile", headers={"x-api-key": key}).status_code)
    return statuses


def drive(pipeline: Pipeline, bus: Bus, until: tuple[str, ...], steps: int = 30):
    """Run the worker loop by hand until the newest incident reaches a state."""
    incident = None
    for _ in range(steps):
        for event in bus.consume():
            pipeline.handle_event(event)
        pipeline.tick()
        incidents = pipeline.store.incidents()
        incident = incidents[-1] if incidents else None
        if incident and incident.status in until:
            return incident
    raise AssertionError(f"Never reached {until}; ended at {incident.status if incident else None}: "
                         f"{[t.message for t in incident.timeline] if incident else ''}")


__all__ = ["AGENT", "AGENT_DISGUISED", "CHROME", "EXPORT", "SAFARI", "RecordingAI", "NoAI", "client_for", "drive",
           "run_attack"]
