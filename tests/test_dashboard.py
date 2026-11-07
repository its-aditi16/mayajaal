"""Renders the real dashboard headlessly, in every state a viewer can meet."""
from __future__ import annotations

from pathlib import Path

import pytest
import streamlit as st
from conftest import drive, run_attack
from streamlit.testing.v1 import AppTest

DASHBOARD = str(Path(__file__).resolve().parent.parent / "mayajaal" / "dashboard_app.py")


@pytest.fixture
def dashboard(settings, monkeypatch):
    monkeypatch.setenv("MAYAJAAL_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("MAYAJAAL_SECRET_KEY", "test-secret")
    monkeypatch.setenv("MAYAJAAL_ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("MAYAJAAL_PUBLIC_BASE_URL", "http://127.0.0.1:9")  # Worker is down.
    st.cache_resource.clear()

    def render() -> AppTest:
        at = AppTest.from_file(DASHBOARD, default_timeout=180).run()
        assert not at.exception, at.exception
        return at

    return render


def text_of(at: AppTest) -> str:
    return " ".join(str(el.value) for group in (at.markdown, at.warning, at.info, at.error, at.success) for el in group)


def test_empty_state(dashboard):
    at = dashboard()
    assert "No traps have fired" in text_of(at)
    assert "Worker not running" in text_of(at)


def test_incident_awaiting_approval_offers_the_decision(dashboard, app, make_pipeline, bus):
    run_attack(app)
    drive(make_pipeline(), bus, ("awaiting_approval",))
    at = dashboard()
    assert any(b.label == "Approve block" for b in at.button)
    assert at.metric[0].value == "1"
    assert "Nothing is blocked until you approve" in text_of(at)


def test_blocked_incident_shows_the_block_and_can_be_revoked(dashboard, app, make_pipeline, bus):
    pipeline = make_pipeline()
    run_attack(app)
    incident = drive(pipeline, bus, ("awaiting_approval",))
    pipeline.approve(incident.fix_id, "tester")
    at = dashboard()
    assert "Approved by tester" in text_of(at)
    assert any(b.label == "Revoke this block" for b in at.button)


def test_approving_with_the_worker_down_shows_an_error_not_a_crash(dashboard, app, make_pipeline, bus):
    pipeline = make_pipeline()
    run_attack(app)
    incident = drive(pipeline, bus, ("awaiting_approval",))
    at = dashboard()
    next(b for b in at.button if b.label == "Approve block").click().run()
    assert not at.exception
    assert "Worker not reachable" in text_of(at)
    assert pipeline.store.get_fix(incident.fix_id).status == "awaiting_approval"


def test_memory_tab_shows_before_and_after(dashboard, app, make_pipeline, bus):
    from conftest import AGENT_DISGUISED

    pipeline = make_pipeline()
    run_attack(app)
    first = drive(pipeline, bus, ("awaiting_approval",))
    pipeline.approve(first.fix_id, "tester")
    app.state.shield._loaded_at = 0.0
    for _ in range(5):
        pipeline.tick()
        pipeline._background.submit(lambda: None).result()
    run_attack(app, headers=AGENT_DISGUISED, ip="192.0.2.77")
    second = drive(pipeline, bus, ("awaiting_approval",))
    pipeline.approve(second.fix_id, "tester")
    at = dashboard()
    labels = {metric.label for metric in at.metric}
    assert {"AI calls needed", "Watch-only wait"} <= labels
    assert "Recognised from memory" in text_of(at)
