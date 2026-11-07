"""Teams approval cards, Sentinel events and signed one-time approval links.
Without a webhook or workspace configured, messages go to a local outbox file instead. An
alert failing must never stop detection or blocking, so failures are logged and swallowed."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time

import httpx

from .config import Settings
from .models import Fix, Incident
from .traps import registry

log = logging.getLogger("mayajaal.alerts")
APPROVAL_TTL_SECONDS = 4 * 3600
LABELS = {"ai_agent": "AI agent", "human": "Human", "uncertain": "Uncertain"}


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_approval(secret: bytes, fix_id: str, action: str, ttl: int = APPROVAL_TTL_SECONDS) -> str:
    payload = _b64(json.dumps({"fix": fix_id, "action": action, "exp": int(time.time()) + ttl,
                               "nonce": secrets.token_hex(8)}).encode())
    return f"{payload}.{_b64(hmac.new(secret, payload.encode(), hashlib.sha256).digest())}"


def read_approval(secret: bytes, token: str) -> dict | None:
    """Returns the claims if the signature is good and the link has not expired."""
    try:
        payload, signature = token.split(".", 1)
        expected = _b64(hmac.new(secret, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(_unb64(payload))
        return claims if claims["exp"] >= time.time() else None
    except Exception:
        return None


def build_card(incident: Incident, fix: Fix, approve_url: str, decline_url: str) -> dict:
    c = incident.classification
    radius = incident.blast_radius
    traps = ", ".join(registry.BY_ID[t].title if t in registry.BY_ID else t for t in incident.traps_fired)
    facts = [
        {"title": "Attacker", "value": f"{LABELS[c.label]} (score {c.score})"},
        {"title": "Traps fired", "value": traps or "none"},
        {"title": "Real data reached", "value": ", ".join(radius.get("data_routes", [])) or "none"},
        {"title": "Requests", "value": f"{radius.get('requests', 0)} in {radius.get('duration_seconds', 0)}s"},
        {"title": "Fix", "value": f"{fix.id}: {', '.join(sorted({r.kind for r in fix.rules}))} rules, from {fix.source}"},
        {"title": "Shadow mode", "value": f"{fix.shadow_hits_attacker} attacker hit(s), "
                                          f"{fix.shadow_hits_other} hit(s) on anyone else"},
    ]
    body: list[dict] = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": f"Mayajaal: approve block for {incident.id}?"},
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "wrap": True, "text": incident.explanation[:800]},
    ]
    if incident.recollection:
        body.append({"type": "TextBlock", "wrap": True, "color": "Attention",
                     "text": f"Memory: resembles {incident.recollection.incident_id} "
                             f"({incident.recollection.similarity:.0%} behaviour match)."})
    if fix.report:
        body.append({"type": "TextBlock", "wrap": True, "text": "Checks on " + fix.report.backend + ": " + "; ".join(
            f"{'PASS' if chk.passed else 'FAIL'} {chk.name}" for chk in fix.report.checks)})
    return {
        "type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4",
        "body": body,
        "actions": [{"type": "Action.OpenUrl", "title": "Approve block", "url": approve_url},
                    {"type": "Action.OpenUrl", "title": "Decline", "url": decline_url}],
    }


class Alerts:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.client = client or httpx.Client(timeout=10)
        self.outbox = settings.data_dir / "alerts_outbox.jsonl"
        self._sentinel_token: tuple[str, float] | None = None

    def _to_outbox(self, kind: str, payload: dict) -> None:
        try:
            self.outbox.parent.mkdir(parents=True, exist_ok=True)
            with self.outbox.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"ts": time.time(), "kind": kind, "payload": payload}) + "\n")
        except OSError as exc:
            log.warning("Could not write alert outbox: %s", exc)

    @property
    def teams_backend(self) -> str:
        return "teams" if self.settings.teams_webhook_url else "local outbox"

    @property
    def sentinel_backend(self) -> str:
        s = self.settings
        ready = s.sentinel_dce_endpoint and s.sentinel_dcr_id and s.sentinel_tenant_id
        return "sentinel" if ready else "local outbox"

    def request_approval(self, incident: Incident, fix: Fix, approve_url: str, decline_url: str) -> None:
        card = build_card(incident, fix, approve_url, decline_url)
        if not self.settings.teams_webhook_url:
            self._to_outbox("teams_card", card)
            return
        try:
            self.client.post(self.settings.teams_webhook_url, json={
                "type": "message",
                "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
            }).raise_for_status()
        except Exception as exc:
            log.warning("Teams alert failed (%s); saved to outbox", exc)
            self._to_outbox("teams_card", card)

    def _sentinel_bearer(self) -> str:
        if self._sentinel_token and self._sentinel_token[1] > time.time() + 60:
            return self._sentinel_token[0]
        s = self.settings
        response = self.client.post(
            f"https://login.microsoftonline.com/{s.sentinel_tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": s.sentinel_client_id,
                  "client_secret": s.sentinel_client_secret, "scope": "https://monitor.azure.com//.default"})
        response.raise_for_status()
        data = response.json()
        self._sentinel_token = (data["access_token"], time.time() + int(data.get("expires_in", 3000)))
        return data["access_token"]

    def send_event(self, event_type: str, incident: Incident) -> None:
        record = {
            "TimeGenerated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "EventType": event_type,
            "IncidentId": incident.id, "Status": incident.status, "AttackerClass": incident.classification.label,
            "Score": incident.classification.score, "Traps": incident.traps_fired,
            "BlastRadius": incident.blast_radius, "Fingerprints": incident.fingerprints,
        }
        if self.sentinel_backend != "sentinel":
            self._to_outbox("sentinel_event", record)
            return
        s = self.settings
        try:
            self.client.post(
                f"{s.sentinel_dce_endpoint.rstrip('/')}/dataCollectionRules/{s.sentinel_dcr_id}/streams/{s.sentinel_stream}",
                params={"api-version": "2023-01-01"},
                headers={"Authorization": f"Bearer {self._sentinel_bearer()}"}, json=[record],
            ).raise_for_status()
        except Exception as exc:
            log.warning("Sentinel send failed (%s); saved to outbox", exc)
            self._to_outbox("sentinel_event", record)
