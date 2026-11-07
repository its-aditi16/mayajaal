from __future__ import annotations

import re
import time
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Sensitivity = Literal["asset", "public", "user", "data", "credential", "trap"]


class Activity(BaseModel):
    id: int | None = None
    ts: float = Field(default_factory=time.time)
    ip_hash: str = ""
    ip_masked: str = ""
    fingerprint: str = ""
    token_hash: str | None = None
    session_hash: str | None = None
    honeytoken: str | None = None  # Fake by construction, so safe to keep for replay.
    served_hashes: list[str] = []
    method: str = "GET"
    path: str = "/"
    route: str = "/"
    query: str = ""
    status: int = 0
    user_agent: str = ""
    headers: dict[str, str] = {}
    body: str = ""
    sensitivity: Sensitivity = "public"
    trap_id: str | None = None
    blocked_by: str | None = None

    def rule_attrs(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "token_hash": self.token_hash or "",
            "session_hash": self.session_hash or "",
            "path": self.path,
            "query": self.query,
            "method": self.method,
            "user_agent": self.user_agent,
        }


# IP is deliberately not a field: attackers rotate IPs and real users share them.
RuleField = Literal["fingerprint", "token_hash", "session_hash", "path", "query", "method", "user_agent"]
NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")


class Condition(BaseModel):
    field: RuleField
    op: Literal["eq", "prefix", "contains", "regex"]
    value: str = Field(min_length=1, max_length=256)

    @field_validator("value")
    @classmethod
    def _no_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value


class Rule(BaseModel):
    id: str
    kind: Literal["credential", "fingerprint", "technique"]
    title: str = Field(max_length=200)
    conditions: list[Condition] = Field(min_length=1, max_length=5)


class Check(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class VerificationReport(BaseModel):
    passed: bool = False
    backend: str = ""
    checks: list[Check] = []
    duration_seconds: float = 0.0


FixStatus = Literal["draft", "rejected", "shadow", "awaiting_approval", "active", "revoked", "declined"]


class Fix(BaseModel):
    id: str
    incident_id: str
    status: FixStatus = "draft"
    source: Literal["ai", "template", "memory"] = "template"
    rationale: str = ""
    rules: list[Rule] = []
    report: VerificationReport | None = None
    reused_from: str | None = None
    created: float = Field(default_factory=time.time)
    shadow_started: float | None = None
    shadow_seconds: float = 0.0
    shadow_hits_attacker: int = 0
    shadow_hits_other: int = 0
    approved_by: str | None = None
    approved_at: float | None = None


class Classification(BaseModel):
    label: Literal["ai_agent", "human", "uncertain"] = "uncertain"
    score: float = 0.5
    reasons: list[str] = []
    features: dict[str, float] = {}


class Recollection(BaseModel):
    """A past attacker this one resembles, confirmed by deterministic comparison."""
    incident_id: str
    similarity: float
    identity_match: list[str] = []
    fix_id: str | None = None
    backend: str = ""
    memory_text: str = ""


class TimelineEntry(BaseModel):
    ts: float = Field(default_factory=time.time)
    stage: str
    message: str


IncidentStatus = Literal[
    "detected", "proving", "shadow", "awaiting_approval", "blocked", "declined", "needs_human", "error"
]


class Incident(BaseModel):
    id: str
    status: IncidentStatus = "detected"
    created: float = Field(default_factory=time.time)
    updated: float = Field(default_factory=time.time)
    first_activity_id: int = 0
    actor_keys: list[str] = []
    fingerprints: list[str] = []
    ip_hashes: list[str] = []
    token_hashes: list[str] = []
    session_hashes: list[str] = []
    activity_ids: list[int] = []
    traps_fired: list[str] = []
    signature: list[str] = []
    classification: Classification = Classification()
    blast_radius: dict = {}
    explanation: str = ""
    explanation_source: str = ""
    screened_items: int = 0
    shield_backend: str = ""
    recollection: Recollection | None = None
    fix_id: str | None = None
    time_to_fix_seconds: float | None = None
    analysis_seconds: float | None = None
    ai_calls: int = 0
    retained: bool = False
    hits_after_block: int = 0
    timeline: list[TimelineEntry] = []

    def log(self, stage: str, message: str) -> None:
        self.timeline.append(TimelineEntry(stage=stage, message=message))
        self.updated = time.time()
