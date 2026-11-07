"""Long-term memory of attackers, built on Hindsight (retain, recall, reflect).

Hindsight finds candidates. A deterministic comparison in the pipeline then confirms them, so
a fuzzy memory match alone can never label someone a returning attacker.

Every experience is also written to a small local table. That table is a safety net for when
Hindsight is unreachable, not a replacement for it, and results always say which one answered."""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass

from .config import Settings
from .models import Fix, Incident
from .store import Store
from .traps import registry

log = logging.getLogger("mayajaal.memory")
INCIDENT_ID = re.compile(r"INC-[0-9a-f]{8}")

RETAIN_MISSION = ("Extract what attackers did against this application: traps fired, order of probing, techniques, "
                  "what real pages and data they touched, and which fix stopped them. Keep incident ids exactly.")
REFLECT_MISSION = ("You advise a security team on deception. Reason from past attacks to say how attackers tend to "
                   "behave and where bait would catch them earliest. A person decides whether to act on it.")
OBSERVATIONS_MISSION = "Form durable observations about attacker behaviour patterns across incidents."

REFLECT_QUERY = ("Across the attacks seen so far: what do AI agents usually probe first, which traps catch them "
                 "earliest, which fixes worked, and where should new traps be placed? "
                 "Answer in at most five short bullet points, using only the recalled attacks.")
EXPERIENCE_QUERY = "Attack experience: attacker class, probe order, traps fired, data touched, outcome and fix"
MAX_REFLECT_MEMORIES = 6
MAX_REFLECT_MEMORY_CHARS = 500


@dataclass
class MemoryHit:
    incident_id: str
    text: str
    backend: str


def describe_signature(signature: list[str]) -> str:
    return " -> ".join(signature) if signature else "no recorded steps"


def experience_text(incident: Incident, fix: Fix | None) -> str:
    c = incident.classification
    radius = incident.blast_radius or {}
    traps = [registry.BY_ID[t].title if t in registry.BY_ID else t for t in incident.traps_fired]
    outcome = "no fix was deployed"
    if fix is not None:
        kinds = ", ".join(f"{r.kind} rule on {'+'.join(x.field for x in r.conditions)}" for r in fix.rules)
        outcome = f"fix {fix.id} ended as {fix.status} ({kinds})"
    return (
        f"Attack experience {incident.id}. Attacker class: {c.label} (score {c.score}). "
        f"Probe order: {describe_signature(incident.signature)}. "
        f"Traps fired: {'; '.join(traps) or 'none'}. "
        f"Real data endpoints touched: {', '.join(radius.get('data_routes', [])) or 'none'}. "
        f"Requests: {radius.get('requests', 0)}. Outcome: {outcome}."
    )


def recall_query(signature: list[str], traps: list[str]) -> str:
    return (f"Past attackers with this probe order: {describe_signature(signature)}. "
            f"Traps fired: {', '.join(traps)}. Which incident was this and which fix worked?")


def _words(text: str) -> set[str]:
    return {word.strip(".,:;-") for word in re.findall(r"[\w:/.-]+", text.lower())}


class LocalMemory:
    """Plain word overlap and counts, no intelligence. Keeps the system honest when offline."""

    name = "local-fallback"

    def __init__(self, store: Store, bank: str):
        self.store, self.bank = store, bank

    def retain(self, incident: Incident, fix: Fix | None) -> None:
        self.store.memory_add(self.bank, incident.id, experience_text(incident, fix), {
            "incident_id": incident.id, "label": incident.classification.label,
            "first_step": incident.signature[0] if incident.signature else "",
            "traps": incident.traps_fired,
        })

    def recall(self, query: str, limit: int = 5) -> list[MemoryHit]:
        words = _words(query)
        scored = []
        for row in self.store.memory_all(self.bank):
            overlap = len(words & _words(row["text"]))
            scored.append((overlap, row["id"], row))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [MemoryHit(row["document_id"], row["text"], self.name) for overlap, _, row in scored[:limit] if overlap]

    def reflect(self) -> str | None:
        rows = self.store.memory_all(self.bank)
        if not rows:
            return None
        agents = [r["metadata"] for r in rows if r["metadata"].get("label") == "ai_agent"]
        pool = agents or [r["metadata"] for r in rows]
        firsts = Counter(m["first_step"] for m in pool if m.get("first_step"))
        traps = Counter(t for m in pool for t in m.get("traps", []))
        lines = [f"Based on simple counts over {len(rows)} remembered attack(s), {len(agents)} labelled AI."]
        if firsts:
            step, count = firsts.most_common(1)[0]
            lines.append(f"Most common first step: {step} ({count} of {len(pool)}).")
        if traps:
            lines.append("Traps most often taken: " + ", ".join(f"{t} ({n})" for t, n in traps.most_common(3)) + ".")
            lines.append("Suggestion for review: add bait near the first step above so attackers trip earlier.")
        return " ".join(lines)


class HindsightMemory:
    name = "hindsight"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.bank = settings.hindsight_bank
        client = self._client(timeout=5)
        try:
            client.get_version()
        finally:
            client.close()
        self._create_bank()

    def _create_bank(self) -> None:
        client = self._client(timeout=30)
        try:
            client.create_bank(self.bank, retain_mission=RETAIN_MISSION, reflect_mission=REFLECT_MISSION,
                               retain_extraction_mode=self.settings.hindsight_extraction_mode,
                               # Observations need extracted facts and a background LLM job, which
                               # a laptop CPU cannot spare, so they run only with fact extraction.
                               enable_observations=self.settings.hindsight_extraction_mode != "chunks",
                               observations_mission=OBSERVATIONS_MISSION)
        finally:
            client.close()

    def _client(self, timeout: float = 300.0, attempts: int = 2):
        from hindsight_client import Hindsight

        return Hindsight(base_url=self.settings.hindsight_url, api_key=self.settings.hindsight_api_key or None,
                         timeout=timeout, max_attempts=attempts)

    def reset(self) -> None:
        """Forget everything in this bank, then recreate it empty."""
        client = self._client(timeout=60)
        try:
            client.delete_bank(self.bank)
        finally:
            client.close()
        self._create_bank()

    def retain(self, incident: Incident, fix: Fix | None) -> None:
        client = self._client()
        try:
            client.retain(
                bank_id=self.bank, content=experience_text(incident, fix), context="Mayajaal attack experience",
                document_id=incident.id, metadata={"incident_id": incident.id},
                tags=[f"class:{incident.classification.label}"],
            )
        finally:
            client.close()

    def recall(self, query: str, limit: int = 10) -> list[MemoryHit]:
        client = self._client(timeout=60)
        try:
            response = client.recall(bank_id=self.bank, query=query, budget="mid")
        finally:
            client.close()
        hits: dict[str, MemoryHit] = {}
        for result in response.results or []:
            found = (result.metadata or {}).get("incident_id") or result.document_id
            if not found or not INCIDENT_ID.fullmatch(found):
                match = INCIDENT_ID.search(result.text or "")
                found = match.group(0) if match else None
            if found and found not in hits:
                hits[found] = MemoryHit(found, result.text or "", self.name)
        return list(hits.values())[:limit]

    def reflect(self) -> str | None:
        hits = self.recall(EXPERIENCE_QUERY)
        if not hits:
            return None
        context = "Recalled attack experiences:\n" + "\n".join(
            hit.text[:MAX_REFLECT_MEMORY_CHARS] for hit in hits[:MAX_REFLECT_MEMORIES])
        client = self._client(timeout=self.settings.hindsight_reflect_timeout, attempts=1)
        try:
            return client.reflect(bank_id=self.bank, query=REFLECT_QUERY, budget="low", context=context).text or None
        finally:
            client.close()


class Memory:
    """Writes to both, reads from Hindsight first, and reports who actually answered."""

    RECONNECT_SECONDS = 30.0

    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.local = LocalMemory(store, settings.hindsight_bank)
        self.primary: HindsightMemory | None = None
        self.problem = ""
        self._next_attempt = 0.0
        self._lock = threading.Lock()
        self._connect()

    def _connect(self) -> None:
        """Hindsight can be slow to boot or restart, so keep trying instead of deciding once."""
        if self.primary or self.settings.memory_backend not in ("auto", "hindsight"):
            return
        with self._lock:
            if self.primary or time.time() < self._next_attempt:
                return
            self._next_attempt = time.time() + self.RECONNECT_SECONDS
            try:
                self.primary = HindsightMemory(self.settings)
                self.problem = ""
                log.info("Connected to Hindsight at %s", self.settings.hindsight_url)
            except Exception as exc:
                self.problem = f"{type(exc).__name__}: {exc}"[:200]
                level = log.warning if self.settings.memory_backend == "hindsight" else log.info
                level("Hindsight unavailable, using the local fallback for now: %s", self.problem)

    @property
    def off(self) -> bool:
        return self.settings.memory_backend == "off"

    @property
    def backend(self) -> str:
        if self.off:
            return "off"
        self._connect()
        return self.primary.name if self.primary else self.local.name

    def retain(self, incident: Incident, fix: Fix | None) -> None:
        if self.off:
            return
        self._connect()
        self.local.retain(incident, fix)
        if self.primary:
            self.primary.retain(incident, fix)  # Raises so the pipeline can retry later.

    def recall(self, query: str) -> list[MemoryHit]:
        if self.off:
            return []
        self._connect()
        if self.primary:
            try:
                hits = self.primary.recall(query)
                if hits:
                    return hits
            except Exception as exc:
                log.warning("Hindsight recall failed; using local fallback: %s", exc)
        # Also covers attacks remembered while Hindsight was still starting.
        return self.local.recall(query)

    def reset(self) -> None:
        self._connect()
        if self.primary:
            self.primary.reset()

    def reflect(self) -> tuple[str | None, str]:
        if self.off:
            return None, "off"
        self._connect()
        if self.primary:
            try:
                return self.primary.reflect(), self.primary.name
            except Exception as exc:
                log.warning("Hindsight reflect failed; using local fallback: %s", exc)
        return self.local.reflect(), self.local.name
