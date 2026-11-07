"""The loop: trap fires -> detect -> learn -> prove -> shadow -> human approves -> block -> remember.
AI and memory steps are optional at every point. If they fail, traps and blocks carry on."""
from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable
from urllib.parse import parse_qsl

from fastapi import FastAPI

from .ai import DefenderAI, strip_links
from .alerts import Alerts, sign_approval
from .config import Settings
from .detect import classify, signature, similarity
from .memory import Memory, recall_query
from .models import Activity, Condition, Fix, Incident, Recollection, Rule
from .prove import GoldenRequest, Verifier, known_params
from .rewind import actor_keys, blast_radius, correlate
from .safety import PromptScreen
from .store import Store
from .traps import registry

log = logging.getLogger("mayajaal.pipeline")

OPEN_STATES = ("detected", "shadow")
RECOGNISED_AT = 0.6
RETAIN_RETRY_SECONDS = 30.0
RETENTION_CHECK_SECONDS = 3600.0
MAX_EVIDENCE_REQUESTS = 60


class ApprovalError(Exception):
    pass


def _rule_id() -> str:
    return f"R-{uuid.uuid4().hex[:8]}"


class Pipeline:
    def __init__(self, settings: Settings, store: Store, memory: Memory, ai: DefenderAI, screen: PromptScreen,
                 alerts: Alerts, app_factory: Callable[[Settings], FastAPI], golden: list[GoldenRequest]):
        self.settings, self.store, self.memory, self.ai = settings, store, memory, ai
        self.screen, self.alerts, self.golden = screen, alerts, golden
        self.verifier = Verifier(settings, store, app_factory, golden)
        self._lock = threading.RLock()
        self._background = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mayajaal-memory")
        self._retaining: dict[str, Future] = {}
        self._retain_after: dict[str, float] = {}
        self._reflecting: Future | None = None
        self._retained_since_reflect = 0
        self._last_retention = 0.0

    def status(self) -> dict[str, str]:
        return {
            "memory": self.memory.backend, "memory_problem": self.memory.problem, "defender_ai": self.ai.label,
            "prompt_screen": self.screen.backend, "teams": self.alerts.teams_backend,
            "sentinel": self.alerts.sentinel_backend,
        }

    # DETECT --------------------------------------------------------------------
    def _rewind(self, seed: Activity) -> list[Activity]:
        since = seed.ts - self.settings.rewind_window_seconds
        return correlate(self.store.activity_since(since), seed)

    def _absorb(self, incident: Incident, records: list[Activity]) -> None:
        incident.activity_ids = [r.id for r in records]
        incident.actor_keys = actor_keys(records)
        incident.fingerprints = sorted({r.fingerprint for r in records})
        incident.ip_hashes = sorted({r.ip_hash for r in records})
        incident.token_hashes = sorted({r.token_hash for r in records if r.token_hash})
        incident.session_hashes = sorted({r.session_hash for r in records if r.session_hash})
        incident.traps_fired = sorted({r.trap_id for r in records if r.trap_id})
        incident.signature = signature(records)
        incident.classification = classify(records)
        incident.blast_radius = blast_radius(records)

    def handle_event(self, event: dict) -> Incident | None:
        seed = self.store.get_activity(int(event["activity_id"]))
        if seed is None:
            return None
        records = self._rewind(seed)
        keys = set(actor_keys(records))
        with self._lock:
            for existing in reversed(self.store.incidents()):
                if keys & set(existing.actor_keys):
                    if existing.status == "blocked":
                        existing.hits_after_block += 1
                        existing.updated = time.time()
                    elif existing.status in OPEN_STATES or existing.status == "awaiting_approval":
                        known_traps = set(existing.traps_fired)
                        self._absorb(existing, records)
                        if seed.trap_id not in known_traps:
                            existing.log("detect", f"Took another bait: {seed.trap_id}")
                    self.store.save_incident(existing)
                    return existing

            incident = Incident(id=f"INC-{uuid.uuid4().hex[:8]}", first_activity_id=seed.id)
            self._absorb(incident, records)
            trap = registry.BY_ID.get(seed.trap_id)
            incident.log("detect", f"Trap fired: {trap.title if trap else seed.trap_id}")
            self.store.save_incident(incident)
            self.store.audit("system", "incident_opened", incident.id, seed.trap_id or "")
        self.alerts.send_event("TrapFired", incident)
        return incident

    # LEARN ---------------------------------------------------------------------
    def _screened_evidence(self, incident: Incident, records: list[Activity]) -> dict:
        """Attacker-written text passes through the screen before any AI can read it."""
        sample = records[:MAX_EVIDENCE_REQUESTS]
        fields = ("path", "query", "user_agent", "body", "referer")

        def raw(record: Activity, name: str) -> str:
            return record.headers.get("referer", "") if name == "referer" else getattr(record, name)

        texts = sorted({raw(r, f) for r in sample for f in fields if raw(r, f)})
        result = self.screen.screen(texts)
        clean = dict(zip(texts, result.texts))
        incident.screened_items = result.flagged
        incident.shield_backend = result.backend
        if result.flagged:
            incident.log("safety", f"Removed {result.flagged} prompt injection attempt(s) from the evidence "
                                   f"before the AI saw it ({result.backend})")
        base = records[0].ts if records else 0
        steps = []
        for r in sample:
            step = {"t": round(r.ts - base, 2), "method": r.method, "path": clean.get(r.path, ""),
                    "status": r.status, "user_agent": clean.get(r.user_agent, "")}
            for name in ("query", "body"):
                if getattr(r, name):
                    step[name] = clean.get(getattr(r, name), "")
            if r.headers.get("referer"):
                step["referer"] = clean.get(r.headers["referer"], "")
            if r.trap_id:
                step["bait_taken"] = r.trap_id
            steps.append(step)
        return {
            "attacker_class": incident.classification.label,
            "summary": incident.blast_radius,
            "fingerprints": incident.fingerprints,
            "token_hashes": incident.token_hashes,
            "session_hashes": incident.session_hashes,
            "normal_traffic_must_keep_working": sorted({
                f"{g.method} {g.path}" + (f"?{g.query}" if g.query else "") for g in self.golden}),
            "requests": steps,
        }

    def _template_explanation(self, incident: Incident) -> str:
        r = incident.blast_radius
        c = incident.classification
        who = {"ai_agent": "An autonomous, probably AI, attacker", "human": "A person",
               "uncertain": "An unclassified actor"}[c.label]
        data = ", ".join(r.get("data_routes", []))
        parts = [
            f"{who} made {r.get('requests', 0)} requests over {r.get('duration_seconds', 0)}s "
            f"from {len(r.get('ips_masked', []))} address(es).",
            f"Bait taken: {'; '.join(registry.BY_ID[t].title if t in registry.BY_ID else t for t in incident.traps_fired) or 'none'}.",
            f"Real data reached: {data}." if data else "It reached no real data.",
        ]
        if r.get("stolen_token_uses"):
            parts.append(f"It tried to use stolen bait credentials {r['stolen_token_uses']} time(s).")
        return " ".join(parts)

    def _recall(self, incident: Incident) -> Recollection | None:
        """Memory proposes, code confirms: a candidate only counts if the behaviour really matches."""
        try:
            hits = self.memory.recall(recall_query(incident.signature, incident.traps_fired))
        except Exception:
            log.exception("Recall failed")
            return None
        best: Recollection | None = None
        for hit in hits:
            past = self.store.get_incident(hit.incident_id)
            if past is None or past.id == incident.id:
                continue
            score = similarity(incident.signature, past.signature)
            shared = []
            if set(incident.fingerprints) & set(past.fingerprints):
                shared.append("fingerprint")
            if set(incident.token_hashes) & set(past.token_hashes):
                shared.append("credential")
            if score < RECOGNISED_AT and not shared:
                continue
            if best is None or score > best.similarity:
                best = Recollection(incident_id=past.id, similarity=round(score, 3), identity_match=shared,
                                    fix_id=past.fix_id, backend=hit.backend, memory_text=hit.text[:600])
        return best

    # Rule drafting -------------------------------------------------------------
    def _identity_rules(self, incident: Incident, records: list[Activity]) -> list[Rule]:
        rules: list[Rule] = []
        for value in incident.token_hashes:
            rules.append(Rule(id=_rule_id(), kind="credential", title="Revoke stolen access token",
                              conditions=[Condition(field="token_hash", op="eq", value=value)]))
        for value in incident.session_hashes:
            rules.append(Rule(id=_rule_id(), kind="credential", title="Revoke hijacked session",
                              conditions=[Condition(field="session_hash", op="eq", value=value)]))
        # A fingerprint someone innocent also has would lock them out too, so it is left out.
        others = self.verifier._other_traffic({r.id for r in records})
        shared = {r.fingerprint for r in others}
        for value in incident.fingerprints:
            if value not in shared:
                rules.append(Rule(id=_rule_id(), kind="fingerprint", title="Block device fingerprint",
                                  conditions=[Condition(field="fingerprint", op="eq", value=value)]))
        return rules

    def _technique_rules(self, records: list[Activity]) -> list[Rule]:
        """Flag request parameters on real data pages that normal traffic never uses."""
        known = known_params(self.golden)
        attacker_ids = {r.id for r in records}
        for other in self.verifier._other_traffic(attacker_ids):
            known.setdefault(other.path, set()).update(k for k, _ in parse_qsl(other.query))
        rules: list[Rule] = []
        seen: set[tuple[str, str]] = set()
        for record in records:
            if record.sensitivity not in ("data", "user") or record.trap_id or not 200 <= record.status < 300:
                continue
            for part in record.query.split("&"):
                name = part.split("=", 1)[0]
                if not name or name in known.get(record.path, set()) or (record.path, part) in seen:
                    continue
                seen.add((record.path, part))
                rules.append(Rule(
                    id=_rule_id(), kind="technique", title=f"Block unusual parameter {name} on {record.path}",
                    conditions=[Condition(field="path", op="eq", value=record.path),
                                Condition(field="query", op="contains", value=part)]))
        return rules

    def _template_fix(self, incident: Incident, records: list[Activity]) -> Fix:
        return Fix(id=f"FIX-{uuid.uuid4().hex[:8]}", incident_id=incident.id, source="template",
                   rationale="Blocks this attacker's stolen access, device fingerprint and technique.",
                   rules=self._identity_rules(incident, records) + self._technique_rules(records))

    def _memory_fix(self, incident: Incident, records: list[Activity], recollection: Recollection) -> Fix | None:
        past = self.store.get_fix(recollection.fix_id) if recollection.fix_id else None
        if past is None or past.status != "active":
            return None
        techniques = [r.model_copy(update={"id": _rule_id()}) for r in past.rules if r.kind == "technique"]
        return Fix(id=f"FIX-{uuid.uuid4().hex[:8]}", incident_id=incident.id, source="memory", reused_from=past.id,
                   rationale=f"Applies the technique that stopped {past.incident_id} to this attacker's new identity.",
                   rules=self._identity_rules(incident, records) + techniques)

    def _prove(self, incident: Incident, fix: Fix, records: list[Activity]) -> bool:
        report = self.verifier.verify(fix, records)
        fix.report = report
        incident.log("prove", f"Tested on: {report.backend} ({report.duration_seconds}s)")
        for check in report.checks:
            incident.log("prove", f"{'PASS' if check.passed else 'FAIL'} {check.name}: {check.detail}")
        fix.status = "draft" if report.passed else "rejected"
        self.store.save_fix(fix)
        return report.passed

    def _learn_and_prove(self, incident: Incident) -> None:
        started = time.time()
        seed = self.store.get_activity(incident.first_activity_id)
        if seed is None:
            incident.status = "error"
            incident.log("learn", "The trap's activity record has already been deleted")
            return
        records = self._rewind(seed)
        self._absorb(incident, records)
        c = incident.classification
        incident.log("detect", f"Labelled {c.label} (score {c.score}): " + "; ".join(c.reasons[:3]))
        r = incident.blast_radius
        incident.log("learn", f"Rewound {r['requests']} requests. Real data reached: "
                              f"{', '.join(r['data_routes']) or 'none'}. Stolen token uses: {r['stolen_token_uses']}.")

        incident.recollection = self._recall(incident)
        rec = incident.recollection
        if rec:
            why = f"{rec.similarity:.0%} behaviour match" + (
                f", same {' and '.join(rec.identity_match)}" if rec.identity_match else "")
            incident.log("memory", f"Recognised: resembles {rec.incident_id} ({why}), recalled via {rec.backend}")
        else:
            incident.log("memory", f"No similar past attacker in memory ({self.memory.backend})")

        fix = self._memory_fix(incident, records, rec) if rec else None
        evidence: dict | None = None
        if fix is not None:
            incident.explanation = (self._template_explanation(incident)
                                    + f" Memory: this matches {rec.incident_id}, so its proven fix was reused.")
            incident.explanation_source = "template + memory"
            incident.log("memory", f"Reusing the proven fix from {fix.reused_from}, no AI drafting needed")
        else:
            evidence = self._screened_evidence(incident, records)
            incident.ai_calls += 2 if self.ai.available else 0
            notes = self.ai.explain(evidence) if self.ai.available else None
            incident.explanation_source = f"verified facts + {self.ai.label}" if notes else "template"
            incident.explanation = self._template_explanation(incident)
            if notes:  # The model can be wrong, so its reading never replaces the recorded facts.
                incident.explanation += f" AI analyst notes, unverified: {notes}"
            incident.log("learn", f"Explanation written by {incident.explanation_source}")
            drafted = self.ai.draft_rules(evidence) if self.ai.available else None
            if drafted:
                rationale, rules = drafted
                fix = Fix(id=f"FIX-{uuid.uuid4().hex[:8]}", incident_id=incident.id, source="ai",
                          rationale=rationale, rules=rules)
                incident.log("prove", f"{self.ai.label} drafted {len(rules)} rule(s); testing them")
            else:
                fix = self._template_fix(incident, records)
                incident.log("prove", f"Using the built-in rule template ({len(fix.rules)} rules); testing them")

        proved = self._prove(incident, fix, records)
        if not proved and fix.source != "template":
            incident.log("prove", f"The {fix.source} draft failed its checks and was thrown away; trying the template")
            fix = self._template_fix(incident, records)
            proved = self._prove(incident, fix, records)
        incident.fix_id = fix.id
        if not proved:
            incident.status = "needs_human"
            incident.log("prove", "No candidate passed. Traps stay live; a person needs to look at this.")
            self.alerts.send_event("NeedsHuman", incident)
            return

        incident.time_to_fix_seconds = round(time.time() - incident.created, 2)
        incident.analysis_seconds = round(time.time() - started, 2)
        fix.status = "shadow"
        fix.shadow_started = time.time()
        proven = fix.source == "memory"
        fix.shadow_seconds = self.settings.shadow_seconds_proven if proven else self.settings.shadow_seconds
        self.store.save_fix(fix)
        incident.status = "shadow"
        incident.log("shadow", f"Watching live traffic for {fix.shadow_seconds:g}s without blocking anything")

    # SHADOW and APPROVAL -------------------------------------------------------
    def _count_shadow(self, incident: Incident, fix: Fix) -> None:
        hit_ids = self.store.shadow_hit_activity_ids(fix.id)
        seed = self.store.get_activity(incident.first_activity_id)
        attacker = {r.id for r in self._rewind(seed)} if seed else set(incident.activity_ids)
        fix.shadow_hits_attacker = sum(1 for i in hit_ids if i in attacker)
        fix.shadow_hits_other = sum(1 for i in hit_ids if i not in attacker)

    def _finish_shadow(self, incident: Incident) -> None:
        fix = self.store.get_fix(incident.fix_id)
        if fix is None or time.time() - (fix.shadow_started or 0) < fix.shadow_seconds:
            return
        with self._lock:
            seed = self.store.get_activity(incident.first_activity_id)
            if seed:
                self._absorb(incident, self._rewind(seed))
            self._count_shadow(incident, fix)
            if fix.shadow_hits_other:
                fix.status = "rejected"
                incident.status = "needs_human"
                incident.log("shadow", f"FAIL: would have blocked {fix.shadow_hits_other} request(s) from other "
                                       "people. Fix withdrawn.")
                self.store.save_fix(fix)
                self.store.save_incident(incident)
                self.alerts.send_event("NeedsHuman", incident)
                return
            fix.status = "awaiting_approval"
            incident.status = "awaiting_approval"
            incident.log("shadow", f"PASS: {fix.shadow_hits_attacker} attacker request(s) matched, none from anyone else")
            incident.log("approve", f"Approval requested via {self.alerts.teams_backend}")
            self.store.save_fix(fix)
            # Saved before the alert goes out, so an instant approval can never be overwritten.
            self.store.save_incident(incident)
        self.alerts.request_approval(incident, fix, self.approval_url(fix.id, "approve"),
                                     self.approval_url(fix.id, "decline"))

    def approval_url(self, fix_id: str, action: str) -> str:
        token = sign_approval(self.settings.secret, fix_id, action)
        return f"{self.settings.public_base_url.rstrip('/')}/approve/{token}"

    def _pending(self, fix_id: str) -> tuple[Fix, Incident]:
        fix = self.store.get_fix(fix_id)
        if fix is None or fix.status != "awaiting_approval":
            raise ApprovalError("This fix is not waiting for approval")
        incident = self.store.get_incident(fix.incident_id)
        if incident is None:
            raise ApprovalError("Incident not found")
        return fix, incident

    def approve(self, fix_id: str, actor: str) -> Incident:
        """Only a person, through a signed link or the admin API, reaches this."""
        with self._lock:
            fix, incident = self._pending(fix_id)
            self._count_shadow(incident, fix)  # Traffic may have changed while it waited.
            if fix.shadow_hits_other:
                fix.status = "rejected"
                incident.status = "needs_human"
                incident.log("approve", f"Refused: the fix now matches {fix.shadow_hits_other} request(s) from others")
                self.store.save_fix(fix)
                self.store.save_incident(incident)
                raise ApprovalError("Fix matched other people's traffic while waiting, so it was withdrawn")
            fix.status = "active"
            fix.approved_by = actor
            fix.approved_at = time.time()
            incident.status = "blocked"
            incident.log("block", f"Approved by {actor}. Attacker locked out of the whole app.")
            self.store.save_fix(fix)
            self.store.save_incident(incident)
            self.store.audit(actor, "fix_approved", fix.id, incident.id)
        self.alerts.send_event("Blocked", incident)
        return incident

    def decline(self, fix_id: str, actor: str) -> Incident:
        with self._lock:
            fix, incident = self._pending(fix_id)
            fix.status = "declined"
            incident.status = "declined"
            incident.log("approve", f"Declined by {actor}. Nothing was blocked; traps stay live.")
            self.store.save_fix(fix)
            self.store.save_incident(incident)
            self.store.audit(actor, "fix_declined", fix.id, incident.id)
        return incident

    def revoke(self, fix_id: str, actor: str) -> None:
        with self._lock:
            fix = self.store.get_fix(fix_id)
            if fix is None or fix.status != "active":
                raise ApprovalError("Only an active fix can be revoked")
            fix.status = "revoked"
            self.store.save_fix(fix)
            self.store.audit(actor, "fix_revoked", fix.id, fix.incident_id)

    # REMEMBER ------------------------------------------------------------------
    def _retain_job(self, incident: Incident, fix: Fix | None) -> None:
        self.memory.retain(incident, fix)

    def _service_memory(self) -> None:
        now = time.time()
        for incident_id, future in list(self._retaining.items()):
            if not future.done():
                continue
            del self._retaining[incident_id]
            with self._lock:
                incident = self.store.get_incident(incident_id)
                if incident is None:
                    continue
                error = future.exception()
                if error:
                    self._retain_after[incident_id] = now + RETAIN_RETRY_SECONDS
                    log.warning("Retain failed for %s; will retry: %s", incident_id, error)
                    continue
                incident.retained = True
                if self.memory.backend != "off":
                    incident.log("memory", f"Experience retained in {self.memory.backend}")
                self.store.save_incident(incident)
                self._retained_since_reflect += 1

        for incident in self.store.incidents(("blocked", "declined", "needs_human")):
            if incident.retained or incident.id in self._retaining or self._retain_after.get(incident.id, 0) > now:
                continue
            fix = self.store.get_fix(incident.fix_id) if incident.fix_id else None
            self._retaining[incident.id] = self._background.submit(self._retain_job, incident, fix)

        if self._reflecting is not None and self._reflecting.done():
            self._reflecting = None
        if self._retained_since_reflect >= self.settings.reflect_every and self._reflecting is None:
            self._retained_since_reflect = 0
            self.reflect_now()

    def reflect_now(self) -> Future:
        def job() -> None:
            text, source = self.memory.reflect()
            if text:
                self.store.add_observation(source, strip_links(text))

        self._reflecting = self._background.submit(job)
        return self._reflecting

    # Loop ----------------------------------------------------------------------
    def tick(self) -> None:
        for incident in self.store.incidents(OPEN_STATES):
            try:
                if incident.status == "detected":
                    if time.time() - incident.created >= self.settings.settle_seconds:
                        self._learn_and_prove(incident)
                        with self._lock:
                            self.store.save_incident(incident)
                elif incident.status == "shadow":
                    self._finish_shadow(incident)
            except Exception as exc:
                log.exception("Pipeline step failed for %s", incident.id)
                incident.status = "error"
                incident.log("error", f"{type(exc).__name__}: {exc}"[:300])
                self.store.save_incident(incident)
        self._service_memory()
        if time.time() - self._last_retention > RETENTION_CHECK_SECONDS:
            self._last_retention = time.time()
            removed = self.store.purge_older_than(self.settings.retention_days)
            if removed:
                self.store.audit("system", "retention_purge", "activity", f"{removed} rows")

    def run(self, bus, stop: threading.Event, interval: float = 0.25) -> None:
        while not stop.is_set():
            try:
                for event in bus.consume():
                    self.handle_event(event)
                self.tick()
            except Exception:
                log.exception("Pipeline loop error")
            stop.wait(interval)
        self._background.shutdown(wait=True)
