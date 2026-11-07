"""Exercises the real Hindsight server, not a stub. Needs one running on MAYAJAAL_HINDSIGHT_URL.
Run by hand (pytest does not collect it): python tests/live_hindsight.py"""
from __future__ import annotations

import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mayajaal.config import Settings  # noqa: E402
from mayajaal.memory import HindsightMemory, recall_query  # noqa: E402
from mayajaal.models import Classification, Condition, Fix, Incident, Rule  # noqa: E402

SIGNATURE = ["public:/robots.txt", "trap:env_file", "trap:admin_console", "probe:404", "trap:vault_decoy",
             "data:/api/customers/export", "trap:canary_record"]
UNRELATED = ["public:/", "public:/products", "trap:admin_console"]


def incident(signature: list[str], label: str, traps: list[str]) -> Incident:
    return Incident(id=f"INC-{uuid.uuid4().hex[:8]}", signature=signature, traps_fired=traps,
                    classification=Classification(label=label, score=0.97),
                    blast_radius={"requests": 9, "data_routes": ["/api/customers/export"]})


def main() -> int:
    settings = Settings(data_dir=tempfile.mkdtemp(), secret_key="live", hindsight_bank=f"mayajaal-live-{uuid.uuid4().hex[:6]}")
    memory = HindsightMemory(settings)
    print("connected, bank", settings.hindsight_bank)

    attacker = incident(SIGNATURE, "ai_agent", ["env_file", "admin_console", "vault_decoy", "canary_record"])
    other = incident(UNRELATED, "human", ["admin_console"])
    fix = Fix(id="FIX-live", incident_id=attacker.id, status="active", rules=[Rule(
        id="R-1", kind="technique", title="t", conditions=[Condition(field="query", op="contains", value="include=api_key")])])

    for item, item_fix in ((attacker, fix), (other, None)):
        started = time.time()
        memory.retain(item, item_fix)
        print(f"retain {item.id}: {time.time() - started:.1f}s")

    started = time.time()
    hits = memory.recall(recall_query(SIGNATURE, attacker.traps_fired))
    print(f"recall: {time.time() - started:.1f}s -> {[h.incident_id for h in hits]}")
    for hit in hits[:3]:
        print("  ", hit.text[:160])
    found = attacker.id in {h.incident_id for h in hits}
    print("attacker found by recall:", found)

    started = time.time()
    reflection = memory.reflect()
    print(f"reflect: {time.time() - started:.1f}s\n{reflection}")
    return 0 if found and reflection else 1


if __name__ == "__main__":
    raise SystemExit(main())
