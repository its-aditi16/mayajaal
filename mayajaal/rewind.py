"""Rewinds recent activity to find everything one attacker touched, including real pages.

Records link only on strong evidence: the same credential or session, a stolen token back to
whoever it was served to, or the same IP AND fingerprint together. IP alone never links two
requests (offices share IPs) and neither does fingerprint alone (browsers share them), so
innocent users are not swept into an incident."""
from __future__ import annotations

from .models import Activity


def record_keys(a: Activity) -> set[str]:
    keys = {f"pair:{a.ip_hash}:{a.fingerprint}"}
    if a.token_hash:
        keys.add(f"token:{a.token_hash}")
    if a.session_hash:
        keys.add(f"session:{a.session_hash}")
    keys.update(f"token:{h}" for h in a.served_hashes)
    return keys


def correlate(records: list[Activity], seed: Activity) -> list[Activity]:
    """Grow outwards from the seed until no new record shares a key with the actor."""
    keyed = [(r, record_keys(r)) for r in records]
    known = record_keys(seed)
    members: dict[int, Activity] = {seed.id: seed} if seed.id is not None else {}
    changed = True
    while changed:
        changed = False
        for record, keys in keyed:
            if record.id not in members and keys & known:
                members[record.id] = record
                known |= keys
                changed = True
    return sorted(members.values(), key=lambda r: (r.ts, r.id or 0))


def actor_keys(records: list[Activity]) -> list[str]:
    return sorted(set().union(*(record_keys(r) for r in records))) if records else []


def blast_radius(records: list[Activity]) -> dict:
    pages = [r for r in records if r.sensitivity != "asset"]
    reached = [r for r in pages if 200 <= r.status < 300]
    data = [r for r in reached if r.sensitivity in ("data", "user")]
    return {
        "requests": len(records),
        "first_seen": records[0].ts if records else None,
        "last_seen": records[-1].ts if records else None,
        "duration_seconds": round(records[-1].ts - records[0].ts, 2) if records else 0,
        "ips_masked": sorted({r.ip_masked for r in records}),
        "traps": sorted({r.trap_id for r in records if r.trap_id}),
        "real_pages": sorted({r.route for r in reached if not r.trap_id}),
        "data_routes": sorted({r.route for r in data if not r.trap_id}),
        "data_reads": len([r for r in data if not r.trap_id]),
        "stolen_token_uses": len([r for r in records if r.honeytoken]),
        "denied": len([r for r in pages if r.status in (401, 403)]),
        "not_found": len([r for r in pages if r.status == 404]),
    }
