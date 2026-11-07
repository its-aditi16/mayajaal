"""Labelling attackers and working out what they touched."""
from __future__ import annotations

from mayajaal.detect import classify, signature, similarity
from mayajaal.models import Activity
from mayajaal.rewind import blast_radius, correlate


def rec(i: int, ts: float, path: str = "/", **kwargs) -> Activity:
    base = dict(id=i, ts=ts, path=path, route=path, status=200, ip_hash="ip1", fingerprint="fp1")
    return Activity(**{**base, **kwargs})


def ai_records() -> list[Activity]:
    paths = ["/robots.txt", "/.env", "/internal/admin-console", "/backup", "/api/vault/keys"]
    records = [rec(i, 100 + i * 0.1, p, user_agent="python-httpx/0.28", trap_id="env_file" if p == "/.env" else None,
                   sensitivity="trap" if p == "/.env" else "public", status=404 if p == "/backup" else 200)
               for i, p in enumerate(paths)]
    records.append(rec(9, 103, "/api/customers/export", user_agent="python-httpx/0.28", sensitivity="data",
                       trap_id="admin_console"))
    return records


def human_records() -> list[Activity]:
    browser = dict(user_agent="Mozilla/5.0 Safari/604.1", headers={"accept-language": "en"})
    records = []
    for i, ts in enumerate((100, 112, 125, 141)):
        records.append(rec(i * 3, ts, ["/", "/products", "/", "/internal/admin-console"][i],
                           trap_id="admin_console" if i == 3 else None, **browser))
        records.append(rec(i * 3 + 1, ts + 0.1, "/static/app.css", sensitivity="asset", **browser))
    return records


def test_fast_tooling_is_labelled_ai_with_reasons():
    result = classify(ai_records())
    assert result.label == "ai_agent" and result.score > 0.9
    assert any("second apart" in r for r in result.reasons)


def test_reading_pace_with_assets_is_labelled_human():
    assert classify(human_records()).label == "human"


def test_browser_disguise_does_not_hide_machine_speed():
    disguised = [r.model_copy(update={"user_agent": "Mozilla/5.0 Chrome/131", "headers": {"accept-language": "en"}})
                 for r in ai_records()]
    assert classify(disguised).label == "ai_agent"


def test_too_little_evidence_is_uncertain_not_a_guess():
    assert classify(ai_records()[:2]).label == "uncertain"


def test_signature_ignores_identity_and_collapses_repeats():
    a = ai_records()
    b = [r.model_copy(update={"ip_hash": "ip9", "fingerprint": "fp9", "user_agent": "other"}) for r in a]
    assert signature(a) == signature(b)
    assert similarity(signature(a), signature(b)) == 1.0
    repeated = [rec(1, 1, "/x"), rec(2, 2, "/x")]
    assert signature(repeated) == ["public:/x"]


def test_different_behaviour_scores_low():
    assert similarity(signature(ai_records()), signature(human_records())) < 0.3


def test_innocent_user_on_the_same_office_ip_is_not_swept_in():
    attacker = rec(1, 1, "/.env", trap_id="env_file")
    colleague = rec(2, 2, "/products", ip_hash="ip1", fingerprint="fp-colleague")
    assert correlate([attacker, colleague], attacker) == [attacker]


def test_other_user_with_the_same_browser_is_not_swept_in():
    attacker = rec(1, 1, "/.env", trap_id="env_file")
    lookalike = rec(2, 2, "/products", ip_hash="ip-elsewhere", fingerprint="fp1")
    assert correlate([attacker, lookalike], attacker) == [attacker]


def test_stolen_token_links_a_new_ip_and_device_back_to_the_theft():
    theft = rec(1, 1, "/api/customers/export", served_hashes=["dye1"], sensitivity="data")
    other = rec(2, 2, "/products", ip_hash="ip7", fingerprint="fp7")
    use = rec(3, 3, "/api/profile", ip_hash="ip2", fingerprint="fp2", token_hash="dye1", honeytoken="x", trap_id="canary_record")
    assert [r.id for r in correlate([theft, other, use], use)] == [1, 3]


def test_blast_radius_separates_reached_from_denied():
    records = [
        rec(1, 1, "/api/customers/export", sensitivity="data"),
        rec(2, 2, "/api/orders", sensitivity="user", status=401),
        rec(3, 3, "/.env", sensitivity="trap", trap_id="env_file"),
    ]
    radius = blast_radius(records)
    assert radius["data_routes"] == ["/api/customers/export"]
    assert radius["denied"] == 1 and radius["traps"] == ["env_file"]
