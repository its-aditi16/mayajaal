"""No rule gets through because the AI said so. Each test is a bad rule that must be refused."""
from __future__ import annotations

from conftest import AGENT, CHROME, EXPORT, client_for, run_attack

from mayajaal.demo.app import create_app
from mayajaal.demo.golden import GOLDEN
from mayajaal.models import Condition, Fix, Rule
from mayajaal.prove import Verifier
from mayajaal.rules import lint, rule_matches


def rule(kind="technique", **cond) -> Rule:
    return Rule(id="R-test", kind=kind, title="test", conditions=[Condition(**cond)])


def verifier(settings, store) -> Verifier:
    return Verifier(settings, store, create_app, GOLDEN)


def check(report, name: str):
    return next(c for c in report.checks if c.name == name)


def attack_records(app, store, **kwargs):
    run_attack(app, **kwargs)
    return store.activity_since(0)


def fix_of(*rules) -> Fix:
    return Fix(id="FIX-test", incident_id="INC-test", rules=list(rules))


def test_narrow_fix_passes(app, settings, store):
    records = attack_records(app, store)
    report = verifier(settings, store).verify(
        fix_of(rule("fingerprint", field="fingerprint", op="eq", value=records[0].fingerprint)), records)
    assert report.passed, report.checks
    assert report.backend == "in-process copy"


def test_rule_that_misses_the_attack_is_refused(app, settings, store):
    records = attack_records(app, store)
    report = verifier(settings, store).verify(fix_of(rule(field="path", op="eq", value="/nothing-here")), records)
    assert not report.passed and not check(report, "Stops the attack").passed


def test_blocking_all_python_clients_is_refused(app, settings, store):
    """The AI's tempting shortcut. A legitimate inventory script uses the same library."""
    records = attack_records(app, store)
    report = verifier(settings, store).verify(fix_of(rule(field="user_agent", op="contains", value="python")), records)
    assert not report.passed
    # Refused twice over: it would hide the bait, and it would break a legitimate script.
    assert "hide the bait" in check(report, "Rule is safe to run").detail
    with_trap_open = fix_of(Rule(id="R", kind="technique", title="t", conditions=[
        Condition(field="user_agent", op="contains", value="python"),
        Condition(field="path", op="eq", value="/products")]))
    report = verifier(settings, store).verify(with_trap_open, records)
    assert "sync" in check(report, "Normal users still get through").detail


def test_blocking_a_whole_data_page_is_refused(app, settings, store):
    records = attack_records(app, store)
    report = verifier(settings, store).verify(
        fix_of(rule(field="path", op="prefix", value="/api/customers")), records)
    assert not report.passed
    # It also covers the fake customer record, so it is refused before even reaching the replay.
    assert "hide the bait" in check(report, "Rule is safe to run").detail
    exports = fix_of(rule(field="path", op="eq", value="/api/customers/export"))
    assert not check(verifier(settings, store).verify(exports, records), "Normal users still get through").passed


def test_rule_that_would_hit_recent_real_traffic_is_refused(app, settings, store):
    client_for(app, CHROME, "198.51.100.77").get("/products?campaign=diwali")
    records = attack_records(app, store)
    attack = [r for r in records if r.user_agent == AGENT["user-agent"]]
    fix = fix_of(rule("fingerprint", field="fingerprint", op="eq", value=attack[0].fingerprint),
                 rule(field="query", op="contains", value="campaign=diwali"))
    report = verifier(settings, store).verify(fix, attack)
    assert not report.passed and not check(report, "Recent real traffic unaffected").passed


def test_empty_fix_is_refused(app, settings, store):
    records = attack_records(app, store)
    assert not verifier(settings, store).verify(fix_of(), records).passed


def test_catastrophic_regex_is_refused_before_it_runs(app, settings, store):
    records = attack_records(app, store)
    report = verifier(settings, store).verify(fix_of(rule(field="path", op="regex", value="(a+)+$")), records)
    assert not report.passed and report.backend == "static"


def test_lint_catches_broad_and_broken_rules():
    assert lint(rule(field="path", op="prefix", value="/"))
    assert lint(rule(field="path", op="regex", value=".*"))
    assert lint(rule(field="path", op="regex", value="(unclosed"))
    assert lint(rule(field="method", op="eq", value="GET"))
    assert not lint(rule(field="path", op="eq", value="/api/customers/export"))


def test_rule_schema_has_no_ip_field():
    """IPs rotate and offices share them, so a rule can never be written against one."""
    import pydantic
    import pytest

    with pytest.raises(pydantic.ValidationError):
        Condition(field="ip", op="eq", value="1.2.3.4")


def test_rule_matching():
    attrs = {"path": EXPORT.split("?")[0], "query": "limit=1&include=api_key", "method": "GET"}
    both = Rule(id="r", kind="technique", title="t", conditions=[
        Condition(field="path", op="eq", value="/api/customers/export"),
        Condition(field="query", op="contains", value="include=api_key")])
    assert rule_matches(both, attrs)
    assert not rule_matches(both, {**attrs, "query": "limit=50"})
    assert not rule_matches(rule(field="token_hash", op="eq", value="x"), attrs)  # Missing field never matches.


def test_verification_never_touches_live_data(app, settings, store):
    records = attack_records(app, store)
    before = len(store.activity_since(0))
    verifier(settings, store).verify(
        fix_of(rule("fingerprint", field="fingerprint", op="eq", value=records[0].fingerprint)), records)
    assert len(store.activity_since(0)) == before


def test_rule_that_blocks_a_trap_for_everyone_is_refused(app, settings, store):
    """Regression from a live test: approved AI rules blocked /.env for everyone, so the next
    attacker got a 403 instead of a fake key and the trap stopped working."""
    records = attack_records(app, store)
    report = verifier(settings, store).verify(fix_of(rule(field="path", op="eq", value="/.env")), records)
    assert not report.passed
    assert "hide the bait" in check(report, "Rule is safe to run").detail


def test_blocking_the_attacker_on_a_trap_page_is_still_allowed(app, settings, store):
    records = attack_records(app, store)
    attacker_on_trap = Rule(id="R-ok", kind="fingerprint", title="t", conditions=[
        Condition(field="fingerprint", op="eq", value=records[0].fingerprint),
        Condition(field="path", op="eq", value="/.env")])
    narrow = rule("fingerprint", field="fingerprint", op="eq", value=records[0].fingerprint)
    assert verifier(settings, store).verify(fix_of(narrow, attacker_on_trap), records).passed


def test_built_in_traps_are_protected_even_if_this_attacker_never_touched_them(app, settings, store):
    from mayajaal.prove import hides_bait

    assert hides_bait([rule(field="path", op="prefix", value="/internal/")], [])
