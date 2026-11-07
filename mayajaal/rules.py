"""Rule evaluation and static checks. Deterministic: this code decides, not the AI."""
from __future__ import annotations

import re

from .models import NESTED_QUANTIFIER, Condition, Rule

MAX_INPUT = 2048


def _matches(cond: Condition, attrs: dict[str, str]) -> bool:
    actual = (attrs.get(cond.field) or "")[:MAX_INPUT]
    if not actual:
        return False
    if cond.op == "eq":
        return actual == cond.value
    if cond.op == "prefix":
        return actual.startswith(cond.value)
    if cond.op == "contains":
        return cond.value in actual
    try:
        return re.search(cond.value, actual) is not None
    except re.error:
        return False


def rule_matches(rule: Rule, attrs: dict[str, str]) -> bool:
    return all(_matches(c, attrs) for c in rule.conditions)


def lint(rule: Rule) -> list[str]:
    """Reject rules that are unsafe whatever the traffic looks like."""
    problems: list[str] = []
    for cond in rule.conditions:
        if cond.op == "regex":
            try:
                re.compile(cond.value)
            except re.error as exc:
                problems.append(f"invalid regex {cond.value!r}: {exc}")
                continue
            if NESTED_QUANTIFIER.search(cond.value):
                problems.append(f"regex could backtrack catastrophically: {cond.value!r}")
            if re.search(cond.value, "") is not None:
                problems.append(f"regex matches everything: {cond.value!r}")
        if cond.field == "path" and cond.op in ("prefix", "contains") and cond.value in ("/", ".", "/api", "/api/"):
            problems.append(f"path condition is far too broad: {cond.op} {cond.value!r}")
    if all(c.field == "method" for c in rule.conditions):
        problems.append("a rule cannot match on HTTP method alone")
    return problems
