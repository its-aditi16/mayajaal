"""Human or AI, from behaviour. Transparent weighted signals, no model, so it keeps
working when the AI is down and every label can explain itself.

Limit worth stating plainly: behaviour shows a machine is driving. Separating an LLM agent
from a plain script relies on softer signs (think-then-act pauses, reacting to hidden hints),
so treat `ai_agent` as "autonomous, probably AI", not as proof of which software it is."""
from __future__ import annotations

import math
import statistics

from .models import Activity, Classification

BROWSER_MARKERS = ("Mozilla/", "Chrome/", "Safari/", "Firefox/", "Edg/")
TOOL_MARKERS = ("python", "httpx", "curl", "wget", "go-http", "node-fetch", "aiohttp",
                "scrapy", "agent", "gpt", "claude", "bot")


def extract_features(records: list[Activity]) -> dict[str, float]:
    records = sorted(records, key=lambda r: r.ts)
    pages = [r for r in records if r.sensitivity != "asset"]
    gaps = [b.ts - a.ts for a, b in zip(pages, pages[1:])]
    duration = (records[-1].ts - records[0].ts) if len(records) > 1 else 0.0

    bursts = 0
    window: list[float] = []
    for r in pages:
        window = [t for t in window if r.ts - t <= 2.0] + [r.ts]
        if len(window) == 5:
            bursts += 1

    # Did it follow a path only mentioned in robots.txt within seconds?
    reaction = -1.0
    robots = next((r.ts for r in pages if r.path == "/robots.txt"), None)
    if robots is not None:
        follow = next((r.ts for r in pages if r.ts > robots and r.trap_id), None)
        if follow is not None:
            reaction = follow - robots

    ua = (records[-1].user_agent if records else "") or ""
    browser_ua = any(m in ua for m in BROWSER_MARKERS)
    tool_ua = not ua or any(m in ua.lower() for m in TOOL_MARKERS)
    has_browser_headers = any("accept-language" in r.headers for r in records)
    errors = [r for r in pages if 400 <= r.status < 500]

    return {
        "requests": float(len(records)),
        "pages": float(len(pages)),
        "duration": duration,
        "median_gap": statistics.median(gaps) if gaps else -1.0,
        "fast_ratio": (sum(g < 1.0 for g in gaps) / len(gaps)) if gaps else 0.0,
        "think_pauses": float(sum(2.0 <= g <= 30.0 for g in gaps)),
        "bursts": float(bursts),
        "assets": float(len(records) - len(pages)),
        "distinct_routes": float(len({r.route for r in pages})),
        "error_ratio": (len(errors) / len(pages)) if pages else 0.0,
        "traps": float(len({r.trap_id for r in records if r.trap_id})),
        "robots_reaction": reaction,
        "browser_ua": float(browser_ua and not tool_ua),
        "browser_headers": float(has_browser_headers),
    }


def classify(records: list[Activity]) -> Classification:
    f = extract_features(records)
    if f["pages"] < 3:
        return Classification(label="uncertain", score=0.5, features=f,
                              reasons=[f"Only {int(f['pages'])} page request(s) so far: not enough to judge"])

    score = 0.0
    reasons: list[str] = []

    def signal(weight: float, why: str) -> None:
        nonlocal score
        score += weight
        reasons.append(why)

    if f["fast_ratio"] >= 0.6:
        signal(1.4, f"{f['fast_ratio']:.0%} of requests came less than a second apart")
    elif f["fast_ratio"] <= 0.2:
        signal(-1.2, "Requests are spaced at a human reading pace")
    if f["bursts"] >= 1:
        signal(0.9, f"{int(f['bursts'])} burst(s) of 5+ requests within 2 seconds")
    if f["assets"] == 0:
        signal(0.7, "Never loaded page assets (CSS, JS), so no browser is rendering")
    elif f["assets"] >= f["pages"] * 0.3:
        signal(-1.0, "Loads page assets the way a real browser does")
    if not f["browser_headers"]:
        signal(0.5, "Missing the headers browsers normally send")
    if not f["browser_ua"]:
        signal(0.6, "User agent is a tool, not a browser")
    if 0 <= f["robots_reaction"] < 3.0:
        signal(1.0, f"Followed a robots.txt hint to a trap in {f['robots_reaction']:.1f}s")
    if f["traps"] >= 2:
        signal(0.6, f"Took {int(f['traps'])} different baits")
    if f["think_pauses"] >= 1 and f["bursts"] >= 1:
        signal(0.5, "Act-then-pause rhythm: bursts split by pauses, typical of an LLM loop")
    if f["error_ratio"] >= 0.4:
        signal(0.3, f"{f['error_ratio']:.0%} of requests failed, consistent with probing")

    # Logistic squash, biased so one weak signal alone is never enough.
    probability = 1 / (1 + math.exp(-(score - 0.5)))
    label = "ai_agent" if probability >= 0.75 else "human" if probability <= 0.35 else "uncertain"
    return Classification(label=label, score=round(probability, 3), reasons=reasons, features=f)


def signature(records: list[Activity]) -> list[str]:
    """The order of what an attacker tried. Survives new IPs, user agents and tokens."""
    out: list[str] = []
    for r in sorted(records, key=lambda r: r.ts):
        if r.sensitivity == "asset":
            continue
        if r.honeytoken:
            step = f"use:{r.trap_id}"
        elif r.trap_id:
            step = f"trap:{r.trap_id}"
        elif r.status == 404:
            step = "probe:404"
        elif r.sensitivity == "public" and not 200 <= r.status < 300:
            # A blocked or failed request's URL is attacker-written text. It must never reach
            # long-term memory, where an AI would later read it as if it were a fact.
            step = f"probe:{r.status}"
        else:
            step = f"{r.sensitivity}:{r.route}"
        if not out or out[-1] != step:
            out.append(step)
    return out


def similarity(a: list[str], b: list[str]) -> float:
    """Half what it touched, half the order it touched things in."""
    if not a or not b:
        return 0.0

    def jaccard(x: set, y: set) -> float:
        return len(x & y) / len(x | y) if x | y else 0.0

    if len(a) < 2 or len(b) < 2:
        return jaccard(set(a), set(b))
    return 0.5 * jaccard(set(a), set(b)) + 0.5 * jaccard(set(zip(a, a[1:])), set(zip(b, b[1:])))
