"""The full story on real sockets: mayajaal demo [--fresh] [--no-ai] [--no-memory]

An AI agent attacks, gets caught and is blocked. It keeps coming back in new disguises, and
memory recognises it each time. A curious person wanders in and is not blocked. Normal users
run throughout, and the run ends by checking none of them was ever blocked.

Run it again without --fresh and only a returning attacker appears, showing that what was
learned survives a restart. Use --fresh --no-memory to see the same story without memory."""
from __future__ import annotations

import argparse
import logging
import socket
import threading
import time
import uuid

import httpx
import uvicorn

from ..bus import Bus
from ..config import Settings
from ..control_api import create_control_app
from ..models import Incident
from ..pipeline import Pipeline
from ..sim import AGENT_A, ai_agent, curious_human, normal_user
from ..store import Store
from ..worker import build_pipeline
from .app import create_app

BOLD, DIM, RED, GREEN, CYAN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[36m", "\033[0m"
LOCAL_STATE = ("mayajaal.db", "mayajaal.db-wal", "mayajaal.db-shm", "kiranacloud.db", "alerts_outbox.jsonl")
PAUSED = ("awaiting_approval", "needs_human", "error")
BROWSERS = ("Chrome/131.0 Safari/537.36", "Firefox/132.0", "Edg/130.0", "Chrome/129.0 Safari/537.36")


def heading(text: str) -> None:
    print(f"\n{BOLD}{CYAN}=== {text} ==={RESET}", flush=True)


def disguise(number: int) -> dict[str, str]:
    """A brand new client identity every time: the only constant is how it behaves."""
    # The fingerprint reads the user agent, so a unique build number makes a genuinely new identity.
    build = uuid.uuid4().int % 9000 + 1000
    browser = BROWSERS[number % len(BROWSERS)].replace(".0", f".0.{build}", 1)
    return {"user-agent": f"Mozilla/5.0 (X11; Linux x86_64) {browser}",
            "accept": "application/json, */*", "x-client-trace": f"scout-{uuid.uuid4().hex[:8]}"}


def _free_port(preferred: int) -> int:
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", preferred)) != 0:
            return preferred
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _serve(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    return server


class Story:
    def __init__(self, settings: Settings, store: Store, pipeline: Pipeline, base: str):
        self.settings, self.store, self.pipeline, self.base = settings, store, pipeline, base
        self.seen = {i.id for i in store.incidents()}  # Earlier runs are not part of this story.
        self.printed: dict[str, int] = {}
        self.timeout = 180 + (2 * settings.llm_timeout_seconds if pipeline.ai.available else 0)

    def get(self, incident_id: str) -> Incident:
        incident = self.store.get_incident(incident_id)
        assert incident is not None
        return incident

    def wait(self, statuses: tuple[str, ...]) -> Incident | None:
        """Waits for the new incident to reach a state, narrating as it goes."""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            for incident in self.store.incidents():
                if incident.id in self.seen:
                    continue
                done = self.printed.setdefault(incident.id, 0)
                for entry in incident.timeline[done:]:
                    colour = RED if "FAIL" in entry.message else GREEN if "PASS" in entry.message else ""
                    print(f"  {DIM}{incident.id}{RESET} {BOLD}{entry.stage:<8}{RESET} {colour}{entry.message}{RESET}",
                          flush=True)
                self.printed[incident.id] = len(incident.timeline)
                if incident.status in statuses:
                    return incident
            time.sleep(0.1)
        return None

    def approve(self, incident: Incident, action: str = "approve") -> Incident:
        response = httpx.post(self.pipeline.approval_url(incident.fix_id, action), timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"Approval link returned {response.status_code}: {response.text[:200]}")
        self.seen.add(incident.id)
        return self.get(incident.id)

    def wait_until_remembered(self, incident: Incident) -> None:
        deadline = time.time() + 120
        while not self.get(incident.id).retained and time.time() < deadline:
            time.sleep(0.2)
        if self.pipeline.memory.backend != "off":
            print(f"  Experience retained in {self.pipeline.memory.backend}: {self.get(incident.id).retained}")

    def attack(self, ip: str, headers: dict[str, str], shadow_retry: bool = False) -> Incident:
        log = ai_agent(self.base, ip, headers)
        export = next(status for path, status in log if "export" in path)
        note = "stopped by the technique it learned" if export == 403 else "the data got out"
        print(f"  {len(log)} requests. Customer data export -> {export} ({note})", flush=True)
        if shadow_retry:
            watching = self.wait(("shadow", *PAUSED))
            if watching is not None and watching.status == "shadow":
                with httpx.Client(base_url=self.base, timeout=10) as retry:
                    retry.headers.clear()
                    status = retry.get("/api/customers/export?limit=100000&include=api_key",
                                       headers={**headers, "x-forwarded-for": ip}).status_code
                print(f"  Attacker retries during shadow mode -> {status} (watched, deliberately not blocked yet)")
        incident = self.wait(PAUSED)
        if incident is None or incident.status != "awaiting_approval":
            state = incident.status if incident else "timed out"
            raise RuntimeError(f"Attack did not reach approval: {state}")
        incident = self.approve(incident)
        print(f"  {GREEN}A person approved it. Blocked.{RESET}", flush=True)
        self.wait_until_remembered(incident)
        return self.get(incident.id)


def print_curve(attacks: list[Incident], store: Store) -> None:
    print(f"  {BOLD}{'Attack':<8}{'Recognised':<14}{'Fix from':<10}{'AI calls':<10}{'Watch-only':<12}"
          f"{'Testing':<9}Real data reads{RESET}")
    for number, incident in enumerate(attacks, start=1):
        fix = store.get_fix(incident.fix_id)
        known = f"yes, {incident.recollection.similarity:.0%}" if incident.recollection else "no"
        watch = f"{fix.shadow_seconds:g}s" if fix else "-"
        spent = f"{incident.analysis_seconds or 0:.1f}s"
        print(f"  {number:<8}{known:<14}{fix.source if fix else '-':<10}{incident.ai_calls:<10}{watch:<12}"
              f"{spent:<9}{incident.blast_radius.get('data_reads', 0)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh", action="store_true", help="Forget earlier demo runs first")
    parser.add_argument("--no-ai", action="store_true", help="Run with the defender AI switched off")
    parser.add_argument("--no-memory", action="store_true", help="Run with memory switched off, for comparison")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    app_port, control_port = _free_port(8000), _free_port(8100)
    overrides: dict = {}
    if args.no_ai:
        overrides["llm_provider"] = "none"
    if args.no_memory:
        overrides["memory_backend"] = "off"
    settings = Settings(
        trust_forwarded_for=True, settle_seconds=6.0, shadow_seconds=4.0, shadow_seconds_proven=1.0,
        target_app="mayajaal.demo.app:create_app", target_golden="mayajaal.demo.golden:GOLDEN",
        public_base_url=f"http://127.0.0.1:{control_port}", **overrides)
    if args.fresh:
        try:
            for name in LOCAL_STATE:
                (settings.data_dir / name).unlink(missing_ok=True)
        except PermissionError:
            print(f"{RED}Close the dashboard first: it is holding the demo's database open.{RESET}")
            return 1

    store = Store(settings.db_path)
    bus = Bus(settings, store)
    pipeline = build_pipeline(settings, store)
    if args.fresh:  # Old memories would point at incidents that no longer exist.
        pipeline.memory.reset()
    base = f"http://127.0.0.1:{app_port}"
    _serve(create_app(settings), app_port)
    _serve(create_control_app(pipeline), control_port)
    stop = threading.Event()
    threading.Thread(target=pipeline.run, args=(bus, stop), daemon=True).start()

    heading("Mayajaal is running")
    for key, value in {**pipeline.status(), "event bus": bus.name}.items():
        if value:
            print(f"  {key:<16}{value}")
    print(f"  {'data':<16}{settings.data_dir}")

    normal_statuses: dict[int, int] = {}
    lock = threading.Lock()

    def record(response: httpx.Response) -> None:
        with lock:
            normal_statuses[response.status_code] = normal_statuses.get(response.status_code, 0) + 1

    users_stop = threading.Event()
    users = [threading.Thread(target=normal_user, args=(base, ip, users_stop, record), daemon=True)
             for ip in ("198.51.100.10", "198.51.100.11")]
    for user in users:
        user.start()
    print(f"  {'normal users':<16}2 signed-in staff working in the background")
    time.sleep(1.5)

    story = Story(settings, store, pipeline, base)
    returning_only = bool(store.fixes(("active",)))
    attacks: list[Incident] = []
    person: Incident | None = None
    try:
        if returning_only:
            heading("An attacker returns, after a full restart")
            print("  Nothing is shared with the earlier attack except how it behaves.")
            attacks.append(story.attack(f"192.0.2.{uuid.uuid4().int % 200 + 20}", disguise(uuid.uuid4().int)))
        else:
            heading("Attack 1: an AI agent attacks")
            attacks.append(story.attack("192.0.2.10", AGENT_A, shadow_retry=True))
            print(f"\n  {BOLD}What happened ({attacks[0].explanation_source}):{RESET} {attacks[0].explanation}")
            time.sleep(1.2)  # Rule cache refresh.

            heading("Is the attacker locked out?")
            with httpx.Client(base_url=base, timeout=10) as check:
                check.headers.clear()
                for label, ip in (("same address", "192.0.2.10"), ("brand new address", "192.0.2.99")):
                    status = check.get("/products", headers={**AGENT_A, "x-forwarded-for": ip}).status_code
                    verdict = f"{GREEN}blocked{RESET}" if status == 403 else f"{RED}NOT blocked{RESET}"
                    print(f"  Harmless page, {label}: {status} ({verdict})")

            for number, ip in ((2, "192.0.2.77"), (3, "192.0.2.150")):
                heading(f"Attack {number}: it comes back disguised (new IP, new identity, no shared token)")
                attacks.append(story.attack(ip, disguise(number)))

            heading("A curious person wanders in")
            curious_human(base)
            person = story.wait(PAUSED)
            if person is None:
                raise RuntimeError("The person's visit never reached a decision")
            print(f"  Label: {person.classification.label} (score {person.classification.score})")
            if person.status == "awaiting_approval":
                print("  The approver sees it is a person, not a bot, and declines. Nothing is blocked.")
                person = story.approve(person, "decline")
            elif person.status == "needs_human":
                print(f"  {GREEN}Nothing was blocked.{RESET} The fix would also have hit other normal users, so the "
                      "checks\n  refused it and handed the decision to a person.")
    except RuntimeError as exc:
        print(f"{RED}{exc}{RESET}")
        stop.set()
        users_stop.set()
        return 1

    users_stop.set()
    for user in users:
        user.join(timeout=5)

    if pipeline.memory.backend != "off":
        heading("What memory concluded")
        try:
            pipeline.reflect_now().result(timeout=settings.hindsight_reflect_timeout + 30)
        except Exception as exc:
            print(f"  Reflection did not finish: {type(exc).__name__}")
        for row in store.observations(limit=1):
            print(f"  [{row['source']}]\n{row['text']}")

    heading("The learning curve")
    print_curve(attacks, store)

    heading("Result")
    total = sum(normal_statuses.values())
    blocked = normal_statuses.get(403, 0)
    print(f"  Normal user requests: {total}, blocked: {blocked}")
    for number, incident in enumerate(attacks, start=1):
        known = f"recognised as {incident.recollection.incident_id} via {incident.recollection.backend}" \
            if incident.recollection else "not recognised"
        print(f"  Attack {number}: {incident.classification.label} -> {incident.status}, {known}")
    if person:
        print(f"  Person: {person.classification.label} -> {person.status}")
    print("\n  See it all: mayajaal dashboard")

    stop.set()
    returning = attacks if returning_only else attacks[1:]
    # Recognition must come from behaviour: every disguise has a new identity by construction.
    memory_as_expected = (not any(i.recollection for i in returning) if args.no_memory
                          else all(i.recollection and not i.recollection.identity_match for i in returning))
    ok = (blocked == 0 and memory_as_expected and all(i.status == "blocked" for i in attacks)
          and (person is None or person.status in ("declined", "needs_human")))
    print(f"\n  {GREEN + 'DEMO PASSED' if ok else RED + 'DEMO FAILED'}{RESET}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
