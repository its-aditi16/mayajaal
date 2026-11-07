"""PROVE: no rule reaches production on the AI's word. Every candidate is tested on a throwaway
copy of the app. It must stop the attack, leave normal users alone and keep older attacks
blocked. This file contains no AI, and it does not care who wrote the rule."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import parse_qsl

import httpx
from fastapi import FastAPI

from .config import Settings
from .models import Activity, Check, Fix, Rule, VerificationReport
from .rewind import record_keys
from .rules import lint, rule_matches
from .store import Store
from .traps import registry

IDENTITY_FIELDS = {"fingerprint", "token_hash", "session_hash"}

log = logging.getLogger("mayajaal.prove")


@dataclass
class GoldenRequest:
    persona: str
    method: str
    path: str
    headers: dict[str, str]
    expect: int
    query: str = ""
    json: dict | None = field(default=None)


@dataclass
class SandboxResponse:
    status: int
    blocked: bool


class Sandbox(Protocol):
    name: str

    def send(self, persona: str, method: str, path: str, query: str, headers: dict[str, str],
             body: str | None) -> SandboxResponse: ...

    def close(self) -> None: ...


def _sandbox_settings(settings: Settings, rules: list[Rule], data_dir: str) -> Settings:
    return Settings(
        data_dir=data_dir, secret_key=settings.secret.decode(), token_prefix=settings.token_prefix,
        sandbox_mode=True, sandbox_rules=json.dumps([r.model_dump() for r in rules]),
        memory_backend="local", llm_provider="none", redis_url="", _env_file=None,
    )


class InProcessSandbox:
    """A fresh app instance with an empty database. Used when Docker is unavailable, and the
    report says so: isolation here is a separate app and database, not a separate machine."""

    name = "in-process copy"

    def __init__(self, settings: Settings, rules: list[Rule], app_factory: Callable[[Settings], FastAPI]):
        from starlette.testclient import TestClient

        self._client_cls = TestClient
        self._tmp = tempfile.TemporaryDirectory(prefix="mayajaal-sandbox-", ignore_cleanup_errors=True)
        self.app = app_factory(_sandbox_settings(settings, rules, self._tmp.name))
        self._clients: dict[str, object] = {}

    def send(self, persona, method, path, query, headers, body):
        client = self._clients.get(persona)
        if client is None:
            client = self._clients[persona] = self._client_cls(
                self.app, base_url="http://sandbox.local", follow_redirects=False, raise_server_exceptions=False)
            client.__enter__()  # Keeps one event loop alive instead of starting one per request.
            client.headers.clear()
        url = f"{path}?{query}" if query else path
        response = client.request(method, url, headers=headers, content=body)
        return SandboxResponse(response.status_code, "x-mayajaal-block" in response.headers)

    def close(self):
        for client in self._clients.values():
            client.__exit__(None, None, None)
        self._tmp.cleanup()


class DockerSandbox:
    """The same app in a locked-down container that is thrown away afterwards."""

    name = "docker container"

    def __init__(self, settings: Settings, rules: list[Rule], image: str):
        env = {
            **os.environ, "MAYAJAAL_SANDBOX_MODE": "1", "MAYAJAAL_SECRET_KEY": settings.secret.decode(),
            "MAYAJAAL_TOKEN_PREFIX": settings.token_prefix,
            "MAYAJAAL_SANDBOX_RULES": json.dumps([r.model_dump() for r in rules]),
            "MAYAJAAL_DATA_DIR": "/sandbox", "MAYAJAAL_LLM_PROVIDER": "none", "MAYAJAAL_MEMORY_BACKEND": "local",
        }
        names = [k for k in env if k.startswith("MAYAJAAL_") and k in (
            "MAYAJAAL_SANDBOX_MODE", "MAYAJAAL_SECRET_KEY", "MAYAJAAL_TOKEN_PREFIX", "MAYAJAAL_SANDBOX_RULES",
            "MAYAJAAL_DATA_DIR", "MAYAJAAL_LLM_PROVIDER", "MAYAJAAL_MEMORY_BACKEND")]
        cmd = ["docker", "run", "-d", "--rm", "-p", "127.0.0.1:0:8000", "--cap-drop=ALL", "--read-only",
               "--tmpfs", "/sandbox:mode=1777", "--tmpfs", "/tmp", "--memory=512m", "--pids-limit=128",
               "--security-opt=no-new-privileges"]
        for name in names:  # Passed by name so values never appear in the process list.
            cmd += ["-e", name]
        cmd += [image, "uvicorn", "--factory", settings.target_app, "--host", "0.0.0.0", "--port", "8000"]
        self.container = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True, timeout=60).stdout.strip()
        try:
            port_line = subprocess.run(["docker", "port", self.container, "8000/tcp"], capture_output=True, text=True,
                                       check=True, timeout=20).stdout.strip().splitlines()[0]
            self.base = f"http://127.0.0.1:{port_line.rsplit(':', 1)[1]}"
            self._wait_ready()
        except Exception:
            self.close()
            raise
        self._clients: dict[str, httpx.Client] = {}

    def _wait_ready(self) -> None:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                if httpx.get(f"{self.base}/healthz", timeout=2, headers={"user-agent": "mayajaal-sandbox-probe"}).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise TimeoutError("Sandbox container did not become ready")

    def send(self, persona, method, path, query, headers, body):
        client = self._clients.get(persona)
        if client is None:
            client = self._clients[persona] = httpx.Client(base_url=self.base, timeout=15, follow_redirects=False)
            client.headers.clear()
        url = f"{path}?{query}" if query else path
        response = client.request(method, url, headers=headers, content=body)
        return SandboxResponse(response.status_code, "x-mayajaal-block" in response.headers)

    def close(self):
        for client in getattr(self, "_clients", {}).values():
            client.close()
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, timeout=30)


def docker_ready(image: str) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def replay_request(record: Activity) -> tuple[dict[str, str], str | None]:
    headers = {k: v for k, v in record.headers.items() if v.isascii()}
    headers["x-replay-fingerprint"] = record.fingerprint
    if record.token_hash:
        headers["x-replay-token-hash"] = record.token_hash
    if record.session_hash:
        headers["x-replay-session-hash"] = record.session_hash
    if record.honeytoken:
        headers["authorization"] = f"Bearer {record.honeytoken}"
    body = record.body or None
    if body:
        headers["content-type"] = "application/json"
    return headers, body


def must_block(records: list[Activity]) -> list[Activity]:
    """The steps that did or could do harm. Public pages need not be blocked for a fix to count."""
    harmful = [r for r in records if r.sensitivity in ("data", "user", "credential")
               and not r.path.startswith("mcp://")]
    if harmful:
        return harmful
    return [r for r in records if r.sensitivity == "trap" and not r.path.startswith("mcp://")]


def known_params(golden: list[GoldenRequest]) -> dict[str, set[str]]:
    known: dict[str, set[str]] = {}
    for request in golden:
        known.setdefault(request.path, set()).update(k for k, _ in parse_qsl(request.query))
    return known


class Verifier:
    def __init__(self, settings: Settings, store: Store, app_factory: Callable[[Settings], FastAPI],
                 golden: list[GoldenRequest]):
        self.settings, self.store, self.app_factory, self.golden = settings, store, app_factory, golden

    def _sandbox(self, rules: list[Rule]) -> Sandbox:
        backend = self.settings.sandbox_backend
        if backend == "docker" or (backend == "auto" and docker_ready(self.settings.sandbox_image)):
            try:
                return DockerSandbox(self.settings, rules, self.settings.sandbox_image)
            except Exception as exc:
                if backend == "docker":
                    raise
                log.warning("Docker sandbox failed (%s); using an in-process copy", exc)
        return InProcessSandbox(self.settings, rules, self.app_factory)

    @staticmethod
    def _replay(sandbox: Sandbox, records: list[Activity]) -> list[Activity]:
        """Returns the steps that got through."""
        leaked = []
        for record in records:
            headers, body = replay_request(record)
            if not sandbox.send("replay", record.method, record.path, record.query, headers, body).blocked:
                leaked.append(record)
        return leaked

    def _other_traffic(self, attacker_ids: set[int], window: float | None = None) -> list[Activity]:
        """Recent real traffic that belongs to nobody in any incident."""
        excluded = set(attacker_ids)
        attackers: set[str] = set()
        for incident in self.store.incidents():
            excluded.update(incident.activity_ids)
            attackers.update(incident.actor_keys)  # Also catches requests made after the last rewind.
        since = time.time() - (self.settings.rewind_window_seconds if window is None else window)
        return [r for r in self.store.activity_since(since)
                if r.id not in excluded and not r.blocked_by and not record_keys(r) & attackers]

    def verify(self, fix: Fix, attack: list[Activity]) -> VerificationReport:
        started = time.time()
        checks: list[Check] = []

        problems = [f"{r.title}: {p}" for r in fix.rules for p in lint(r)]
        problems += [f"{r.title}: would hide the bait from the next attacker; block the attacker, not the trap"
                     for r in hides_bait(fix.rules, attack)]
        checks.append(Check(name="Rule is safe to run", passed=not problems and bool(fix.rules),
                            detail="; ".join(problems) or (f"{len(fix.rules)} rule(s) passed static checks"
                                                           if fix.rules else "No rules proposed")))
        if not checks[-1].passed:
            return VerificationReport(passed=False, backend="static", checks=checks,
                                      duration_seconds=round(time.time() - started, 3))

        attack_ids = {r.id for r in attack}
        others = self._other_traffic(attack_ids)
        collateral = [r for r in others if any(rule_matches(rule, r.rule_attrs()) for rule in fix.rules)]
        checks.append(Check(
            name="Recent real traffic unaffected", passed=not collateral,
            detail=f"Would have blocked {len(collateral)} of {len(others)} recent requests from other people"
                   + (f", e.g. {collateral[0].method} {collateral[0].route}" if collateral else "")))

        sandbox = self._sandbox(fix.rules)
        backend = sandbox.name
        try:
            targets = must_block(attack)
            leaked = self._replay(sandbox, targets)
            checks.append(Check(
                name="Stops the attack", passed=bool(targets) and not leaked,
                detail=(f"Replayed {len(targets)} attack step(s); {len(targets) - len(leaked)} blocked"
                        + (f"; got through: {', '.join(sorted({r.route for r in leaked})[:4])}" if leaked else ""))
                if targets else "Nothing to replay over HTTP (AI-tool-only attack), so a person must review it"))

            failures = []
            for request in self.golden:
                body = json.dumps(request.json) if request.json is not None else None
                headers = dict(request.headers)
                if body:
                    headers["content-type"] = "application/json"
                result = sandbox.send(f"golden-{request.persona}", request.method, request.path, request.query,
                                      headers, body)
                if result.blocked or result.status != request.expect:
                    failures.append(f"{request.persona} {request.method} {request.path} -> {result.status}")
            checks.append(Check(
                name="Normal users still get through", passed=bool(self.golden) and not failures,
                detail=(f"{len(self.golden) - len(failures)} of {len(self.golden)} normal requests passed"
                        + (f"; broken: {'; '.join(failures[:4])}" if failures else ""))
                if self.golden else "No normal traffic to test against, so this fix cannot be trusted"))
        finally:
            sandbox.close()

        # Regression: the whole rule set together must keep every earlier attack out.
        active = [f for f in self.store.fixes(("active",)) if f.id != fix.id]
        previous = []
        for old in active:
            incident = self.store.get_incident(old.incident_id)
            if incident:
                previous.extend(must_block(self.store.activity_by_ids(incident.activity_ids)))
        if previous:
            combined = [r for f in active for r in f.rules] + fix.rules
            sandbox = self._sandbox(combined)
            try:
                leaked = self._replay(sandbox, previous)
            finally:
                sandbox.close()
            checks.append(Check(
                name="Older attacks stay blocked", passed=not leaked,
                detail=f"Replayed {len(previous)} step(s) from {len(active)} earlier attack(s); "
                       f"{len(previous) - len(leaked)} blocked"))
        else:
            checks.append(Check(name="Older attacks stay blocked", passed=True, detail="No earlier attacks to replay yet"))

        return VerificationReport(passed=all(c.passed for c in checks), backend=backend, checks=checks,
                                  duration_seconds=round(time.time() - started, 3))


def record_golden(settings: Settings, store: Store, days: float = 7.0) -> list[dict]:
    """Turns recent anonymous, successful page views into a starting list of normal traffic.
    Anything with a credential is left out, because it could not be replayed and is private."""
    verifier = Verifier(settings, store, None, [])
    seen: set[tuple[str, str, str]] = set()
    golden: list[dict] = []
    for record in verifier._other_traffic(set(), window=days * 86400):
        key = (record.path, record.query, record.user_agent)
        if (record.method != "GET" or not 200 <= record.status < 300 or record.trap_id or record.token_hash
                or record.session_hash or key in seen):
            continue
        seen.add(key)
        golden.append({"persona": f"visitor-{record.fingerprint[:8]}", "method": "GET", "path": record.path,
                       "query": record.query, "headers": record.headers, "expect": record.status})
    return golden


def hides_bait(rules: list[Rule], attack: list[Activity]) -> list[Rule]:
    """Rules that would block a trap for everyone. A trap must keep serving fake keys so it can
    catch the next attacker, so only rules tied to this attacker's identity may cover it."""
    bait = [r.rule_attrs() for r in attack if r.trap_id and not r.path.startswith("mcp://")]
    bait += [{"path": path, "method": "GET", "query": ""} for path in registry.BY_PATH]
    return [rule for rule in rules
            if not any(c.field in IDENTITY_FIELDS for c in rule.conditions)
            and any(rule_matches(rule, attrs) for attrs in bait)]
