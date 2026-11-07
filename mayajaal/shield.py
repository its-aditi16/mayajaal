"""The part that lives inside the protected app: serves decoys, fires traps, records activity,
enforces approved blocks. No AI anywhere in this file, so it keeps working if the AI is down.
A failure in Mayajaal must never take the host app down, so recording fails open."""
from __future__ import annotations

import logging
import re
import time

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import TypeAdapter
from starlette.middleware.base import BaseHTTPMiddleware

from .bus import Bus
from .config import Settings
from .models import Activity, Rule
from .privacy import keyed_hash, mask, mask_ip
from .rules import rule_matches
from .store import Store
from .traps import registry, tokens

log = logging.getLogger("mayajaal.shield")

# Never stored or fed into the fingerprint: credentials and per-request noise.
SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "set-cookie", "proxy-authorization"}
# These change from one request to the next on the same device, so they cannot identify it.
VOLATILE_HEADERS = {"host", "content-length", "content-type", "connection", "x-forwarded-for", "x-real-ip",
                    "referer", "origin", "range", "cache-control", "pragma", "priority", "te", "upgrade",
                    "upgrade-insecure-requests", "x-requested-with", "traceparent", "tracestate"}
VOLATILE_PREFIXES = ("if-", "sec-fetch-", "access-control-")
REPLAY_HEADERS = {"x-replay-fingerprint", "x-replay-token-hash", "x-replay-session-hash"}
MAX_BODY_SCAN = 64 * 1024
MAX_STORED = 512
RULE_CACHE_SECONDS = 1.0
_RULES = TypeAdapter(list[Rule])


class Shield:
    def __init__(self, settings: Settings, store: Store, bus: Bus, route_tags: dict[str, str] | None = None,
                 extra_trap_paths: dict[str, str] | None = None, session_cookie: str = "session"):
        self.settings = settings
        self.store = store
        self.bus = bus
        self.route_tags = route_tags or {}
        self.trap_paths = {**{p: t.id for p, t in registry.BY_PATH.items()}, **(extra_trap_paths or {})}
        self.session_cookie = session_cookie
        self.secret = settings.secret
        self.token_re = re.compile(re.escape(settings.token_prefix) + r"[a-z2-7]{32}")
        self._blocks: list[tuple[str, Rule]] = []
        self._shadow: list[tuple[str, Rule]] = []
        self._loaded_at = 0.0
        if settings.sandbox_mode:
            self._blocks = [("sandbox", r) for r in _RULES.validate_json(settings.sandbox_rules)]

    # Rule cache: if the store is unreachable, the last known blocks stay in force.
    def _refresh_rules(self) -> None:
        if self.settings.sandbox_mode or time.time() - self._loaded_at < RULE_CACHE_SECONDS:
            return
        try:
            self._blocks = [(f.id, r) for f in self.store.fixes(("active",)) for r in f.rules]
            self._shadow = [(f.id, r) for f in self.store.fixes(("shadow", "awaiting_approval")) for r in f.rules]
            self._loaded_at = time.time()
        except Exception:
            log.exception("Could not refresh rules; keeping existing blocks")

    # Honeytokens are minted per requester, so a stolen token identifies who it was served to.
    def dye(self, request: Request, trap_id: str) -> str:
        identity = getattr(request.state, "mayajaal_identity", "anonymous")
        token = tokens.mint(self.secret, registry.BY_ID[trap_id].code, identity, self.settings.token_prefix)
        served = getattr(request.state, "mayajaal_served", None)
        if served is None:
            served = request.state.mayajaal_served = []
        served.append(keyed_hash(self.secret, token))
        return token

    def _client_ip(self, request: Request) -> str:
        if self.settings.trust_forwarded_for:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def fingerprint(self, request: Request) -> str:
        names = [k.decode().lower() for k, _ in request.scope["headers"]]
        stable = [n for n in names if n not in SENSITIVE_HEADERS | VOLATILE_HEADERS | REPLAY_HEADERS
                  and not n.startswith(VOLATILE_PREFIXES)]
        h = request.headers
        material = "|".join([",".join(stable), h.get("user-agent", ""), h.get("accept", ""),
                             h.get("accept-language", ""), h.get("accept-encoding", "")])
        return keyed_hash(self.secret, "fp:" + material)

    def _find_honeytoken(self, *haystacks: str) -> tuple[str, str] | None:
        for text in haystacks:
            for candidate in self.token_re.findall(text or ""):
                code = tokens.verify(self.secret, candidate, self.settings.token_prefix)
                if code is not None and code in registry.BY_CODE:
                    return candidate, registry.BY_CODE[code].id
        return None

    def route_of(self, path: str) -> str:
        return "/".join(":id" if seg.isdigit() else seg for seg in path.split("/"))

    def sensitivity_of(self, route: str) -> str:
        return self.route_tags.get(route, "asset" if route.startswith("/static/") else "public")

    async def inspect(self, request: Request) -> Activity:
        h = request.headers
        ip = self._client_ip(request)
        path = request.url.path
        route = self.route_of(path)
        query = request.url.query or ""

        body = ""
        declared = h.get("content-length", "0")
        if request.method in ("POST", "PUT", "PATCH") and declared.isdigit() and int(declared) <= MAX_BODY_SCAN:
            body = (await request.body()).decode("utf-8", "replace")

        auth = h.get("authorization", "")
        raw_token = auth[7:].strip() if auth.lower().startswith("bearer ") else (h.get("x-api-key") or "").strip()
        cookie_session = request.cookies.get(self.session_cookie)

        found = self._find_honeytoken(raw_token, query, body, h.get("cookie", ""))
        sensitivity = self.sensitivity_of(route)
        trap_id = self.trap_paths.get(path)
        honeytoken = None
        if found:
            honeytoken, trap_id = found
            sensitivity = "credential"
        elif trap_id:
            sensitivity = "trap"

        fingerprint = self.fingerprint(request)
        token_hash = keyed_hash(self.secret, raw_token) if raw_token else None
        session_hash = keyed_hash(self.secret, cookie_session) if cookie_session else None

        if self.settings.sandbox_mode:  # Replays carry the recorded identity, which is stored only as hashes.
            fingerprint = h.get("x-replay-fingerprint", fingerprint)
            token_hash = h.get("x-replay-token-hash", token_hash)
            session_hash = h.get("x-replay-session-hash", session_hash)

        ip_hash = keyed_hash(self.secret, "ip:" + ip)
        request.state.mayajaal_identity = f"{ip_hash}:{fingerprint}"

        stored_headers = {
            k: mask(v)[:MAX_STORED] for k, v in h.items()
            if k == "referer" or (k not in SENSITIVE_HEADERS | VOLATILE_HEADERS | REPLAY_HEADERS
                                  and not k.startswith(VOLATILE_PREFIXES))
        }
        return Activity(
            ip_hash=ip_hash, ip_masked=mask_ip(ip), fingerprint=fingerprint, token_hash=token_hash,
            session_hash=session_hash, honeytoken=honeytoken, method=request.method, path=path, route=route,
            query=mask(query)[:MAX_STORED], user_agent=mask(h.get("user-agent", ""))[:MAX_STORED],
            headers=stored_headers, body=mask(body)[:MAX_STORED], sensitivity=sensitivity, trap_id=trap_id,
        )

    def _evaluate(self, attrs: dict[str, str], rules: list[tuple[str, Rule]]) -> list[tuple[str, Rule]]:
        return [(fid, r) for fid, r in rules if rule_matches(r, attrs)]

    def _record(self, activity: Activity, shadow_matches: list[tuple[str, Rule]]) -> None:
        try:
            activity.id = self.store.add_activity(activity)
            for fix_id in {fid for fid, _ in shadow_matches}:
                self.store.add_shadow_hit(fix_id, activity.id)
            if activity.trap_id and not self.settings.sandbox_mode:
                self.bus.publish({"activity_id": activity.id, "trap_id": activity.trap_id})
        except Exception:
            log.exception("Could not record activity for %s", activity.path)


class ShieldMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, shield: Shield):
        super().__init__(app)
        self.shield = shield

    async def dispatch(self, request: Request, call_next):
        shield = self.shield
        try:
            activity = await shield.inspect(request)
            shield._refresh_rules()
            attrs = activity.rule_attrs()
            blocks = shield._evaluate(attrs, shield._blocks)
            shadow = shield._evaluate(attrs, shield._shadow)
        except Exception:
            log.exception("Inspection failed; letting the request through")
            return await call_next(request)

        if blocks:
            activity.blocked_by = blocks[0][1].id
            activity.status = 403
            shield._record(activity, shadow)
            response = JSONResponse({"detail": "Forbidden"}, status_code=403)
            if shield.settings.sandbox_mode:  # Tells a replay this was us, not the app. Attackers never see it.
                response.headers["x-mayajaal-block"] = activity.blocked_by
            return response

        response = await call_next(request)
        activity.status = response.status_code
        activity.served_hashes = list(getattr(request.state, "mayajaal_served", []))
        shield._record(activity, shadow)
        return response


def decoy_router(shield: Shield) -> APIRouter:
    """Convincing bait. Nothing real links here, so real users never arrive."""
    router = APIRouter(include_in_schema=False)

    @router.get("/.env")
    def env_file(request: Request):
        key = shield.dye(request, "env_file")
        return PlainTextResponse(
            "APP_ENV=production\nDATABASE_URL=postgres://app:changeme@db.internal:5432/app\n"
            f"PAYMENTS_API_KEY={key}\nDEBUG=false\n")

    @router.get("/internal/admin-console")
    def admin_console(request: Request):
        key = shield.dye(request, "admin_console")
        return HTMLResponse(
            "<html><title>Admin Console</title><body><h1>Internal admin console</h1>"
            f"<p>Service token: <code>{key}</code></p>"
            '<p><a href="/api/vault/keys">Key vault</a></p></body></html>')

    @router.get("/api/vault/keys")
    def vault_index():
        return {"keys": ["payments-master", "backup-signing"], "vault": "prod-kv-01"}

    @router.get("/api/vault/keys/payments-master")
    def vault_key(request: Request):
        return {"name": "payments-master", "value": shield.dye(request, "vault_decoy"), "enabled": True}

    return router


def install(app: FastAPI, settings: Settings, store: Store, bus: Bus, route_tags: dict[str, str] | None = None,
            extra_trap_paths: dict[str, str] | None = None, decoys: list | None = None) -> Shield:
    from .traps import site_bait

    if decoys is None and settings.decoys_file:
        decoys = site_bait.load(settings.decoys_file)
    decoys = decoys or []
    shield = Shield(settings, store, bus, route_tags,
                    {"/api/vault/keys": "vault_decoy", **{d.path: "site_decoy" for d in decoys},
                     **(extra_trap_paths or {})})
    app.add_middleware(ShieldMiddleware, shield=shield)
    app.include_router(decoy_router(shield))
    if decoys:
        app.include_router(site_bait.router(shield, decoys))
    app.state.shield = shield
    return shield
