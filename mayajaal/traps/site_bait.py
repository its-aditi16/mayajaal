"""Bait that fits the website it protects.

AI (or, without AI, simple rules) suggests decoy URLs that look like they belong to this app.
Code then rejects any suggestion that could catch a real user, and nothing is deployed until a
person reviews the file and points MAYAJAAL_DECOYS_FILE at it. Trap placement stays a human call."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError

from . import registry

MAX_DECOYS = 8
SAFE_PATH = re.compile(r"^/[a-z0-9][a-z0-9._/-]{1,79}$")
FAKE_RECORD = {"id": 9017, "name": "Ananya Rao", "email": "ananya.rao@customers.example", "city": "Hyderabad"}


class Decoy(BaseModel):
    path: str = Field(max_length=80)
    kind: Literal["data", "secret", "page"]
    reason: str = Field(default="", max_length=200)


def app_paths(app: FastAPI) -> list[str]:
    """The app's own routes, leaving out Mayajaal's built-in traps."""
    built_in = set(registry.BY_PATH) | {"/api/vault/keys"}
    paths = {getattr(route, "path", "") for route in app.routes}
    return sorted(p for p in paths if p and p not in built_in and not p.startswith(("/docs", "/openapi", "/redoc")))


def _matches_template(candidate: str, template: str) -> bool:
    """True if a real route with {parameters} would also answer this URL."""
    a, b = candidate.strip("/").split("/"), template.strip("/").split("/")
    return len(a) == len(b) and all(t.startswith("{") or c == t for c, t in zip(a, b))


GENERIC_WORDS = {"api", "v1", "v2", "static", "healthz", "health", "robots", "txt", "id", "app", "index"}


def vocabulary(real_paths: list[str]) -> set[str]:
    """Words the app itself uses in its routes, such as patients or customers."""
    words = set()
    for path in real_paths:
        for word in re.split(r"[/_.\-{}]+", path.lower()):
            if len(word) >= 3 and word not in GENERIC_WORDS:
                words.add(word)
    return words


def validate(decoys: list[Decoy], real_paths: list[str]) -> tuple[list[Decoy], list[tuple[str, str]]]:
    """Keeps only decoys no real user could ever hit. Returns (accepted, [(path, why rejected)])."""
    accepted: list[Decoy] = []
    rejected: list[tuple[str, str]] = []
    taken = set(registry.BY_PATH) | {"/api/vault/keys"}
    templates = [p for p in real_paths if "{" in p]
    words = vocabulary(real_paths)
    for decoy in decoys:
        path = decoy.path.rstrip("/") or "/"
        why = ""
        if not SAFE_PATH.match(path) or ".." in path or "//" in path:
            why = "not a simple lowercase path"
        elif path in real_paths:
            why = "a real page already uses this path"
        elif any(_matches_template(path, t) for t in templates):
            why = "a real route with a parameter would also answer it, so a real user could hit it"
        elif path in taken:
            why = "duplicate"
        elif words and not any(word in path for word in words):
            why = "generic: uses none of this app's own words, and built-in traps already cover that"
        elif len(accepted) >= MAX_DECOYS:
            why = f"more than {MAX_DECOYS} decoys"
        if why:
            rejected.append((path, why))
        else:
            taken.add(path)
            accepted.append(decoy.model_copy(update={"path": path}))
    return accepted, rejected


def rule_suggestions(real_paths: list[str]) -> list[Decoy]:
    """No-AI fallback: decoys named after the app's own top-level sections."""
    sections = sorted({p.strip("/").split("/")[0] for p in real_paths if p.strip("/") and "{" not in p.split("/")[1]})
    names = [s for s in sections if s not in ("static", "healthz", "robots.txt", "api")] or ["app"]
    api = sorted({p.strip("/").split("/")[1] for p in real_paths if p.startswith("/api/") and p.count("/") >= 2
                  and "{" not in p.split("/")[2]})
    out: list[Decoy] = []
    for name in (api or names)[:3]:
        out.append(Decoy(path=f"/{name}-archive/export-all", kind="data", reason=f"Looks like a bulk export of {name}"))
        out.append(Decoy(path=f"/internal/{name}-admin", kind="page", reason=f"Looks like an admin page for {name}"))
    out.append(Decoy(path=f"/backup/{names[0]}-db.sql", kind="secret", reason="Looks like a forgotten database backup"))
    return out


def parse_ai_suggestions(raw: dict | None) -> list[Decoy]:
    items = (raw or {}).get("decoys", []) if isinstance(raw, dict) else []
    out = []
    for item in items[:MAX_DECOYS * 2]:
        try:
            out.append(Decoy.model_validate(item))
        except ValidationError:
            continue
    return out


def load(path: str | Path) -> list[Decoy]:
    return [Decoy.model_validate(item) for item in json.loads(Path(path).read_text(encoding="utf-8"))]


def router(shield, decoys: list[Decoy]) -> APIRouter:
    """Serves each decoy with a per-requester signed key, like every other trap."""
    api = APIRouter(include_in_schema=False)

    def handler(kind: str):
        def serve(request: Request):
            key = shield.dye(request, "site_decoy")
            if kind == "data":
                return {"count": 1, "records": [{**FAKE_RECORD, "api_key": key}]}
            if kind == "secret":
                return PlainTextResponse(f"-- backup\nSERVICE_API_KEY={key}\n")
            return HTMLResponse(f"<html><body><h1>Admin</h1><p>Token: <code>{key}</code></p></body></html>")
        return serve

    for decoy in decoys:
        api.add_api_route(decoy.path, handler(decoy.kind), methods=["GET"])
    return api
