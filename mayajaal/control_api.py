"""Control plane: approval links from Teams, and the admin API the dashboard uses.

Opening an approval link never changes anything, because chat apps fetch links to build
previews. It shows a confirm page, and only the POST from that page acts. Links are signed,
expire and work once. Whoever holds the link can use it, so add Entra sign-in for production."""
from __future__ import annotations

import hmac
from html import escape

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

from .alerts import read_approval
from .pipeline import ApprovalError, Pipeline

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mayajaal approval</title><style>body{{font:16px system-ui;max-width:640px;margin:40px auto;padding:0 16px;color:#1b1f24}}
button{{font:inherit;padding:10px 18px;background:#b42318;color:#fff;border:0;border-radius:6px;cursor:pointer}}
li{{margin:4px 0}}</style></head><body>{body}</body></html>"""


def create_control_app(pipeline: Pipeline) -> FastAPI:
    app = FastAPI(title="Mayajaal control", docs_url=None, redoc_url=None, openapi_url=None)
    settings = pipeline.settings
    store = pipeline.store

    def require_admin(authorization: str = Header(default="")) -> None:
        if not hmac.compare_digest(authorization.encode(), f"Bearer {settings.admin}".encode()):
            raise HTTPException(401, "Admin token required")

    def claims_or_404(token: str) -> dict:
        claims = read_approval(settings.secret, token)
        if claims is None:
            raise HTTPException(404, "This link is invalid or has expired")
        return claims

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", **pipeline.status()}

    @app.get("/approve/{token}", response_class=HTMLResponse)
    def approval_page(token: str):
        claims = claims_or_404(token)
        fix = store.get_fix(claims["fix"])
        if fix is None:
            raise HTTPException(404, "Fix not found")
        incident = store.get_incident(fix.incident_id)
        rules = "".join(f"<li>{escape(r.kind)}: {escape(r.title)}</li>" for r in fix.rules)
        checks = "".join(f"<li>{'PASS' if c.passed else 'FAIL'}: {escape(c.name)}</li>"
                         for c in (fix.report.checks if fix.report else []))
        verb = "Block this attacker" if claims["action"] == "approve" else "Decline this fix"
        body = (f"<h1>{escape(verb)}?</h1><p>{escape(incident.explanation if incident else '')}</p>"
                f"<h2>Rules</h2><ul>{rules}</ul><h2>Checks</h2><ul>{checks}</ul>"
                f'<form method="post"><button>{escape(verb)}</button></form>')
        return PAGE.format(body=body)

    @app.post("/approve/{token}", response_class=HTMLResponse)
    def approval_action(token: str, request: Request):
        claims = claims_or_404(token)
        if not store.use_nonce(claims["nonce"]):
            raise HTTPException(409, "This link has already been used")
        actor = f"approval-link ({request.client.host if request.client else 'unknown'})"
        try:
            if claims["action"] == "approve":
                pipeline.approve(claims["fix"], actor)
                message = "Blocked. The attacker is locked out."
            else:
                pipeline.decline(claims["fix"], actor)
                message = "Declined. Nothing was blocked and the traps stay live."
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc
        return PAGE.format(body=f"<h1>{escape(message)}</h1>")

    @app.post("/api/fixes/{fix_id}/approve", dependencies=[Depends(require_admin)])
    def api_approve(fix_id: str, actor: str = "dashboard"):
        try:
            return {"incident": pipeline.approve(fix_id, actor).id, "status": "blocked"}
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/fixes/{fix_id}/decline", dependencies=[Depends(require_admin)])
    def api_decline(fix_id: str, actor: str = "dashboard"):
        try:
            return {"incident": pipeline.decline(fix_id, actor).id, "status": "declined"}
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/fixes/{fix_id}/revoke", dependencies=[Depends(require_admin)])
    def api_revoke(fix_id: str, actor: str = "dashboard"):
        try:
            pipeline.revoke(fix_id, actor)
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"status": "revoked"}

    @app.post("/api/reflect", dependencies=[Depends(require_admin)])
    def api_reflect():
        pipeline.reflect_now()
        return {"status": "started"}

    return app
