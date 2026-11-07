"""KiranaCloud: a fictional grocery SaaS that stands in for a company's real app.
All people and data here are made up. It has one deliberate flaw for the demo: the customer
export endpoint forgets to check who is asking.

Run with: uvicorn --factory mayajaal.demo.app:create_app --port 8000"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading

from fastapi import Body, Cookie, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from ..bus import Bus
from ..config import Settings
from ..shield import install
from ..store import Store

CANARY_ID = 9001
DEMO_PASSWORD = "demo-only-password"
STAFF_EMAIL = "asha@kiranacloud.example"

ROUTE_TAGS = {
    "/api/customers": "data", "/api/customers/export": "data", "/api/customers/:id": "data",
    "/api/profile": "user", "/api/orders": "user", "/account": "user", "/settings": "user",
    "/api/login": "credential",
}
FIRST_NAMES = ["Asha", "Vikram", "Neha", "Arjun", "Pooja", "Rahul", "Divya", "Karan", "Meera", "Sanjay"]
LAST_NAMES = ["Rao", "Sharma", "Iyer", "Khan", "Das", "Patel", "Nair", "Singh"]

PAGE = """<!doctype html><html><head><title>KiranaCloud</title>
<link rel="stylesheet" href="/static/app.css"><script src="/static/app.js" defer></script></head>
<body><h1>KiranaCloud</h1><p>Groceries for neighbourhood stores.</p><a href="/products">Products</a></body></html>"""


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def _seed(db: sqlite3.Connection) -> None:
    db.executescript("""
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY, name TEXT, email TEXT, city TEXT, api_key TEXT, canary INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS staff (email TEXT PRIMARY KEY, salt BLOB, password_hash TEXT);
    """)
    if db.execute("SELECT COUNT(*) FROM customers").fetchone()[0]:
        return
    rows = []
    for i in range(40):
        first, last = FIRST_NAMES[i % len(FIRST_NAMES)], LAST_NAMES[i % len(LAST_NAMES)]
        rows.append((1000 + i, f"{first} {last}", f"{first.lower()}.{last.lower()}{i}@customers.example",
                     "Hyderabad", f"cust_{secrets.token_hex(12)}", 0))
    # The dye pack: looks like any other customer, sits among the real rows, belongs to nobody.
    rows.insert(17, (CANARY_ID, "Ritu Menon", "ritu.menon@customers.example", "Hyderabad", "", 1))
    db.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?)", rows)
    salt = secrets.token_bytes(16)
    db.execute("INSERT INTO staff VALUES (?,?,?)", (STAFF_EMAIL, salt, _hash(DEMO_PASSWORD, salt)))
    db.commit()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    store = Store(settings.db_path)
    bus = Bus(settings, store)
    app = FastAPI(title="KiranaCloud", docs_url=None, redoc_url=None, openapi_url=None)
    shield = install(app, settings, store, bus, route_tags=ROUTE_TAGS,
                     extra_trap_paths={f"/api/customers/{CANARY_ID}": "canary_record"})

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(settings.data_dir / "kiranacloud.db", check_same_thread=False)
    db.row_factory = sqlite3.Row
    db_lock = threading.Lock()
    with db_lock:
        _seed(db)
    sessions: dict[str, str] = {}

    def query(sql: str, *args) -> list[sqlite3.Row]:
        with db_lock:
            return db.execute(sql, args).fetchall()

    def require_staff(session: str | None) -> str:
        email = sessions.get(session or "")
        if not email:
            raise HTTPException(401, "Sign in required")
        return email

    def customer_json(row: sqlite3.Row, request: Request, include_keys: bool) -> dict:
        item = {"id": row["id"], "name": row["name"], "email": row["email"], "city": row["city"]}
        if include_keys:
            item["api_key"] = shield.dye(request, "canary_record") if row["canary"] else row["api_key"]
        return item

    @app.get("/", response_class=HTMLResponse)
    def home():
        return PAGE

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/static/app.css")
    def css():
        return Response("body{font-family:sans-serif}", media_type="text/css")

    @app.get("/static/app.js")
    def js():
        return Response("console.log('kiranacloud');", media_type="application/javascript")

    @app.get("/robots.txt", response_class=PlainTextResponse)
    def robots():
        return "User-agent: *\nDisallow: /internal/admin-console\nDisallow: /backup/\n"

    @app.get("/products")
    def products():
        return {"products": [{"sku": "ATTA-5KG", "price": 289}, {"sku": "TEA-500G", "price": 240}]}

    @app.post("/api/login")
    def login(response: Response, payload: dict = Body(...)):
        email, password = str(payload.get("email", "")), str(payload.get("password", ""))
        rows = query("SELECT salt, password_hash FROM staff WHERE email=?", email)
        if not rows or not hmac.compare_digest(_hash(password, rows[0]["salt"]), rows[0]["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        session = secrets.token_urlsafe(24)
        sessions[session] = email
        response.set_cookie("session", session, httponly=True, samesite="lax")
        return {"email": email}

    @app.get("/account")
    def account(session: str | None = Cookie(default=None)):
        return {"email": require_staff(session)}

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, session: str | None = Cookie(default=None)):
        email = require_staff(session)
        key = shield.dye(request, "settings_secret")
        # Bait: looks like a key someone forgot to remove. Real users never see or use it.
        return f"<html><body><h1>Settings for {email}</h1><!-- legacy_signing_key={key} TODO remove --></body></html>"

    @app.get("/api/orders")
    def orders(session: str | None = Cookie(default=None)):
        require_staff(session)
        return {"orders": [{"id": 5001, "status": "out_for_delivery"}]}

    @app.get("/api/customers")
    def customers(request: Request, limit: int = Query(20, le=100), session: str | None = Cookie(default=None)):
        require_staff(session)
        rows = query("SELECT * FROM customers WHERE canary=0 LIMIT ?", limit)
        return {"customers": [customer_json(r, request, False) for r in rows]}

    @app.get("/api/customers/export")
    def export_customers(request: Request, limit: int = 50, include: str = ""):
        # DELIBERATE DEMO FLAW: no sign-in check, and it will happily include API keys.
        rows = query("SELECT * FROM customers ORDER BY rowid LIMIT ?", limit)
        return {"customers": [customer_json(r, request, include == "api_key") for r in rows]}

    @app.get("/api/customers/{customer_id}")
    def customer(customer_id: int, request: Request):
        rows = query("SELECT * FROM customers WHERE id=?", customer_id)
        if not rows:
            raise HTTPException(404, "Not found")
        return customer_json(rows[0], request, False)

    @app.get("/api/profile")
    def profile(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        key = x_api_key or (authorization or "").removeprefix("Bearer ").strip()
        rows = query("SELECT id, name FROM customers WHERE api_key=? AND canary=0", key) if key else []
        if not rows:
            return JSONResponse({"detail": "Invalid API key"}, status_code=401)
        return {"id": rows[0]["id"], "name": rows[0]["name"]}

    return app
