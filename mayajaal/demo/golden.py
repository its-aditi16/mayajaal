"""Normal traffic for the verification copy. A fix must leave every one of these untouched.
A real deployment would record this from its own users and integrations."""
from __future__ import annotations

from ..prove import GoldenRequest
from .app import DEMO_PASSWORD, STAFF_EMAIL

CHROME = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "accept-language": "en-IN,en;q=0.9",
}
SAFARI = {
    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "accept-language": "hi-IN,hi;q=0.9,en;q=0.8",
}
# A legitimate script: it stops any fix that blocks "everything that looks like a Python client".
INVENTORY_SYNC = {"user-agent": "python-httpx/0.28.1", "accept": "application/json"}

GOLDEN: list[GoldenRequest] = [
    GoldenRequest("shopper", "GET", "/", CHROME, 200),
    GoldenRequest("shopper", "GET", "/static/app.css", CHROME, 200),
    GoldenRequest("shopper", "GET", "/static/app.js", CHROME, 200),
    GoldenRequest("shopper", "GET", "/products", CHROME, 200),
    GoldenRequest("mobile", "GET", "/", SAFARI, 200),
    GoldenRequest("mobile", "GET", "/products", SAFARI, 200),
    GoldenRequest("sync", "GET", "/healthz", INVENTORY_SYNC, 200),
    GoldenRequest("sync", "GET", "/products", INVENTORY_SYNC, 200),
    GoldenRequest("staff", "POST", "/api/login", CHROME, 200, json={"email": STAFF_EMAIL, "password": DEMO_PASSWORD}),
    GoldenRequest("staff", "GET", "/account", CHROME, 200),
    GoldenRequest("staff", "GET", "/settings", CHROME, 200),
    GoldenRequest("staff", "GET", "/api/orders", CHROME, 200),
    GoldenRequest("staff", "GET", "/api/customers", CHROME, 200, query="limit=20"),
    GoldenRequest("staff", "GET", "/api/customers/export", CHROME, 200, query="limit=50"),
    GoldenRequest("staff", "GET", "/api/customers/1003", CHROME, 200),
]
