"""Mayajaal: a honeypot with memory."""
from __future__ import annotations

__version__ = "0.1.0"


def protect(app, route_tags: dict[str, str] | None = None, extra_trap_paths: dict[str, str] | None = None,
            settings=None):
    """Add Mayajaal to a FastAPI app: traps, activity log and enforcement of approved blocks.

    route_tags says which of your routes matter, for example
    {"/api/customers": "data", "/api/login": "credential", "/account": "user"}.
    Digits in a path become :id, so /api/customers/42 is tagged as "/api/customers/:id".
    """
    from .bus import Bus
    from .config import Settings
    from .shield import install
    from .store import Store

    settings = settings or Settings()
    store = Store(settings.db_path)
    return install(app, settings, store, Bus(settings, store), route_tags, extra_trap_paths)
