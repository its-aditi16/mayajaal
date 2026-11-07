"""The trap catalogue. Fixed, reviewed code: AI may suggest a new trap to a person,
but it can never add, move or disable one."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Trap:
    id: str
    code: int
    kind: str
    title: str
    path: str | None = None


TRAPS: tuple[Trap, ...] = (
    Trap("env_file", 1, "secret", "Fake secret key in an exposed settings file", "/.env"),
    Trap("settings_secret", 2, "secret", "Fake signing key hidden in the settings page"),
    Trap("admin_console", 3, "page", "Hidden admin page nothing links to", "/internal/admin-console"),
    Trap("canary_record", 4, "data", "Fake customer record inside the real database"),
    Trap("vault_decoy", 5, "vault", "Fake key in the key vault", "/api/vault/keys/payments-master"),
    Trap("mcp_decoy", 6, "ai_tool", "Decoy tool inside the company AI assistant"),
    Trap("site_decoy", 7, "site", "Decoy made to fit this website, approved by a person"),
)

BY_ID = {t.id: t for t in TRAPS}
BY_CODE = {t.code: t for t in TRAPS}
BY_PATH = {t.path: t for t in TRAPS if t.path}
