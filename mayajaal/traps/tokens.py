"""Signed honeytokens. A token proves itself fake with an HMAC, so there is no list of
bait to steal and checking one needs no database. Only the holder of the key can tell
them apart from real keys."""
from __future__ import annotations

import base64
import hashlib
import hmac

SIG_BYTES = 10
NONCE_BYTES = 9


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=").lower()


def _unb32(text: str) -> bytes:
    return base64.b32decode(text.upper() + "=" * (-len(text) % 8))


def mint(secret: bytes, trap_code: int, instance: str, prefix: str) -> str:
    """Deterministic per (trap, instance) so tokens survive restarts and verification copies."""
    nonce = hmac.new(secret, f"nonce:{trap_code}:{instance}".encode(), hashlib.sha256).digest()[:NONCE_BYTES]
    payload = bytes([trap_code]) + nonce
    sig = hmac.new(secret, payload, hashlib.sha256).digest()[:SIG_BYTES]
    return prefix + _b32(payload + sig)


def verify(secret: bytes, token: str, prefix: str) -> int | None:
    """Return the trap code if this is one of our honeytokens, otherwise None."""
    if not token or not token.startswith(prefix) or len(token) > 128:
        return None
    try:
        raw = _unb32(token[len(prefix):])
    except Exception:
        return None
    if len(raw) != 1 + NONCE_BYTES + SIG_BYTES:
        return None
    payload, sig = raw[: 1 + NONCE_BYTES], raw[1 + NONCE_BYTES:]
    expected = hmac.new(secret, payload, hashlib.sha256).digest()[:SIG_BYTES]
    return payload[0] if hmac.compare_digest(sig, expected) else None
