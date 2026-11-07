"""Data minimisation: mask personal data before it is stored, remembered or sent to an AI."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[\w.+-]+(?:@|%40)[\w-]+(?:\.[\w-]+)+"), "[email]"),
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[card]"),
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[aadhaar]"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[pan]"),
    (re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9]\d{9}(?!\d)"), "[phone]"),
    (re.compile(r"(?i)(password|passwd|pwd)(\"?\s*[:=]\s*\"?)[^\s\"&,}]+"), r"\1\2[secret]"),
]


def mask(text: str | None) -> str:
    if not text:
        return ""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def keyed_hash(secret: bytes, value: str) -> str:
    """Keyed so stored hashes cannot be reversed by guessing IPs or tokens."""
    return hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()[:24]


def mask_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.version == 4:
        return ".".join(ip.split(".")[:3]) + ".x"
    return addr.exploded.rsplit(":", 5)[0] + ":x"
