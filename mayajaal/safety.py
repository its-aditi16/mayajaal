"""Screens attacker-written text before the defender's AI reads it.
Local patterns always run. Azure Prompt Shields runs on top when configured. If Azure fails,
screening falls back to the local patterns and the report says so."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from .config import Settings

log = logging.getLogger("mayajaal.safety")
REMOVED = "[removed: prompt injection attempt]"
AZURE_API_VERSION = "2024-09-01"
AZURE_DOCS_PER_CALL = 5

INJECTION = re.compile(
    r"(?is)"
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+\w*"
    r"|disregard\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|instructions|rules)"
    r"|forget\s+(?:all\s+|your\s+|the\s+)?(?:previous|instructions|rules)"
    r"|(?:system|developer)\s*(?:prompt|message|instructions?)"
    r"|you\s+are\s+now\b"
    r"|new\s+instructions?\s*:"
    r"|(?:mark|classify|label|treat|report)\b.{0,40}\b(?:benign|safe|harmless|false\s+positive|authori[sz]ed|legitimate)"
    r"|(?:do\s+not|don'?t|never)\s+(?:block|report|alert|flag)"
    r"|(?:approve|whitelist|allowlist|unblock)\b.{0,40}\b(?:this|me|request|ip|actor|rule)"
    r"|<\|?(?:im_start|im_end|system|assistant)\|?>"
    r"|\[/?(?:inst|sys)\]"
)


@dataclass
class ScreenResult:
    texts: list[str]
    flagged: int
    backend: str


class PromptScreen:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.endpoint = settings.content_safety_endpoint.rstrip("/")
        self.key = settings.content_safety_key
        self.client = client or httpx.Client(timeout=10)

    @property
    def backend(self) -> str:
        return "azure-prompt-shields+local" if self.endpoint and self.key else "local-patterns"

    def _azure_flags(self, texts: list[str]) -> list[bool]:
        flags: list[bool] = []
        for start in range(0, len(texts), AZURE_DOCS_PER_CALL):
            chunk = texts[start:start + AZURE_DOCS_PER_CALL]
            response = self.client.post(
                f"{self.endpoint}/contentsafety/text:shieldPrompt",
                params={"api-version": AZURE_API_VERSION},
                headers={"Ocp-Apim-Subscription-Key": self.key},
                json={"userPrompt": "", "documents": chunk},
            )
            response.raise_for_status()
            analysis = response.json()["documentsAnalysis"]
            if len(analysis) != len(chunk):
                raise ValueError("Prompt Shields returned a different number of results")
            flags.extend(bool(item["attackDetected"]) for item in analysis)
        return flags

    def screen(self, texts: list[str]) -> ScreenResult:
        local = [bool(INJECTION.search(t)) for t in texts]
        backend = self.backend
        remote = [False] * len(texts)
        if self.endpoint and self.key and texts:
            try:
                remote = self._azure_flags(texts)
            except Exception as exc:
                log.warning("Prompt Shields failed (%s); using local patterns only", exc)
                backend = "local-patterns (azure call failed)"
        flags = [a or b for a, b in zip(local, remote)]
        return ScreenResult(
            texts=[REMOVED if flag else text for text, flag in zip(texts, flags)],
            flagged=sum(flags), backend=backend,
        )
