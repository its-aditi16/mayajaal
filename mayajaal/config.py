"""Runtime settings. Every optional integration is off until configured, so the
core (traps, detection, verification, blocking) always works with no cloud at all."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MAYAJAAL_", env_file=".env", extra="ignore")

    # Kept outside the project by default: SQLite WAL files and OneDrive sync do not mix.
    data_dir: Path = Path.home() / ".mayajaal"
    secret_key: str = ""
    admin_token: str = ""
    token_prefix: str = "kc_live_"

    # Only enable behind a proxy you control: otherwise clients can forge their IP.
    trust_forwarded_for: bool = False
    # Set only inside the throwaway verification copy. Never in production.
    sandbox_mode: bool = False
    sandbox_rules: str = "[]"

    redis_url: str = ""

    # Pipeline timing
    settle_seconds: float = 2.0
    shadow_seconds: float = 10.0
    shadow_seconds_proven: float = 2.0
    rewind_window_seconds: float = 3600.0
    retention_days: int = 30
    reflect_every: int = 3
    public_base_url: str = "http://127.0.0.1:8100"

    # The app being protected: a factory taking optional settings, and its normal traffic.
    target_app: str = "mayajaal.demo.app:create_app"
    target_golden: str = "mayajaal.demo.golden:GOLDEN"
    # Website-specific decoys from `mayajaal suggest-traps`, after a person has reviewed them.
    decoys_file: str = ""
    control_host: str = "127.0.0.1"
    control_port: int = 8100

    # Verification copy: auto | docker | inprocess
    sandbox_backend: str = "auto"
    sandbox_image: str = "mayajaal:latest"

    # Memory: auto | hindsight | local | off (off exists to show the difference memory makes)
    memory_backend: str = "auto"
    hindsight_url: str = "http://localhost:8888"
    hindsight_api_key: str = ""
    hindsight_bank: str = "mayajaal-attacks"
    # concise = the LLM extracts facts on every retain: richest, but needs a fast cloud model.
    # chunks = stores and searches the text with no LLM on retain: works on a laptop CPU.
    hindsight_extraction_mode: str = "chunks"
    hindsight_reflect_timeout: float = 120.0

    # Defender AI: auto | foundry | groq | ollama | none
    llm_provider: str = "auto"
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"
    foundry_endpoint: str = ""
    foundry_api_key: str = ""
    foundry_model: str = ""
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    llm_timeout_seconds: float = 120.0

    # Azure AI Content Safety (Prompt Shields)
    content_safety_endpoint: str = ""
    content_safety_key: str = ""

    # Alerts
    teams_webhook_url: str = ""
    sentinel_tenant_id: str = ""
    sentinel_client_id: str = ""
    sentinel_client_secret: str = ""
    sentinel_dce_endpoint: str = ""
    sentinel_dcr_id: str = ""
    sentinel_stream: str = "Custom-Mayajaal_CL"

    def _persisted_secret(self, filename: str) -> str:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.data_dir / filename
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        value = secrets.token_urlsafe(32)
        path.write_text(value, encoding="utf-8")
        os.chmod(path, 0o600)
        return value

    @property
    def secret(self) -> bytes:
        return (self.secret_key or self._persisted_secret("secret.key")).encode()

    @property
    def admin(self) -> str:
        return self.admin_token or self._persisted_secret("admin.token")

    @property
    def db_path(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "mayajaal.db"
