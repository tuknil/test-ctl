"""Typed settings loaded from environment / .env file.

Never hardcode secrets. `python-dotenv` loads a local `.env` file if present;
in containerized/live deployment the real environment variables take
precedence over any `.env` file.
"""

from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import BaseModel


load_dotenv(override=False)


class Settings(BaseModel):
    run_mode: str = "fixture"  # "fixture" | "live"
    model_provider: str = "openai"
    model_name: str = "gpt-4o-mini"
    openai_api_key: str | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str | None = None
    host: str = "0.0.0.0"
    port: int = 8000

    @property
    def is_live(self) -> bool:
        return self.run_mode.lower() == "live"


@lru_cache
def get_settings() -> Settings:
    return Settings(
        run_mode=os.getenv("RUN_MODE", "fixture"),
        model_provider=os.getenv("MODEL_PROVIDER", "openai"),
        model_name=os.getenv("MODEL_NAME", "gpt-4o-mini"),
        openai_api_key=os.getenv("OPENAI_API_KEY") or None,
        azure_openai_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT") or None,
        azure_openai_api_key=os.getenv("AZURE_OPENAI_API_KEY") or None,
        azure_openai_api_version=os.getenv("AZURE_OPENAI_API_VERSION") or None,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
    )
