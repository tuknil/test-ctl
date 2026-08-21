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
    model_provider: str = "none"
    model_name: str = "not-configured"
    openai_api_key: str | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str | None = None
    # AT&T Inference is configured as an OpenAI-compatible endpoint. Keep the
    # endpoint and key separate from public OpenAI settings so deployments can
    # use an internal gateway without exposing credentials to the UI.
    att_inference_base_url: str | None = None
    att_inference_api_key: str | None = None
    model_request_timeout_seconds: int = 60
    enable_docs: bool = True
    host: str = "0.0.0.0"
    port: int = 8000

    @property
    def is_live(self) -> bool:
        return self.run_mode.lower() == "live"

    @property
    def normalized_model_provider(self) -> str:
        return self.model_provider.strip().lower()

    @property
    def is_att_inference(self) -> bool:
        return self.normalized_model_provider in {"att", "att-inference"}

    @property
    def credentials_configured(self) -> bool:
        """Whether the selected live provider has its required settings.

        This intentionally returns only a boolean: API keys are never exposed
        in status endpoints, logs, result envelopes, or the browser UI.
        """
        if self.is_att_inference:
            return bool(self.att_inference_base_url and self.att_inference_api_key)
        if self.normalized_model_provider == "azure-openai":
            return bool(self.azure_openai_endpoint and self.azure_openai_api_key)
        return bool(self.openai_api_key)

    @property
    def configuration_errors(self) -> list[str]:
        """Return safe configuration errors without including secret values."""
        errors: list[str] = []
        normalized_mode = self.run_mode.strip().lower()
        if normalized_mode not in {"fixture", "live"}:
            errors.append("RUN_MODE must be either 'fixture' or 'live'.")
        if not 1 <= self.port <= 65535:
            errors.append("PORT must be between 1 and 65535.")
        if not 1 <= self.model_request_timeout_seconds <= 300:
            errors.append("MODEL_REQUEST_TIMEOUT_SECONDS must be between 1 and 300.")
        if normalized_mode == "live":
            if self.normalized_model_provider in {"", "none"}:
                errors.append("MODEL_PROVIDER is required when RUN_MODE=live.")
            if self.model_name.strip().lower() in {"", "not-configured"}:
                errors.append("MODEL_NAME is required when RUN_MODE=live.")
            if not self.credentials_configured:
                errors.append(
                    "The selected live model provider is missing required credentials or endpoint settings."
                )
        return errors

    @property
    def ready(self) -> bool:
        return not self.configuration_errors


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
        att_inference_base_url=os.getenv("ATT_INFERENCE_BASE_URL") or None,
        att_inference_api_key=os.getenv("ATT_INFERENCE_API_KEY") or None,
        model_request_timeout_seconds=int(
            os.getenv("MODEL_REQUEST_TIMEOUT_SECONDS", "60")
        ),
        enable_docs=os.getenv("ENABLE_DOCS", "true").strip().lower()
        in {"1", "true", "yes", "on"},
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
    )
