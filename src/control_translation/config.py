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
    persistence_backend: str = "sqlite"
    database_path: str = "/app/data/control_translation.db"
    service_replica_count: int = 1
    databricks_server_hostname: str | None = None
    databricks_http_path: str | None = None
    databricks_auth_type: str = "oauth-m2m"
    databricks_token: str | None = None
    databricks_client_id: str | None = None
    databricks_client_secret: str | None = None
    databricks_catalog: str = "36889_janus_dev"
    databricks_schema: str = "control_translation"
    databricks_results_table: str = "control_translation_results"
    worker_poll_seconds: float = 0.25
    worker_lease_seconds: int = 30
    worker_heartbeat_seconds: float = 5.0
    worker_max_attempts: int = 3
    worker_shutdown_grace_seconds: float = 2.0
    capability_callback_token: str | None = None
    capability_callback_allowed_hosts: tuple[str, ...] = ()
    capability_callback_timeout_seconds: float = 10.0
    capability_callback_poll_interval_seconds: float = 1.0
    default_target_technology: str = "akamai-waf"
    default_target_policy_context_id: str = "akamai-policy:example:rev-17"

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
    def normalized_persistence_backend(self) -> str:
        return self.persistence_backend.strip().lower()

    @property
    def normalized_databricks_auth_type(self) -> str:
        return self.databricks_auth_type.strip().lower()

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
        if self.worker_poll_seconds <= 0:
            errors.append("WORKER_POLL_SECONDS must be greater than zero.")
        if self.worker_lease_seconds < 2:
            errors.append("WORKER_LEASE_SECONDS must be at least 2.")
        if not 0 < self.worker_heartbeat_seconds < self.worker_lease_seconds:
            errors.append("WORKER_HEARTBEAT_SECONDS must be positive and shorter than the lease.")
        if self.worker_max_attempts < 1:
            errors.append("WORKER_MAX_ATTEMPTS must be at least 1.")
        if self.capability_callback_timeout_seconds <= 0:
            errors.append("CAPABILITY_CALLBACK_TIMEOUT_SECONDS must be greater than zero.")
        if self.capability_callback_poll_interval_seconds <= 0:
            errors.append(
                "CAPABILITY_CALLBACK_POLL_INTERVAL_SECONDS must be greater than zero."
            )
        if self.normalized_persistence_backend not in {"sqlite", "databricks"}:
            errors.append("PERSISTENCE_BACKEND must be either 'sqlite' or 'databricks'.")
        if self.service_replica_count != 1:
            errors.append(
                "SERVICE_REPLICA_COUNT must be 1 while lifecycle state uses SQLite."
            )
        if self.normalized_persistence_backend == "databricks":
            required_databricks_settings = {
                "DATABRICKS_SERVER_HOSTNAME": self.databricks_server_hostname,
                "DATABRICKS_HTTP_PATH": self.databricks_http_path,
                "DATABRICKS_CATALOG": self.databricks_catalog,
                "DATABRICKS_SCHEMA": self.databricks_schema,
                "DATABRICKS_RESULTS_TABLE": self.databricks_results_table,
            }
            if self.normalized_databricks_auth_type == "pat":
                required_databricks_settings["DATABRICKS_TOKEN"] = (
                    self.databricks_token
                )
            elif self.normalized_databricks_auth_type == "oauth-m2m":
                required_databricks_settings.update(
                    {
                        "DATABRICKS_CLIENT_ID": self.databricks_client_id,
                        "DATABRICKS_CLIENT_SECRET": self.databricks_client_secret,
                    }
                )
            else:
                errors.append(
                    "DATABRICKS_AUTH_TYPE must be either 'oauth-m2m' or 'pat'."
                )
            missing = [
                name for name, value in required_databricks_settings.items()
                if not value or not value.strip()
            ]
            if missing:
                errors.append(
                    "Databricks persistence is missing required settings: "
                    + ", ".join(missing)
                    + "."
                )
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
        persistence_backend=os.getenv("PERSISTENCE_BACKEND", "sqlite"),
        database_path=os.getenv(
            "DATABASE_PATH", "/app/data/control_translation.db"
        ),
        service_replica_count=int(os.getenv("SERVICE_REPLICA_COUNT", "1")),
        databricks_server_hostname=os.getenv("DATABRICKS_SERVER_HOSTNAME") or None,
        databricks_http_path=os.getenv("DATABRICKS_HTTP_PATH") or None,
        databricks_auth_type=os.getenv("DATABRICKS_AUTH_TYPE", "oauth-m2m"),
        databricks_token=os.getenv("DATABRICKS_TOKEN") or None,
        databricks_client_id=os.getenv("DATABRICKS_CLIENT_ID") or None,
        databricks_client_secret=os.getenv("DATABRICKS_CLIENT_SECRET") or None,
        databricks_catalog=os.getenv("DATABRICKS_CATALOG", "36889_janus_dev"),
        databricks_schema=os.getenv("DATABRICKS_SCHEMA", "control_translation"),
        databricks_results_table=os.getenv(
            "DATABRICKS_RESULTS_TABLE", "control_translation_results"
        ),
        worker_poll_seconds=float(os.getenv("WORKER_POLL_SECONDS", "0.25")),
        worker_lease_seconds=int(os.getenv("WORKER_LEASE_SECONDS", "30")),
        worker_heartbeat_seconds=float(
            os.getenv("WORKER_HEARTBEAT_SECONDS", "5")
        ),
        worker_max_attempts=int(os.getenv("WORKER_MAX_ATTEMPTS", "3")),
        worker_shutdown_grace_seconds=float(
            os.getenv("WORKER_SHUTDOWN_GRACE_SECONDS", "2")
        ),
        capability_callback_token=os.getenv("CAPABILITY_CALLBACK_TOKEN") or None,
        capability_callback_allowed_hosts=tuple(
            host.strip().lower()
            for host in os.getenv("CAPABILITY_CALLBACK_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        ),
        capability_callback_timeout_seconds=float(
            os.getenv("CAPABILITY_CALLBACK_TIMEOUT_SECONDS", "10")
        ),
        capability_callback_poll_interval_seconds=float(
            os.getenv("CAPABILITY_CALLBACK_POLL_INTERVAL_SECONDS", "1")
        ),
        default_target_technology=os.getenv(
            "DEFAULT_TARGET_TECHNOLOGY", "akamai-waf"
        ),
        default_target_policy_context_id=os.getenv(
            "DEFAULT_TARGET_POLICY_CONTEXT_ID", "akamai-policy:example:rev-17"
        ),
    )
