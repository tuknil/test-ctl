"""Persistence backend selection."""

from __future__ import annotations

from control_translation.config import Settings
from control_translation.persistence.base import PersistenceError, RunRepository
from control_translation.persistence.databricks import DatabricksRunRepository
from control_translation.persistence.split import SplitRunRepository
from control_translation.persistence.sqlite import SQLiteRunRepository


def create_run_repository(settings: Settings) -> RunRepository:
    """Build the configured repository without exposing configuration values."""
    backend = settings.normalized_persistence_backend
    if backend == "sqlite":
        return SQLiteRunRepository(settings.database_path)
    if backend == "databricks":
        common_required = (
            settings.databricks_server_hostname,
            settings.databricks_http_path,
        )
        auth_type = settings.normalized_databricks_auth_type
        if auth_type == "pat":
            auth_required = (settings.databricks_token,)
        elif auth_type == "oauth-m2m":
            auth_required = (
                settings.databricks_client_id,
                settings.databricks_client_secret,
            )
        else:
            raise PersistenceError("Unsupported Databricks authentication type.")
        if any(
            not value or not value.strip()
            for value in common_required + auth_required
        ):
            raise PersistenceError(
                "Databricks persistence configuration is incomplete."
            )
        result_sink = DatabricksRunRepository(
            server_hostname=settings.databricks_server_hostname or "",
            http_path=settings.databricks_http_path or "",
            auth_type=auth_type,
            token=settings.databricks_token,
            client_id=settings.databricks_client_id,
            client_secret=settings.databricks_client_secret,
            catalog=settings.databricks_catalog,
            schema=settings.databricks_schema,
            table=settings.databricks_results_table,
        )
        return SplitRunRepository(
            SQLiteRunRepository(settings.database_path),
            result_sink,
        )
    raise PersistenceError("Unsupported persistence backend configuration.")
