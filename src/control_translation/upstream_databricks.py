"""Databricks SQL reader for authoritative upstream capability results."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any, Protocol
from time import perf_counter

from control_translation.contracts import DatabricksResultReference
from control_translation.upstream import (
    UpstreamRecord,
    UpstreamResolutionError,
    decode_json_object,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")
logger = logging.getLogger(__name__)


class _Cursor(Protocol):
    def execute(self, operation: str, parameters: tuple[Any, ...] | None = None) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    def close(self) -> None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...
    def close(self) -> None: ...


ConnectionFactory = Callable[[], _Connection]


class DatabricksUpstreamResultResolver:
    """Read exactly one record from each caller-authorized Databricks reference."""

    def __init__(
        self,
        *,
        server_hostname: str,
        http_path: str,
        auth_type: str = "oauth-m2m",
        token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._server_hostname = server_hostname.strip()
        self._http_path = http_path.strip()
        self._auth_type = auth_type.strip().lower()
        self._token = token
        self._client_id = client_id.strip() if client_id else None
        self._client_secret = client_secret
        if self._auth_type not in {"oauth-m2m", "pat"}:
            raise ValueError("Invalid Databricks authentication type.")
        self._connection_factory = connection_factory or self._default_connection

    def fetch(self, reference: DatabricksResultReference) -> UpstreamRecord | None:
        coordinates = (
            reference.catalog,
            reference.schema_name,
            reference.table,
        )
        table_name = ".".join(
            _quote_identifier(value, label)
            for value, label in (
                (reference.catalog, "catalog"),
                (reference.schema_name, "schema"),
                (reference.table, "table"),
            )
        )
        if reference.key.startswith("defense-generation-result:"):
            expected_coordinates = (
                "36889_janus_dev",
                "defense_generation",
                "defense_generation_results",
            )
            operation = f"""
                SELECT result_id, terminal_state, TO_JSON(request_json),
                       TO_JSON(result_json)
                FROM {table_name}
                WHERE result_id = ?
                LIMIT 2
            """
            shape = "defense"
        elif reference.key.startswith("mitigation-check-result:"):
            expected_coordinates = (
                "36889_janus_dev",
                "mitigation-check",
                "mitigation_check",
            )
            operation = f"""
                SELECT result_id, result_json
                FROM {table_name}
                WHERE result_id = ?
                LIMIT 2
            """
            shape = "mitigation"
        elif reference.key.startswith("bypass-validation-result:"):
            expected_coordinates = (
                "36889_janus_dev",
                "bypass_validation",
                "bypass_validation_results",
            )
            operation = f"""
                SELECT result_id, terminal_state, correlation_id,
                       request_json, result_json
                FROM {table_name}
                WHERE result_id = ?
                LIMIT 2
            """
            shape = "bypass"
        else:
            raise ValueError("Unsupported upstream result-reference key")
        if coordinates != expected_coordinates:
            raise ValueError(
                f"{shape} result reference does not match the approved table"
            )
        connection: _Connection | None = None
        cursor: _Cursor | None = None
        started = perf_counter()
        logger.info(
            "Upstream Databricks read started shape=%s table=%s result_id=%s",
            shape,
            table_name,
            reference.key,
        )
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            cursor.execute(operation, (reference.key,))
            rows = cursor.fetchall()
            if len(rows) > 1:
                raise UpstreamResolutionError(
                    f"{shape} result reference resolved to multiple rows"
                )
            row = rows[0] if rows else None
            logger.info(
                "Upstream Databricks read completed shape=%s table=%s "
                "result_id=%s found=%s duration_ms=%.2f",
                shape,
                table_name,
                reference.key,
                row is not None,
                (perf_counter() - started) * 1000,
            )
        except Exception as exc:
            logger.exception(
                "Upstream Databricks read failed shape=%s table=%s result_id=%s "
                "duration_ms=%.2f error_type=%s error_code=%s sql_state=%s",
                shape,
                table_name,
                reference.key,
                (perf_counter() - started) * 1000,
                type(exc).__name__,
                getattr(exc, "error_code", None) or "-",
                getattr(exc, "sql_state", None) or "-",
            )
            raise
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    logger.warning(
                        "Upstream Databricks cursor close failed table=%s",
                        table_name,
                        exc_info=True,
                    )
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    logger.warning(
                        "Upstream Databricks connection close failed table=%s",
                        table_name,
                        exc_info=True,
                    )
        if row is None:
            return None
        if shape == "defense":
            request = decode_json_object(row[2], "Defense Generation request_json")
            result = decode_json_object(row[3], "Defense Generation result_json")
            terminal_state = row[1]
            correlation_id = _find_one(result, request, key="correlation_id")
            subject_revision = _find_one(
                result, request, key="subject_record_revision_id"
            )
        elif shape == "mitigation":
            request = {}
            result = decode_json_object(row[1], "Mitigation Check result_json")
            terminal_state = result.get("terminal_state")
            correlation_id = result.get("correlation_id")
            subject_revision = _find_one(
                result, key="subject_record_revision_id"
            )
        else:
            request = decode_json_object(row[3], "Bypass Validation request_json")
            result = decode_json_object(row[4], "Bypass Validation result_json")
            terminal_state = row[1] or result.get("terminal_state")
            correlation_id = row[2] or _find_one(
                result, request, key="correlation_id"
            )
            subject_revision = _find_one(
                result, request, key="subject_record_revision_id"
            )
        return UpstreamRecord(
            result_id=row[0],
            terminal_state=str(terminal_state or ""),
            correlation_id=(
                str(correlation_id) if isinstance(correlation_id, str) else None
            ),
            subject_record_revision_id=subject_revision,
            request=request,
            result=result,
        )

    def _default_connection(self) -> _Connection:
        from databricks import sql

        if self._auth_type == "pat":
            if not self._token:
                raise RuntimeError("Databricks PAT configuration is incomplete")
            return sql.connect(
                server_hostname=self._server_hostname,
                http_path=self._http_path,
                access_token=self._token,
            )

        from databricks.sdk.core import Config, oauth_service_principal

        if not self._client_id or not self._client_secret:
            raise RuntimeError("Databricks OAuth configuration is incomplete")
        config = Config(
            host=f"https://{self._server_hostname}",
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        return sql.connect(
            server_hostname=self._server_hostname,
            http_path=self._http_path,
            credentials_provider=lambda: oauth_service_principal(config),
        )


def create_upstream_result_resolver(settings: Any) -> DatabricksUpstreamResultResolver | None:
    """Create a reader when Databricks connection settings are available."""
    if not settings.databricks_server_hostname or not settings.databricks_http_path:
        return None
    auth_type = settings.normalized_databricks_auth_type
    if auth_type == "pat" and not settings.databricks_token:
        return None
    if auth_type == "oauth-m2m" and (
        not settings.databricks_client_id or not settings.databricks_client_secret
    ):
        return None
    return DatabricksUpstreamResultResolver(
        server_hostname=settings.databricks_server_hostname,
        http_path=settings.databricks_http_path,
        auth_type=auth_type,
        token=settings.databricks_token,
        client_id=settings.databricks_client_id,
        client_secret=settings.databricks_client_secret,
    )


def _quote_identifier(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"Invalid Databricks {label} identifier.")
    return f"`{normalized}`"


def _find_one(*documents: Any, key: str) -> str | None:
    values: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if child_key == key and isinstance(child_value, str) and child_value:
                    values.add(child_value)
                visit(child_value)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for document in documents:
        visit(document)
    return next(iter(values)) if len(values) == 1 else None
