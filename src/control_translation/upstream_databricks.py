"""Databricks SQL reader for authoritative upstream capability results."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from time import perf_counter
from typing import Any, Protocol

from control_translation.cancellation import CancellationSignal, check_cancelled
from control_translation.contracts import (
    DatabricksResultReference,
    OrchestrationUpstreamInput,
)
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
VolumeReader = Callable[[str, int], bytes]

_MAX_UPSTREAM_RESULT_BYTES = 200 * 1024 * 1024
_PAYLOAD_MANIFEST_TYPE = "janus-volume-payload-manifest"
_PAYLOAD_REFERENCE = re.compile(r"^payload://sha256/([a-f0-9]{64})$")

_GoField = tuple[str, "_GoSchema | None", str | None]
_GoSchema = tuple[_GoField, ...]


def _field(
    name: str,
    schema: _GoSchema | None = None,
    omit_empty: str | None = None,
) -> _GoField:
    return name, schema, omit_empty


_RESULT_REF_SCHEMA: _GoSchema = (
    _field("system"),
    _field("catalog", omit_empty="string"),
    _field("schema", omit_empty="string"),
    _field("table"),
    _field("key"),
)

_DEFENSE_OUTCOME_REASON_SCHEMA: _GoSchema = (
    _field("code"),
    _field("detail"),
    _field("unresolved_payload", omit_empty="string"),
    _field("encoding_kind", omit_empty="string"),
    _field("uncovered_required_form", omit_empty="string"),
    _field("rejection_reason", omit_empty="string"),
    _field("repeated_functional_fingerprint", omit_empty="string"),
)
_DEFENSE_COLLATERAL_PRIOR_SCHEMA: _GoSchema = (
    _field("verdict"),
    _field("confidence"),
    _field("basis"),
    _field("gaps"),
    _field("measured"),
)
_DEFENSE_CANDIDATE_SCHEMA: _GoSchema = (
    _field("candidate_id"),
    _field("selected_control_class"),
    _field("candidate_kind"),
    _field("mitigation_intent"),
    _field("discriminator"),
    _field("expected_block_behavior"),
    _field("expected_allow_behavior"),
    _field("artifact_type"),
    _field("artifact_content"),
    _field("artifact_hash"),
    _field("collateral_impact_prior", _DEFENSE_COLLATERAL_PRIOR_SCHEMA),
    _field("assumptions"),
    _field("limitations"),
    _field("evidence_refs"),
)
_DEFENSE_PROOF_HANDOFF_SCHEMA: _GoSchema = (
    _field("capability"),
    _field("contract_id"),
    _field("substrate"),
    _field("candidate_ref", _RESULT_REF_SCHEMA),
    _field("evidence_refs", omit_empty="slice"),
)
_DEFENSE_ATTEMPT_SCHEMA: _GoSchema = (
    _field("candidate_id"),
    _field("outcome"),
    _field("feedback_refs"),
    _field("do_not_repeat_constraints"),
)
_DEFENSE_UPSTREAM_REF_SCHEMA: _GoSchema = (
    _field("capability"),
    _field("contract_id"),
    _field("request_id", omit_empty="string"),
    _field("correlation_id", omit_empty="string"),
    _field("run_id", omit_empty="string"),
    _field("result_id"),
    _field("terminal_state", omit_empty="string"),
    _field("status", omit_empty="string"),
    _field("result_ref", _RESULT_REF_SCHEMA),
    _field("evidence_refs", omit_empty="slice"),
    _field("content_sha256", omit_empty="string"),
    _field("size_bytes", omit_empty="number"),
    _field("created_at", omit_empty="time"),
)
_DEFENSE_RESULT_SCHEMA: _GoSchema = (
    _field("capability"),
    _field("contract_id"),
    _field("request_id"),
    _field("correlation_id"),
    _field("run_id"),
    _field("result_id"),
    _field("status"),
    _field("terminal_state"),
    _field("result_ref", _RESULT_REF_SCHEMA, "pointer"),
    _field("evidence_refs"),
    _field("outcome_reason", _DEFENSE_OUTCOME_REASON_SCHEMA),
    _field("primary_candidate", _DEFENSE_CANDIDATE_SCHEMA, "pointer"),
    _field("proof_handoffs", _DEFENSE_PROOF_HANDOFF_SCHEMA, "slice"),
    _field("attempt_history", _DEFENSE_ATTEMPT_SCHEMA),
    _field("prose_summary"),
    _field("request_digest"),
    _field("upstream_result_refs", _DEFENSE_UPSTREAM_REF_SCHEMA),
    _field("content_sha256", omit_empty="string"),
    _field("size_bytes", omit_empty="number"),
    _field("created_at"),
)

_MITIGATION_LOCATOR_SCHEMA: _GoSchema = (
    _field("capability"),
    _field("contract_id"),
    _field("request_id"),
    _field("correlation_id"),
    _field("run_id"),
    _field("result_id"),
    _field("status"),
    _field("terminal_state"),
    _field("result_ref", _RESULT_REF_SCHEMA),
    _field("content_sha256"),
    _field("size_bytes"),
    _field("created_at"),
)
_MITIGATION_PROVENANCE_SCHEMA: _GoSchema = (
    _field("route_policy"),
    _field("defense_result", _MITIGATION_LOCATOR_SCHEMA),
    _field("check_result", _MITIGATION_LOCATOR_SCHEMA),
    _field("selected_test_basis_id"),
    _field("verification"),
)
_MITIGATION_EXPECTED_SCHEMA: _GoSchema = (
    _field("classification"),
    _field("blocked"),
    _field("status_code"),
)
_MITIGATION_ACTUAL_SCHEMA: _GoSchema = (
    _field("blocked"),
    _field("status_code"),
    _field("reached_app"),
    _field("matched_rule_id", omit_empty="string"),
    _field("detail"),
)
_MITIGATION_SUBSTRATE_SCHEMA: _GoSchema = (
    _field("image"),
    _field("runner", omit_empty="string"),
    _field("container_id", omit_empty="string"),
    _field("host_port", omit_empty="number"),
    _field("fqdn", omit_empty="string"),
    _field("ready"),
)
_MITIGATION_CANDIDATE_SCHEMA: _GoSchema = (
    _field("kind"),
    _field("engine"),
    _field("rule_id"),
    _field("rule"),
    _field("action"),
)
_MITIGATION_REQUEST_SCHEMA: _GoSchema = (
    _field("method"),
    _field("path"),
    _field("headers"),
    _field("body"),
)
_MITIGATION_TEST_BASIS_SCHEMA: _GoSchema = (
    _field("kind"),
    _field("proof_basis"),
    _field("request", _MITIGATION_REQUEST_SCHEMA),
    _field("expected", _MITIGATION_EXPECTED_SCHEMA),
)
_MITIGATION_RESULT_SCHEMA: _GoSchema = (
    _field("capability"),
    _field("contract_id"),
    _field("request_id"),
    _field("run_id"),
    _field("result_id"),
    _field("terminal_state"),
    _field("status"),
    _field("correlation_id", omit_empty="string"),
    _field("result_ref", _RESULT_REF_SCHEMA, "pointer"),
    _field("evidence_refs"),
    _field("request_sha256"),
    _field("upstream_inputs", omit_empty="raw"),
    _field("input_provenance", _MITIGATION_PROVENANCE_SCHEMA, "pointer"),
    _field("match"),
    _field("expected", _MITIGATION_EXPECTED_SCHEMA),
    _field("actual", _MITIGATION_ACTUAL_SCHEMA),
    _field("substrate", _MITIGATION_SUBSTRATE_SCHEMA),
    _field("candidate", _MITIGATION_CANDIDATE_SCHEMA, "pointer"),
    _field("test_basis", _MITIGATION_TEST_BASIS_SCHEMA, "pointer"),
    _field("steps"),
    _field("prose_summary"),
    _field("limitations", omit_empty="slice"),
    _field("content_sha256", omit_empty="string"),
    _field("size_bytes", omit_empty="number"),
    _field("created_at"),
)


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
        volume_reader: VolumeReader | None = None,
        max_result_bytes: int = _MAX_UPSTREAM_RESULT_BYTES,
    ) -> None:
        self._server_hostname = server_hostname.strip()
        self._http_path = http_path.strip()
        self._auth_type = auth_type.strip().lower()
        self._token = token
        self._client_id = client_id.strip() if client_id else None
        self._client_secret = client_secret
        if self._auth_type not in {"oauth-m2m", "pat"}:
            raise ValueError("Invalid Databricks authentication type.")
        if max_result_bytes <= 0:
            raise ValueError("Upstream result byte limit must be positive.")
        self._connection_factory = connection_factory or self._default_connection
        self._volume_reader = volume_reader or self._default_volume_reader
        self._max_result_bytes = max_result_bytes

    def fetch(
        self,
        reference: DatabricksResultReference,
        *,
        immutable_locator: OrchestrationUpstreamInput | None = None,
        cancellation_signal: CancellationSignal | None = None,
    ) -> UpstreamRecord | None:
        check_cancelled(cancellation_signal)
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
                  SELECT run_id, result_id, terminal_state, TO_JSON(request_json),
                      TO_JSON(result_json), produced_at
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
                SELECT run_id, result_id, result_json
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
                  SELECT run_id, result_id, request_id, correlation_id,
                      capability, contract_id, terminal_state, status,
                      request_json, result_json, completion_json,
                      result_sha256, result_size_bytes, created_at
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
            check_cancelled(cancellation_signal)
            connection = self._connection_factory()
            check_cancelled(cancellation_signal)
            cursor = connection.cursor()
            check_cancelled(cancellation_signal)
            cursor.execute(operation, (reference.key,))
            check_cancelled(cancellation_signal)
            rows = cursor.fetchall()
            check_cancelled(cancellation_signal)
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
            error_type = type(exc).__name__
            error_code = getattr(exc, "error_code", None) or "-"
            sql_state = getattr(exc, "sql_state", None) or "-"
            logger.exception(
                "Upstream Databricks read failed shape=%s table=%s result_id=%s "
                "duration_ms=%.2f error_type=%s error_code=%s sql_state=%s",
                shape,
                table_name,
                reference.key,
                (perf_counter() - started) * 1000,
                error_type,
                error_code,
                sql_state,
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
            run_id, result_id, terminal_state = row[0], row[1], row[2]
            request = self._decode_payload(
                row[3],
                "Defense Generation request_json",
                shape=shape,
                approved_volume=(
                    reference.catalog,
                    reference.schema_name,
                    "payloads",
                ),
            )
            result = self._decode_payload(
                row[4],
                "Defense Generation result_json",
                shape=shape,
                approved_volume=(
                    reference.catalog,
                    reference.schema_name,
                    "payloads",
                ),
            )
            correlation_id = _find_one(result, request, key="correlation_id")
            subject_revision = _find_one(
                result, request, key="subject_record_revision_id"
            )
            completion = None
            row_created_at = row[5]
            row_digest = None
            row_size = None
        elif shape == "mitigation":
            run_id, result_id = row[0], row[1]
            request = {}
            result = self._decode_payload(
                row[2],
                "Mitigation Check result_json",
                shape=shape,
                approved_volume=(
                    reference.catalog,
                    reference.schema_name,
                    "payloads",
                ),
            )
            terminal_state = result.get("terminal_state")
            correlation_id = result.get("correlation_id")
            subject_revision = _find_one(
                result, key="subject_record_revision_id"
            )
            completion = None
            row_created_at = None
            row_digest = None
            row_size = None
        else:
            run_id, result_id = row[0], row[1]
            request = self._decode_payload(
                row[8],
                "Bypass Validation request_json",
                shape=shape,
                approved_volume=(
                    reference.catalog,
                    reference.schema_name,
                    "payloads",
                ),
            )
            result = self._decode_payload(
                row[9],
                "Bypass Validation result_json",
                shape=shape,
                approved_volume=(
                    reference.catalog,
                    reference.schema_name,
                    "payloads",
                ),
            )
            completion = decode_json_object(
                row[10], "Bypass Validation completion_json"
            )
            terminal_state = row[6] or result.get("terminal_state")
            correlation_id = row[3] or _find_one(
                result, request, key="correlation_id"
            )
            subject_revision = _find_one(
                result, request, key="subject_record_revision_id"
            )
            row_created_at = row[13]
            row_digest = row[11]
            row_size = row[12]
        self._verify_immutable_result(
            shape=shape,
            reference=reference,
            locator=immutable_locator,
            run_id=str(run_id or ""),
            result_id=str(result_id or ""),
            terminal_state=str(terminal_state or ""),
            result=result,
            completion=completion,
            row_digest=row_digest,
            row_size=row_size,
            row_created_at=row_created_at,
        )
        return UpstreamRecord(
            result_id=str(result_id),
            terminal_state=str(terminal_state or ""),
            correlation_id=(
                str(correlation_id) if isinstance(correlation_id, str) else None
            ),
            subject_record_revision_id=subject_revision,
            request=request,
            result=result,
        )

    def _decode_payload(
        self,
        value: Any,
        label: str,
        *,
        shape: str,
        approved_volume: tuple[str, str, str] | None = None,
    ) -> dict[str, Any]:
        payload = decode_json_object(value, label)
        if payload.get("contract_type") != _PAYLOAD_MANIFEST_TYPE:
            return payload
        content = self._hydrate_payload_manifest(
            payload,
            producer=label.split(" request_json", 1)[0].split(" result_json", 1)[0],
            approved_volume=approved_volume
            or (
                "36889_janus_dev",
                {
                    "defense": "defense_generation",
                    "mitigation": "mitigation-check",
                    "bypass": "bypass_validation",
                }[shape],
                "payloads",
            ),
        )
        return decode_json_object(content, f"hydrated {label}")

    def _hydrate_payload_manifest(
        self,
        manifest: dict[str, Any],
        *,
        producer: str,
        approved_volume: tuple[str, str, str],
    ) -> bytes:
        expected_keys = {
            "contract_type",
            "contract_version",
            "reference",
            "media_type",
            "encoding",
            "content_sha256",
            "size_bytes",
            "volume",
        }
        match = _PAYLOAD_REFERENCE.fullmatch(
            str(manifest.get("reference") or "")
        )
        digest = match.group(1) if match is not None else ""
        volume = manifest.get("volume")
        catalog, schema, volume_name = approved_volume
        expected_volume = {
            "catalog": catalog,
            "schema": schema,
            "name": volume_name,
        }
        size = manifest.get("size_bytes")
        if (
            set(manifest) != expected_keys
            or not digest
            or manifest.get("contract_version") != "1.0"
            or manifest.get("media_type") != "application/json"
            or manifest.get("encoding") != "identity"
            or manifest.get("content_sha256") != f"sha256:{digest}"
            or type(size) is not int
            or not 0 < size <= self._max_result_bytes
            or volume != expected_volume
        ):
            raise UpstreamResolutionError(
                f"{producer} payload manifest is invalid"
            )
        path = (
            f"/Volumes/{catalog}/{schema}/{volume_name}/sha256/"
            f"{digest[:2]}/{digest[2:4]}/{digest}"
        )
        try:
            content = self._volume_reader(path, self._max_result_bytes)
        except Exception as exc:
            raise UpstreamResolutionError(
                f"{producer} payload manifest could not be hydrated"
            ) from exc
        if (
            len(content) != size
            or sha256(content).hexdigest() != digest
            or len(content) > self._max_result_bytes
        ):
            raise UpstreamResolutionError(
                f"{producer} payload manifest integrity verification failed"
            )
        return content

    def _verify_immutable_result(
        self,
        *,
        shape: str,
        reference: DatabricksResultReference,
        locator: OrchestrationUpstreamInput | None,
        run_id: str,
        result_id: str,
        terminal_state: str,
        result: dict[str, Any],
        completion: dict[str, Any] | None,
        row_digest: Any,
        row_size: Any,
        row_created_at: Any,
    ) -> None:
        role = {
            "defense": "Defense Generation",
            "mitigation": "Mitigation Check",
            "bypass": "Bypass Validation",
        }[shape]
        if result_id != reference.key:
            raise UpstreamResolutionError(
                f"{role} row result_id does not match its reference"
            )
        expected_capability = {
            "defense": "defense-generation",
            "mitigation": "mitigation-check",
            "bypass": "bypass-validation",
        }[shape]
        expected_contracts = {
            "defense": {"defense-generation@1.0", "defense-generation-result@1.0"},
            "mitigation": {"mitigation-check@1.0"},
            "bypass": {"bypass-validation@1.0"},
        }[shape]
        if result.get("capability") != expected_capability and (
            shape != "bypass" or result.get("capability") is not None
        ):
            raise UpstreamResolutionError(f"{role} capability identity is invalid")
        if result.get("contract_id") not in expected_contracts:
            raise UpstreamResolutionError(f"{role} result contract is unsupported")
        expected_result_ref = reference.model_dump(mode="json", by_alias=True)
        identities: dict[str, Any] = {
            "run_id": run_id,
            "result_id": result_id,
            "terminal_state": terminal_state,
            "result_ref": expected_result_ref,
        }
        if shape != "bypass":
            identities["status"] = "completed"
        strict_locator = locator is not None and locator.is_strict_locator
        for field, expected in identities.items():
            if (strict_locator or field in result) and result.get(field) != expected:
                raise UpstreamResolutionError(
                    f"{role} result {field} does not match the immutable row"
                )
        declared_digest = result.get("content_sha256")
        declared_size = result.get("size_bytes")
        digest: str | None = None
        size: int | None = None
        if strict_locator or declared_digest is not None or declared_size is not None or shape == "bypass":
            digest, size = _producer_integrity(shape, result)
            if shape in {"defense", "mitigation"} and (
                declared_digest != digest or declared_size != size
            ):
                raise UpstreamResolutionError(
                    f"{role} canonical digest or size is invalid"
                )
        if shape == "bypass":
            if str(row_digest or "") != digest or int(row_size or -1) != size:
                raise UpstreamResolutionError(
                    "Bypass Validation persisted digest or size is invalid"
                )
            _verify_completion(
                completion or {},
                role=role,
                expected={
                    **identities,
                    "status": "completed",
                    "capability": expected_capability,
                    "content_sha256": digest,
                    "size_bytes": size,
                },
            )
        if locator is None:
            return
        if not strict_locator:
            return
        assert digest is not None and size is not None
        locator_values: dict[str, Any] = {
            "run_id": locator.run_id,
            "result_id": locator.result_id,
            "terminal_state": locator.terminal_state,
            "result_ref": expected_result_ref,
        }
        if shape == "bypass":
            assert completion is not None
            _verify_completion(
                completion,
                role=role,
                expected={
                    "capability": locator.capability,
                    "run_id": locator.run_id,
                    "result_id": locator.result_id,
                    "request_id": locator.request_id,
                    "correlation_id": locator.correlation_id,
                    "terminal_state": locator.terminal_state,
                    "status": locator.status,
                    "result_ref": expected_result_ref,
                    "content_sha256": locator.content_sha256,
                    "size_bytes": locator.size_bytes,
                },
            )
        else:
            locator_values.update(
                request_id=locator.request_id,
                correlation_id=locator.correlation_id,
                status=locator.status,
            )
        for field, expected in locator_values.items():
            if result.get(field) != expected:
                raise UpstreamResolutionError(
                    f"{role} result {field} differs from the immutable locator"
                )
        if digest != locator.content_sha256 or size != locator.size_bytes:
            raise UpstreamResolutionError(
                f"{role} canonical digest or size differs from the immutable locator"
            )
        result_created_at = _parse_datetime(
            result.get("created_at") or result.get("produced_at"), role
        )
        if result_created_at != locator.created_at.astimezone(UTC):
            raise UpstreamResolutionError(
                f"{role} created_at differs from the immutable locator"
            )
        if row_created_at is not None and _parse_datetime(row_created_at, role) != result_created_at:
            raise UpstreamResolutionError(
                f"{role} row created_at differs from the canonical result"
            )

    def _default_volume_reader(self, path: str, max_bytes: int) -> bytes:
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.core import Config

        if self._auth_type == "pat":
            if not self._token:
                raise RuntimeError("Databricks PAT configuration is incomplete")
            config = Config(
                host=f"https://{self._server_hostname}", token=self._token
            )
        else:
            if not self._client_id or not self._client_secret:
                raise RuntimeError("Databricks OAuth configuration is incomplete")
            config = Config(
                host=f"https://{self._server_hostname}",
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
        response = WorkspaceClient(config=config).files.download(path)
        content = _read_files_response(response, max_bytes)
        if len(content) > max_bytes:
            raise ValueError("Databricks Volume payload exceeds the configured limit")
        return content

    def healthcheck(self) -> bool:
        """Verify the configured upstream SQL reader without reading results."""
        connection: _Connection | None = None
        cursor: _Cursor | None = None
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchall()
            return True
        except Exception:
            logger.warning("Upstream Databricks readiness check failed", exc_info=True)
            return False
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    logger.warning("Upstream readiness cursor close failed", exc_info=True)
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    logger.warning("Upstream readiness connection close failed", exc_info=True)

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

        from databricks.sdk.core import Config
        from databricks.sdk.credentials_provider import oauth_service_principal

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


def _read_files_response(response: Any, max_bytes: int) -> bytes:
    stream = response.contents
    if stream is None:
        raise ValueError("Databricks Volume download returned no content")
    try:
        return stream.read(max_bytes + 1)
    finally:
        stream.close()


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


def _verify_completion(
    completion: dict[str, Any], *, role: str, expected: dict[str, Any]
) -> None:
    for field, value in expected.items():
        if completion.get(field) != value:
            raise UpstreamResolutionError(
                f"{role} completion {field} does not match the canonical result"
            )


def _producer_integrity(
    shape: str, result: dict[str, Any]
) -> tuple[str, int]:
    if shape == "defense":
        unsigned = {**result, "content_sha256": "", "size_bytes": 0}
        payload = _go_ordered_json(unsigned, _DEFENSE_RESULT_SCHEMA)
    elif shape == "mitigation":
        unsigned = {**result, "content_sha256": "", "size_bytes": 0}
        payload = _go_ordered_json(unsigned, _MITIGATION_RESULT_SCHEMA)
    else:
        payload = json.dumps(
            result,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    return f"sha256:{sha256(payload).hexdigest()}", len(payload)


def _go_ordered_json(
    result: dict[str, Any],
    schema: _GoSchema,
) -> bytes:
    fields = tuple(field[0] for field in schema)
    optional = {field[0] for field in schema if field[2] is not None}
    missing = [
        field for field in fields
        if field not in result and field not in optional
    ]
    if missing:
        raise UpstreamResolutionError(
            "canonical producer result is missing required fields: "
            + ", ".join(missing)
        )
    ordered = _go_struct_value(result, schema)
    encoded = json.dumps(
        ordered,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    # Match encoding/json's default string escaping while retaining UTF-8.
    encoded = (
        encoded.replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("\u2028", r"\u2028")
        .replace("\u2029", r"\u2029")
    )
    return encoded.encode("utf-8")


def _go_struct_value(value: dict[str, Any], schema: _GoSchema) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    for field, child_schema, omit_kind in schema:
        if field not in value:
            continue
        child = value[field]
        if _go_omit_empty(child, omit_kind):
            continue
        ordered[field] = (
            child
            if omit_kind == "raw"
            else _go_nested_value(child, child_schema)
        )
    return ordered


def _go_nested_value(value: Any, schema: _GoSchema | None) -> Any:
    if isinstance(value, list):
        return [_go_nested_value(item, schema) for item in value]
    if isinstance(value, dict):
        if schema is not None:
            return _go_struct_value(value, schema)
        return {
            key: _go_nested_value(value[key], None)
            for key in sorted(value)
        }
    return value


def _go_omit_empty(value: Any, kind: str | None) -> bool:
    if kind in {"pointer", "raw"}:
        return value is None
    if kind == "string":
        return value == ""
    if kind == "slice":
        return value is None or value == []
    if kind == "number":
        return value == 0
    return False


def _parse_datetime(value: Any, role: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise UpstreamResolutionError(
                f"{role} created_at is invalid"
            ) from exc
    else:
        raise UpstreamResolutionError(f"{role} created_at is missing")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
