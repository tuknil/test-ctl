"""FastAPI HTTP surface for the control-translation capability.

Endpoints follow the standard Janus capability-POC invocation surface:
GET /health, GET /schema, POST /invoke, GET /runs/{run_id}. Swagger UI is
available at /docs and the raw OpenAPI schema at /openapi.json (both
provided automatically by FastAPI).
"""

from __future__ import annotations

import logging
import re
from time import perf_counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.staticfiles import StaticFiles

from control_translation import capability
from control_translation.adapters import ADAPTER_REGISTRY
from control_translation.config import get_settings
from control_translation.contracts import (
    ControlTranslationResult,
    DirectBypassValidationResult,
    InvokeAPIRequest,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunListResponse,
)
from control_translation.diagnostics import diagnostic_json
from control_translation.persistence import (
    PersistenceError,
    canonical_request_hash,
    create_run_repository,
)
from control_translation.terminal import TerminalState
from control_translation.upstream_databricks import create_upstream_result_resolver


logger = logging.getLogger(__name__)

_SECRET_VALUE = re.compile(
    r"(?i)\b(access[_ -]?token|api[_ -]?key|authorization|client[_ -]?secret|password)"
    r"\b\s*[:=]\s*([^\s,;]+)"
)

_SETTINGS = get_settings()
_REPOSITORY = create_run_repository(_SETTINGS)
_UPSTREAM_RESOLVER = create_upstream_result_resolver(_SETTINGS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize durable storage before accepting application traffic."""
    logger.info(
        "Starting control-translation run_mode=%s persistence_backend=%s",
        _SETTINGS.run_mode,
        _SETTINGS.normalized_persistence_backend,
    )
    try:
        _REPOSITORY.initialize()
    except Exception:
        logger.exception(
            "Durable storage initialization failed backend=%s",
            _SETTINGS.normalized_persistence_backend,
        )
        raise
    logger.info(
        "Durable storage initialized backend=%s",
        _SETTINGS.normalized_persistence_backend,
    )
    yield

app = FastAPI(
    title="control-translation",
    description=(
        "Turns a proven mitigation pattern into a control-specific "
        "mitigation candidate for a target technology."
    ),
    version="0.1.0",
    docs_url="/docs" if _SETTINGS.enable_docs else None,
    redoc_url="/redoc" if _SETTINGS.enable_docs else None,
    openapi_url="/openapi.json" if _SETTINGS.enable_docs else None,
    lifespan=lifespan,
)

_UI_DIR = Path(__file__).resolve().parents[2] / "ui"


@app.middleware("http")
async def log_request_lifecycle(request: Request, call_next):
    """Log every HTTP request outcome without logging headers or query values."""
    started = perf_counter()
    query_names = sorted(set(request.query_params.keys()))
    client = request.client.host if request.client else "-"
    logger.info(
        "HTTP request started method=%s path=%s query_names=%s client=%s",
        request.method,
        request.url.path,
        query_names,
        client,
    )
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "Unhandled HTTP request failure method=%s path=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            (perf_counter() - started) * 1000,
        )
        raise
    logger.info(
        "HTTP request completed method=%s path=%s status_code=%s duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        (perf_counter() - started) * 1000,
    )
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def readiness() -> dict[str, str]:
    """Deployment readiness check with safe configuration diagnostics."""
    settings = get_settings()
    if not settings.ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not-ready",
                "configuration_errors": settings.configuration_errors,
            },
        )
    if not _REPOSITORY.healthcheck():
        logger.error(
            "Readiness storage healthcheck failed backend=%s",
            settings.normalized_persistence_backend,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not-ready", "storage": "unavailable"},
        )
    return {"status": "ready"}


@app.get("/inference")
def inference_status() -> dict[str, str | bool]:
    """Safe, browser-consumable inference status (never returns secrets)."""
    settings = get_settings()
    return {
        "execution_mode": "live" if settings.is_live else "fixture",
        "provider": settings.model_provider,
        "model": settings.model_name,
        "credentials_configured": settings.credentials_configured,
        "switching_requires_restart": True,
    }


@app.get("/schema")
def schema() -> dict[str, Any]:
    settings = get_settings()
    return {
        "capability": "control-translation",
        "request_model_fields": list(
            InvokeRequestEnvelope.model_fields.keys()
        ),
        "response_model_fields": list(ResultEnvelope.model_fields.keys()),
        "terminal_states": [state.value for state in TerminalState],
        "run_mode": settings.run_mode,
        "persistence": settings.normalized_persistence_backend,
        "inference": inference_status(),
        "supported_adapters": {
            name: {
                "artifact_type": adapter.artifact_type,
                "mode": "fixture-backed (no live policy/API integration yet)",
            }
            for name, adapter in ADAPTER_REGISTRY.items()
        },
        "schema_files": {
            "request": "schemas/request.schema.json",
            "result": "schemas/result.schema.json",
        },
    }


@app.post("/invoke", response_model=ResultEnvelope)
def invoke_endpoint(payload: InvokeAPIRequest) -> ResultEnvelope:
    direct_bypass_result = (
        payload if isinstance(payload, DirectBypassValidationResult) else None
    )
    envelope = (
        capability.normalize_direct_bypass_request(direct_bypass_result)
        if direct_bypass_result is not None
        else payload
    )
    assert isinstance(envelope, InvokeRequestEnvelope)
    effective_envelope = envelope.model_copy(
        update={
            "request_id": envelope.request_id or str(uuid4()),
            "correlation_id": envelope.correlation_id or str(uuid4()),
        }
    )
    request_hash = canonical_request_hash(effective_envelope)
    logger.info(
        "Invocation accepted request_id=%s correlation_id=%s "
        "idempotency_key_present=%s request_hash=%s payload=%s",
        effective_envelope.request_id or "-",
        effective_envelope.correlation_id or "-",
        effective_envelope.idempotency_key is not None,
        request_hash,
        diagnostic_json(effective_envelope),
    )

    if effective_envelope.idempotency_key is not None:
        try:
            existing = _REPOSITORY.get_by_idempotency_key(
                effective_envelope.idempotency_key
            )
        except PersistenceError as exc:
            raise _storage_unavailable(
                operation="get-by-idempotency-key",
                exc=exc,
                request_id=effective_envelope.request_id,
                correlation_id=effective_envelope.correlation_id,
            ) from exc
        if existing is not None:
            if existing.request_hash != request_hash:
                logger.warning(
                    "Invocation idempotency conflict request_id=%s correlation_id=%s",
                    effective_envelope.request_id or "-",
                    effective_envelope.correlation_id or "-",
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key was already used for a different request.",
                )
            _log_invocation_result(existing.result, source="idempotency-cache")
            return existing.result

    started_at = datetime.now(timezone.utc)
    if direct_bypass_result is not None:
        result_envelope = capability.decline_direct_bypass(
            effective_envelope,
            direct_bypass_result,
            settings=_SETTINGS,
        )
    else:
        result_envelope = capability.invoke_envelope(
            effective_envelope,
            resolver=_UPSTREAM_RESOLVER,
            settings=_SETTINGS,
        )
    _log_invocation_result(result_envelope, source="capability")
    try:
        _REPOSITORY.save_completed_run(
            effective_envelope,
            result_envelope,
            request_hash=request_hash,
            started_at=started_at,
        )
    except PersistenceError as exc:
        # A simultaneous retry may have committed the same idempotency key.
        if effective_envelope.idempotency_key is not None:
            try:
                existing = _REPOSITORY.get_by_idempotency_key(
                    effective_envelope.idempotency_key
                )
            except PersistenceError as retry_exc:
                _log_storage_failure(
                    "retry-get-by-idempotency-key",
                    retry_exc,
                    request_id=effective_envelope.request_id,
                    correlation_id=effective_envelope.correlation_id,
                    result_id=result_envelope.result_id,
                )
                existing = None
            if existing is not None and existing.request_hash == request_hash:
                _log_invocation_result(existing.result, source="idempotency-recovery")
                return existing.result
        raise _storage_unavailable(
            operation="save-completed-run",
            exc=exc,
            request_id=effective_envelope.request_id,
            correlation_id=effective_envelope.correlation_id,
            result_id=result_envelope.result_id,
        ) from exc
    logger.info(
        "Invocation durably persisted request_id=%s correlation_id=%s "
        "run_id=%s result_id=%s backend=%s",
        effective_envelope.request_id or "-",
        result_envelope.correlation_id or "-",
        result_envelope.run_id,
        result_envelope.result_id,
        _SETTINGS.normalized_persistence_backend,
    )
    return result_envelope


@app.get("/runs/{run_id}", response_model=ResultEnvelope)
def get_run(run_id: str) -> ResultEnvelope:
    try:
        result_envelope = _REPOSITORY.get_run(run_id)
    except PersistenceError as exc:
        raise _storage_unavailable(
            operation="get-run", exc=exc, run_id=run_id
        ) from exc
    if result_envelope is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return result_envelope


@app.get("/v1/runs", response_model=RunListResponse)
def list_runs(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> RunListResponse:
    """List safe run metadata for the dashboard using bounded pagination."""
    try:
        page = _REPOSITORY.list_runs(limit=limit, offset=offset)
    except PersistenceError as exc:
        raise _storage_unavailable(operation="list-runs", exc=exc) from exc
    return RunListResponse(
        items=list(page.items),
        total=page.total,
        limit=limit,
        offset=offset,
        has_more=offset + len(page.items) < page.total,
        terminal_state_counts=page.terminal_state_counts,
    )


@app.get("/v1/results/{result_id}", response_model=ControlTranslationResult)
def get_result(result_id: str) -> ControlTranslationResult:
    try:
        result_envelope = _REPOSITORY.get_result(result_id)
    except PersistenceError as exc:
        raise _storage_unavailable(
            operation="get-result", exc=exc, result_id=result_id
        ) from exc
    if result_envelope is None:
        raise HTTPException(
            status_code=404,
            detail=f"Result '{result_id}' not found.",
        )
    return result_envelope.structured_result


def _storage_unavailable(
    *,
    operation: str,
    exc: PersistenceError,
    request_id: str | None = None,
    correlation_id: str | None = None,
    run_id: str | None = None,
    result_id: str | None = None,
) -> HTTPException:
    """Log the traceback and return sanitized diagnostics suitable for the UI."""
    _log_storage_failure(
        operation,
        exc,
        request_id=request_id,
        correlation_id=correlation_id,
        run_id=run_id,
        result_id=result_id,
    )
    root_cause = _root_cause(exc)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "message": "Durable result storage is unavailable.",
            "diagnostic": {
                "operation": operation,
                "backend": _SETTINGS.normalized_persistence_backend,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "run_id": run_id,
                "result_id": result_id,
                "error_type": type(root_cause).__name__,
                "error": _sanitize_diagnostic(str(root_cause)),
                "server_traceback_logged": True,
            },
        },
    )


def _root_cause(exc: BaseException) -> BaseException:
    root = exc
    seen: set[int] = set()
    while root.__cause__ is not None and id(root) not in seen:
        seen.add(id(root))
        root = root.__cause__
    return root


def _sanitize_diagnostic(message: str) -> str:
    """Redact common credential assignments and bound UI diagnostic size."""
    redacted = _SECRET_VALUE.sub(lambda match: f"{match.group(1)}=[REDACTED]", message)
    return redacted[:2000] or "No additional error detail was provided."


def _log_storage_failure(
    operation: str,
    exc: PersistenceError,
    *,
    request_id: str | None = None,
    correlation_id: str | None = None,
    run_id: str | None = None,
    result_id: str | None = None,
) -> None:
    """Log a storage exception chain with safe identifiers, never request data."""
    logger.error(
        "Durable storage operation failed operation=%s backend=%s "
        "request_id=%s correlation_id=%s run_id=%s result_id=%s",
        operation,
        _SETTINGS.normalized_persistence_backend,
        request_id or "-",
        correlation_id or "-",
        run_id or "-",
        result_id or "-",
        exc_info=(type(exc), exc, exc.__traceback__),
    )


def _log_invocation_result(result: ResultEnvelope, *, source: str) -> None:
    """Log the complete result contract with candidate content redacted."""
    candidate = result.structured_result.primary_candidate
    artifact_hash = (
        candidate.candidate_artifact.content_hash if candidate is not None else "-"
    )
    logger.info(
        "Invocation result source=%s run_id=%s result_id=%s correlation_id=%s "
        "terminal_state=%s status=%s artifact_hash=%s payload=%s",
        source,
        result.run_id,
        result.result_id,
        result.correlation_id or "-",
        result.terminal_state.value,
        result.status,
        artifact_hash,
        diagnostic_json(result),
    )


if _UI_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_UI_DIR), html=True), name="ui")
