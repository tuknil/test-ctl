"""FastAPI HTTP surface for the control-translation capability.

Endpoints follow the standard Janus capability-POC invocation surface:
GET /health, GET /schema, POST /invoke, GET /runs/{run_id}. Swagger UI is
available at /docs and the raw OpenAPI schema at /openapi.json (both
provided automatically by FastAPI).

This service is API-only. The demo UI is a separate deployable
(`control_translation_ui`) that calls this API cross-origin from the browser,
so browser access requires `CORS_ALLOWED_ORIGINS` to name the UI's origin.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from control_translation import capability
from control_translation.adapters import ADAPTER_REGISTRY
from control_translation.callbacks import (
    CallbackDispatcher,
    CallbackValidationError,
    callback_metadata_from_headers,
)
from control_translation.config import get_settings
from control_translation.contracts import (
    CapabilityRunStatus,
    CapabilityRunSubmission,
    ControlTranslationResult,
    DirectBypassValidationResult,
    InvokeAPIRequest,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunListResponse,
)
from control_translation.diagnostics import diagnostic_json
from control_translation.lifecycle import LifecycleWorker
from control_translation.persistence import (
    IdempotencyConflictError,
    PersistenceError,
    canonical_request_hash,
    create_run_repository,
    normalized_request_digest,
)
from control_translation.terminal import TerminalState
from control_translation.upstream_databricks import create_upstream_result_resolver

logger = logging.getLogger(__name__)

_SETTINGS = get_settings()
_REPOSITORY = create_run_repository(_SETTINGS)
_UPSTREAM_RESOLVER = create_upstream_result_resolver(_SETTINGS)
_LIFECYCLE_WORKER = LifecycleWorker(
    lambda: _REPOSITORY,
    lambda: _UPSTREAM_RESOLVER,
    _SETTINGS,
)
_CALLBACK_DISPATCHER = CallbackDispatcher(
    lambda: _REPOSITORY,
    token=_SETTINGS.capability_callback_token,
    timeout_seconds=_SETTINGS.capability_callback_timeout_seconds,
    poll_interval_seconds=_SETTINGS.capability_callback_poll_interval_seconds,
)


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
    _LIFECYCLE_WORKER.start()
    _CALLBACK_DISPATCHER.start()
    try:
        yield
    finally:
        _LIFECYCLE_WORKER.stop()
        _CALLBACK_DISPATCHER.stop()

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

if _SETTINGS.cors_allowed_origins:
    # The demo UI runs on its own origin. Nothing here is credentialed: the
    # API takes no cookies or browser auth, so credentials stay disallowed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(_SETTINGS.cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["content-type", "idempotency-key", "x-correlation-id"],
        max_age=600,
    )


@app.exception_handler(RequestValidationError)
async def lifecycle_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/v1/control-translation-runs"):
        return _lifecycle_error(
            400,
            "invalid_request",
            "Request body or required headers failed validation.",
        )
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(StarletteHTTPException)
async def lifecycle_http_error(request: Request, exc: StarletteHTTPException):
    """Keep lifecycle errors at the JSON root instead of under FastAPI detail."""
    if request.url.path.startswith("/v1/control-translation-runs"):
        if isinstance(exc.detail, dict) and {
            "code",
            "detail",
            "retryable",
        }.issubset(exc.detail):
            payload = exc.detail
        else:
            payload = {
                "code": "method_not_allowed" if exc.status_code == 405 else "request_failed",
                "detail": str(exc.detail),
                "retryable": _is_retryable_http_status(exc.status_code),
            }
        return JSONResponse(
            status_code=exc.status_code,
            content=payload,
            headers=exc.headers,
        )
    return await http_exception_handler(request, exc)


@app.exception_handler(Exception)
async def lifecycle_unhandled_error(request: Request, exc: Exception):
    if request.url.path.startswith("/v1/control-translation-runs"):
        logger.exception(
            "Unhandled lifecycle request failure method=%s path=%s",
            request.method,
            request.url.path,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return _lifecycle_error(
            500,
            "internal_error",
            "The capability lifecycle request failed unexpectedly.",
        )
    raise exc

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
    if (
        request.method == "POST"
        and request.url.path == "/v1/control-translation-runs"
        and request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        response = _lifecycle_error(
            400,
            "invalid_content_type",
            "Content-Type must be application/json.",
        )
        logger.info(
            "HTTP request completed method=%s path=%s status_code=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            (perf_counter() - started) * 1000,
        )
        return response
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


@app.get("/")
def service_descriptor() -> dict[str, Any]:
    """Identify this service. The demo UI is deployed separately."""
    return {
        "service": "control-translation",
        "contract_id": "control-translation@1.0",
        "role": "api",
        "docs": "/docs" if _SETTINGS.enable_docs else None,
        "endpoints": [
            "/health",
            "/ready",
            "/inference",
            "/schema",
            "/invoke",
            "/v1/control-translation-runs",
        ],
    }


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

    started_at = datetime.now(UTC)
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


def _lifecycle_error(http_status: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=http_status,
        content={
            "code": code,
            "detail": detail,
            "retryable": _is_retryable_http_status(http_status),
        },
    )


def _is_retryable_http_status(http_status: int) -> bool:
    return http_status in {408, 425, 429} or http_status >= 500


@app.post(
    "/v1/control-translation-runs",
    response_model=CapabilityRunSubmission,
    status_code=status.HTTP_202_ACCEPTED,
)
def submit_control_translation_run(
    payload: InvokeRequestEnvelope,
    content_type: str = Header(alias="Content-Type"),
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=1),
    correlation_id: str = Header(alias="X-Correlation-ID", min_length=1),
    callback_url: str | None = Header(default=None, alias="X-Janus-Callback-URL"),
    callback_workflow_id: str | None = Header(
        default=None, alias="X-Janus-Callback-Workflow-ID"
    ),
    callback_signal: str | None = Header(
        default=None, alias="X-Janus-Callback-Signal"
    ),
):
    """Persist one queued run before signaling the independent worker."""
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return _lifecycle_error(
            400,
            "invalid_content_type",
            "Content-Type must be application/json.",
        )
    if payload.request_id is None:
        return _lifecycle_error(400, "request_id_required", "request_id is required.")
    if payload.correlation_id is None:
        return _lifecycle_error(
            400, "correlation_id_required", "correlation_id is required."
        )
    if payload.request_id != idempotency_key:
        return _lifecycle_error(
            400,
            "request_identity_mismatch",
            "request_id and Idempotency-Key must identify the same request.",
        )
    if payload.correlation_id != correlation_id:
        return _lifecycle_error(
            400,
            "correlation_identity_mismatch",
            "correlation_id and X-Correlation-ID must match.",
        )
    if payload.idempotency_key not in (None, idempotency_key):
        return _lifecycle_error(
            400,
            "request_identity_mismatch",
            "Body idempotency_key must match request_id and Idempotency-Key.",
        )
    if payload.callback is not None:
        return _lifecycle_error(
            400,
            "callback_not_supported",
            "Body callbacks are not supported; use the X-Janus-Callback-* headers.",
        )
    try:
        callback = callback_metadata_from_headers(
            {
                "X-Janus-Callback-URL": callback_url,
                "X-Janus-Callback-Workflow-ID": callback_workflow_id,
                "X-Janus-Callback-Signal": callback_signal,
            },
            allowed_hosts=_SETTINGS.capability_callback_allowed_hosts,
        )
    except CallbackValidationError as exc:
        return _lifecycle_error(400, "invalid_callback_headers", str(exc))
    if callback is not None:
        logger.info(
            "Callback metadata accepted request_id=%s correlation_id=%s workflow_id=%s",
            payload.request_id,
            payload.correlation_id,
            callback.callback_workflow_id,
        )
        if not _SETTINGS.capability_callback_token:
            logger.error(
                "Callback configuration error request_id=%s correlation_id=%s reason=missing-callback-token",
                payload.request_id,
                payload.correlation_id,
            )
    effective = payload.model_copy(update={"idempotency_key": idempotency_key})
    digest = normalized_request_digest(effective)
    try:
        created = _REPOSITORY.create_lifecycle_run(
            effective,
            idempotency_key=idempotency_key,
            request_digest=digest,
            callback=callback,
        )
    except IdempotencyConflictError:
        return _lifecycle_error(
            409,
            "idempotency_conflict",
            "Idempotency-Key is already bound to a different normalized request.",
        )
    except PersistenceError as exc:
        raise _storage_unavailable(
            operation="create-lifecycle-run",
            exc=exc,
            request_id=payload.request_id,
            correlation_id=payload.correlation_id,
        ) from exc
    run_status = created.run.status
    _LIFECYCLE_WORKER.wake()
    response = CapabilityRunSubmission(
        request_id=run_status.request_id,
        correlation_id=run_status.correlation_id,
        run_id=run_status.run_id,
        status=run_status.status,
        status_url=f"/v1/control-translation-runs/{run_status.run_id}",
        result_url=f"/v1/control-translation-runs/{run_status.run_id}/result",
        accepted_at=run_status.created_at,
    )
    return JSONResponse(
        status_code=(
            status.HTTP_200_OK
            if not created.created and run_status.status in {"completed", "failed", "canceled"}
            else status.HTTP_202_ACCEPTED
        ),
        content=response.model_dump(mode="json"),
    )


@app.get(
    "/v1/control-translation-runs/{run_id}",
    response_model=CapabilityRunStatus,
)
def get_control_translation_run(run_id: str):
    try:
        run = _REPOSITORY.get_lifecycle_run(run_id)
    except PersistenceError as exc:
        raise _storage_unavailable(operation="get-lifecycle-run", exc=exc, run_id=run_id) from exc
    if run is None:
        return _lifecycle_error(404, "run_not_found", "Run was not found.")
    return run.status


@app.get("/v1/control-translation-runs/{run_id}/result")
def get_control_translation_run_result(run_id: str):
    try:
        run = _REPOSITORY.get_lifecycle_run(run_id)
        result = _REPOSITORY.get_lifecycle_result(run_id) if run is not None else None
    except PersistenceError as exc:
        raise _storage_unavailable(operation="get-lifecycle-result", exc=exc, run_id=run_id) from exc
    if run is None:
        return _lifecycle_error(404, "run_not_found", "Run was not found.")
    if run.status.status in {"queued", "running"}:
        return _lifecycle_error(409, "run_not_terminal", "Run is not terminal.")
    if result is None:
        return run.status
    return result


@app.post(
    "/v1/control-translation-runs/{run_id}/cancel",
    response_model=CapabilityRunStatus,
)
def cancel_control_translation_run(run_id: str):
    try:
        run = _LIFECYCLE_WORKER.cancel_run(run_id)
    except PersistenceError as exc:
        raise _storage_unavailable(operation="cancel-lifecycle-run", exc=exc, run_id=run_id) from exc
    if run is None:
        return _lifecycle_error(404, "run_not_found", "Run was not found.")
    return run.status


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
            "code": "storage_unavailable",
            "detail": "Durable result storage is unavailable.",
            "message": "Durable result storage is unavailable.",
            "retryable": True,
            "diagnostic": {
                "operation": operation,
                "backend": _SETTINGS.normalized_persistence_backend,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "run_id": run_id,
                "result_id": result_id,
                "error_type": type(root_cause).__name__,
                "error": "Root-cause details are available only in server logs.",
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

