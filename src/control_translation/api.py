"""FastAPI HTTP surface for the control-translation capability.

Endpoints follow the standard Janus capability-POC invocation surface:
GET /health, GET /schema, POST /invoke, GET /runs/{run_id}. Swagger UI is
available at /docs and the raw OpenAPI schema at /openapi.json (both
provided automatically by FastAPI).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.staticfiles import StaticFiles

from control_translation import capability
from control_translation.adapters import ADAPTER_REGISTRY
from control_translation.config import get_settings
from control_translation.contracts import (
    ControlTranslationResult,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunListResponse,
)
from control_translation.persistence import (
    PersistenceError,
    canonical_request_hash,
    create_run_repository,
)
from control_translation.terminal import TerminalState
from control_translation.upstream_databricks import create_upstream_result_resolver


_SETTINGS = get_settings()
_REPOSITORY = create_run_repository(_SETTINGS)
_UPSTREAM_RESOLVER = create_upstream_result_resolver(_SETTINGS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize durable storage before accepting application traffic."""
    _REPOSITORY.initialize()
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
def invoke_endpoint(envelope: InvokeRequestEnvelope) -> ResultEnvelope:
    effective_envelope = envelope.model_copy(
        update={"correlation_id": envelope.correlation_id or str(uuid4())}
    )
    request_hash = canonical_request_hash(effective_envelope)

    if effective_envelope.idempotency_key is not None:
        try:
            existing = _REPOSITORY.get_by_idempotency_key(
                effective_envelope.idempotency_key
            )
        except PersistenceError as exc:
            raise _storage_unavailable() from exc
        if existing is not None:
            if existing.request_hash != request_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key was already used for a different request.",
                )
            return existing.result

    started_at = datetime.now(timezone.utc)
    result_envelope = capability.invoke_envelope(
        effective_envelope,
        resolver=_UPSTREAM_RESOLVER,
        settings=_SETTINGS,
    )
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
            except PersistenceError:
                existing = None
            if existing is not None and existing.request_hash == request_hash:
                return existing.result
        raise _storage_unavailable() from exc
    return result_envelope


@app.get("/runs/{run_id}", response_model=ResultEnvelope)
def get_run(run_id: str) -> ResultEnvelope:
    try:
        result_envelope = _REPOSITORY.get_run(run_id)
    except PersistenceError as exc:
        raise _storage_unavailable() from exc
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
        raise _storage_unavailable() from exc
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
        raise _storage_unavailable() from exc
    if result_envelope is None:
        raise HTTPException(
            status_code=404,
            detail=f"Result '{result_id}' not found.",
        )
    return result_envelope.structured_result


def _storage_unavailable() -> HTTPException:
    """Return a safe error that never reveals database paths or SQL details."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Durable result storage is unavailable.",
    )


if _UI_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_UI_DIR), html=True), name="ui")
