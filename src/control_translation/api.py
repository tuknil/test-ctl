"""FastAPI HTTP surface for the control-translation capability.

Endpoints follow the standard Janus capability-POC invocation surface:
GET /health, GET /schema, POST /invoke, GET /runs/{run_id}. Swagger UI is
available at /docs and the raw OpenAPI schema at /openapi.json (both
provided automatically by FastAPI).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles

from control_translation import capability
from control_translation.adapters import ADAPTER_REGISTRY
from control_translation.config import get_settings
from control_translation.contracts import InvokeRequestEnvelope, ResultEnvelope
from control_translation.terminal import TerminalState


_SETTINGS = get_settings()

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
)

_RUNS: dict[str, ResultEnvelope] = {}

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
    result_envelope = capability.invoke_envelope(envelope)
    _RUNS[result_envelope.run_id] = result_envelope
    return result_envelope


@app.get("/runs/{run_id}", response_model=ResultEnvelope)
def get_run(run_id: str) -> ResultEnvelope:
    result_envelope = _RUNS.get(run_id)
    if result_envelope is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return result_envelope


if _UI_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_UI_DIR), html=True), name="ui")
