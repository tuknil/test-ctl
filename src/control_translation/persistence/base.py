"""Persistence contracts for durable capability runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Protocol

from control_translation.callbacks import CallbackDelivery, CallbackMetadata
from control_translation.contracts import (
    CapabilityRunStatus,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunFailure,
    RunSummary,
)


class PersistenceError(RuntimeError):
    """Raised when durable run storage cannot complete an operation."""


@dataclass(frozen=True)
class IdempotencyRecord:
    """A previously completed invocation bound to an idempotency key."""

    request_hash: str
    result: ResultEnvelope


@dataclass(frozen=True)
class RunSummaryPage:
    """Storage-neutral page of safe run summaries."""

    items: tuple[RunSummary, ...]
    total: int
    terminal_state_counts: dict[str, int]


class IdempotencyConflictError(PersistenceError):
    """Raised when an idempotency key is reused for different semantic input."""


@dataclass(frozen=True)
class LifecycleRun:
    """Durable worker record with the validated request and public status."""

    request: InvokeRequestEnvelope
    status: CapabilityRunStatus
    request_digest: str
    cancel_requested: bool
    worker_id: str | None
    attempt_number: int
    publication_state: str
    callback: CallbackMetadata | None = None


@dataclass(frozen=True)
class PreparedPublication:
    """Exact immutable payload staged before external publication begins."""

    request: InvokeRequestEnvelope
    result_envelope: ResultEnvelope
    canonical_result: dict
    completion: dict
    request_hash: str
    started_at: datetime
    result_id: str
    terminal_state: str
    publication_state: str


@dataclass(frozen=True)
class CreatedLifecycleRun:
    run: LifecycleRun
    created: bool


def canonical_request_hash(envelope: InvokeRequestEnvelope) -> str:
    """Hash semantic request data, excluding transport and retry identifiers."""
    payload = envelope.model_dump_json(
        include={
            "input",
            "subject",
            "upstream_result_refs",
            "routing_metadata",
            "scope_config",
            "subject_record_revision_id",
            "provenance",
        },
        exclude_none=True,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def normalized_request_digest(envelope: InvokeRequestEnvelope) -> str:
    """RFC-style stable SHA-256 over the complete semantic request body."""
    data = envelope.model_dump(
        mode="json",
        by_alias=True,
        exclude={"idempotency_key"},
        exclude_none=True,
    )
    normalized = json.dumps(
        data, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    return sha256(normalized.encode("utf-8")).hexdigest()


def canonical_result_bytes(result: dict) -> bytes:
    """Serialize the immutable result content covered by integrity metadata.

    The canonical payload excludes its self-describing integrity fields. The
    exact returned bytes are stored as Databricks ``result_json`` and covered
    by both ``result_sha256`` and ``result_size_bytes``.
    """
    payload = {
        key: value
        for key, value in result.items()
        if key not in {"content_sha256", "size_bytes"}
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class RunRepository(Protocol):
    """Storage boundary used by the API; domain code does not depend on SQL."""

    def initialize(self) -> None: ...

    def healthcheck(self) -> bool: ...

    def save_completed_run(
        self,
        request: InvokeRequestEnvelope,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
        canonical_result: dict | None = None,
    ) -> None: ...

    def get_run(self, run_id: str) -> ResultEnvelope | None: ...

    def get_result(self, result_id: str) -> ResultEnvelope | None: ...

    def get_by_idempotency_key(self, key: str) -> IdempotencyRecord | None: ...

    def list_runs(self, *, limit: int, offset: int) -> RunSummaryPage: ...

    def create_lifecycle_run(
        self,
        request: InvokeRequestEnvelope,
        *,
        idempotency_key: str,
        request_digest: str,
        run_id: str | None = None,
        callback: CallbackMetadata | None = None,
    ) -> CreatedLifecycleRun: ...

    def get_lifecycle_run(self, run_id: str) -> LifecycleRun | None: ...

    def get_lifecycle_result(self, run_id: str) -> dict | None: ...

    def claim_lifecycle_run(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> LifecycleRun | None: ...

    def heartbeat_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        lease_seconds: int,
    ) -> bool: ...

    def prepare_lifecycle_publication(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        result_envelope: ResultEnvelope,
        canonical_result: dict,
        completion: dict,
        request_hash: str,
        started_at: datetime,
        result_id: str,
        terminal_state: str,
    ) -> bool: ...

    def get_prepared_publication(
        self, run_id: str
    ) -> PreparedPublication | None: ...

    def begin_lifecycle_publication(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
    ) -> bool: ...

    def complete_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        result: dict,
        completion: dict,
        result_id: str,
        terminal_state: str,
    ) -> bool: ...

    def fail_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        failure: RunFailure,
        result: dict | None = None,
    ) -> bool: ...

    def cancel_lifecycle_run(self, run_id: str) -> LifecycleRun | None: ...

    def list_due_callback_deliveries(
        self, *, now: datetime, limit: int
    ) -> tuple[CallbackDelivery, ...]: ...

    def mark_callback_delivered(
        self, event_id: str, *, delivered_at: datetime, status_code: int
    ) -> None: ...

    def reschedule_callback_delivery(
        self,
        event_id: str,
        *,
        attempts: int,
        next_attempt_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None: ...

    def mark_callback_configuration_failed(
        self,
        event_id: str,
        *,
        attempts: int,
        failed_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None: ...
