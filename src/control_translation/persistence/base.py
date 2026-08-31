"""Persistence contracts for durable capability runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Protocol

from control_translation.contracts import InvokeRequestEnvelope, ResultEnvelope, RunSummary


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


def canonical_request_hash(envelope: InvokeRequestEnvelope) -> str:
    """Hash semantic request data, excluding transport and retry identifiers."""
    payload = envelope.model_dump_json(
        include={
            "input",
            "upstream_result_refs",
            "routing_metadata",
            "scope_config",
            "subject_record_revision_id",
            "provenance",
        },
        exclude_none=True,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


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
    ) -> None: ...

    def get_run(self, run_id: str) -> ResultEnvelope | None: ...

    def get_result(self, result_id: str) -> ResultEnvelope | None: ...

    def get_by_idempotency_key(self, key: str) -> IdempotencyRecord | None: ...

    def list_runs(self, *, limit: int, offset: int) -> RunSummaryPage: ...
