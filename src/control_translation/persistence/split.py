"""Split lifecycle coordination from the immutable capability result sink."""

from __future__ import annotations

from datetime import datetime

from control_translation.contracts import InvokeRequestEnvelope, ResultEnvelope, RunFailure
from control_translation.persistence.base import (
    CreatedLifecycleRun,
    IdempotencyRecord,
    LifecycleRun,
    PreparedPublication,
    RunRepository,
    RunSummaryPage,
)
from control_translation.persistence.sqlite import SQLiteRunRepository


class SplitRunRepository:
    """Use local SQLite for leases and a shared repository for final results."""

    def __init__(
        self,
        lifecycle: SQLiteRunRepository,
        result_sink: RunRepository,
    ) -> None:
        self.lifecycle = lifecycle
        self.result_sink = result_sink

    def initialize(self) -> None:
        self.lifecycle.initialize()
        self.result_sink.initialize()

    def healthcheck(self) -> bool:
        return self.lifecycle.healthcheck() and self.result_sink.healthcheck()

    def save_completed_run(
        self,
        request: InvokeRequestEnvelope,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
        canonical_result: dict | None = None,
    ) -> None:
        self.result_sink.save_completed_run(
            request,
            result,
            request_hash=request_hash,
            started_at=started_at,
            canonical_result=canonical_result,
        )

    def get_run(self, run_id: str) -> ResultEnvelope | None:
        return self.result_sink.get_run(run_id)

    def get_result(self, result_id: str) -> ResultEnvelope | None:
        return self.result_sink.get_result(result_id)

    def get_by_idempotency_key(self, key: str) -> IdempotencyRecord | None:
        return self.result_sink.get_by_idempotency_key(key)

    def list_runs(self, *, limit: int, offset: int) -> RunSummaryPage:
        return self.result_sink.list_runs(limit=limit, offset=offset)

    def create_lifecycle_run(
        self,
        request: InvokeRequestEnvelope,
        *,
        idempotency_key: str,
        request_digest: str,
        run_id: str | None = None,
    ) -> CreatedLifecycleRun:
        return self.lifecycle.create_lifecycle_run(
            request,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            run_id=run_id,
        )

    def get_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        return self.lifecycle.get_lifecycle_run(run_id)

    def get_lifecycle_result(self, run_id: str) -> dict | None:
        return self.lifecycle.get_lifecycle_result(run_id)

    def claim_lifecycle_run(
        self,
        *,
        worker_id: str,
        lease_seconds: int,
        max_attempts: int,
    ) -> LifecycleRun | None:
        return self.lifecycle.claim_lifecycle_run(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
        )

    def heartbeat_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        lease_seconds: int,
    ) -> bool:
        return self.lifecycle.heartbeat_lifecycle_run(
            run_id,
            worker_id=worker_id,
            attempt_number=attempt_number,
            lease_seconds=lease_seconds,
        )

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
    ) -> bool:
        return self.lifecycle.prepare_lifecycle_publication(
            run_id,
            worker_id=worker_id,
            attempt_number=attempt_number,
            result_envelope=result_envelope,
            canonical_result=canonical_result,
            completion=completion,
            request_hash=request_hash,
            started_at=started_at,
            result_id=result_id,
            terminal_state=terminal_state,
        )

    def get_prepared_publication(self, run_id: str) -> PreparedPublication | None:
        return self.lifecycle.get_prepared_publication(run_id)

    def begin_lifecycle_publication(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
    ) -> bool:
        return self.lifecycle.begin_lifecycle_publication(
            run_id,
            worker_id=worker_id,
            attempt_number=attempt_number,
        )

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
    ) -> bool:
        return self.lifecycle.complete_lifecycle_run(
            run_id,
            worker_id=worker_id,
            attempt_number=attempt_number,
            result=result,
            completion=completion,
            result_id=result_id,
            terminal_state=terminal_state,
        )

    def fail_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        failure: RunFailure,
        result: dict | None = None,
    ) -> bool:
        return self.lifecycle.fail_lifecycle_run(
            run_id,
            worker_id=worker_id,
            attempt_number=attempt_number,
            failure=failure,
            result=result,
        )

    def cancel_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        return self.lifecycle.cancel_lifecycle_run(run_id)