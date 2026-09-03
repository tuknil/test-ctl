"""Durable background execution for asynchronous capability runs."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import quote
from uuid import uuid4

from control_translation import capability
from control_translation.cancellation import OperationCancelled
from control_translation.config import Settings
from control_translation.contracts import (
    CanonicalCompletion,
    DatabricksResultReference,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunFailure,
)
from control_translation.persistence import (
    LifecycleRun,
    PersistenceError,
    RunRepository,
    canonical_result_bytes,
)
from control_translation.terminal import TerminalState
from control_translation.upstream import UpstreamResultResolver

logger = logging.getLogger(__name__)

RepositoryProvider = Callable[[], RunRepository]
ResolverProvider = Callable[[], UpstreamResultResolver | None]


class LifecycleWorker:
    """Claims persisted runs and executes them independently of HTTP requests."""

    def __init__(
        self,
        repository: RepositoryProvider,
        resolver: ResolverProvider,
        settings: Settings,
    ) -> None:
        self._repository = repository
        self._resolver = resolver
        self._settings = settings
        self._worker_id = f"control-translation:{uuid4()}"
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_attempts: dict[str, threading.Event] = {}

    def start(self) -> None:
        """Start one daemon worker; repeated startup calls are harmless."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._wake.set()
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="control-translation-lifecycle-worker",
                daemon=True,
            )
            self._thread.start()

    def wake(self) -> None:
        self.start()
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._active_lock:
            for abort_work in self._active_attempts.values():
                abort_work.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=self._settings.worker_shutdown_grace_seconds)

    def notify_cancellation(self, run_id: str) -> None:
        """Promptly detach an active attempt after durable cancellation."""
        with self._active_lock:
            abort_work = self._active_attempts.get(run_id)
        if abort_work is not None:
            abort_work.set()
        self._wake.set()

    def cancel_run(self, run_id: str) -> LifecycleRun | None:
        """Serialize cancellation with the fenced terminal result publication."""
        with self._publish_lock:
            run = self._repository().cancel_lifecycle_run(run_id)
        if run is not None:
            self.notify_cancellation(run_id)
        return run

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                run = self._repository().claim_lifecycle_run(
                    worker_id=self._worker_id,
                    lease_seconds=self._settings.worker_lease_seconds,
                    max_attempts=self._settings.worker_max_attempts,
                )
            except PersistenceError:
                logger.exception("Lifecycle claim failed worker_id=%s", self._worker_id)
                self._wake.wait(self._settings.worker_poll_seconds)
                self._wake.clear()
                continue
            if run is None:
                self._wake.wait(self._settings.worker_poll_seconds)
                self._wake.clear()
                continue
            self._execute(run)

    def _execute(self, run: LifecycleRun) -> None:
        logger.info(
            "Lifecycle execution started request_id=%s correlation_id=%s run_id=%s attempt=%s worker_id=%s",
            run.status.request_id,
            run.status.correlation_id,
            run.status.run_id,
            run.attempt_number,
            self._worker_id,
        )
        heartbeat_stop = threading.Event()
        abort_work = threading.Event()
        work_done = threading.Event()
        work_error: list[Exception] = []
        with self._active_lock:
            self._active_attempts[run.status.run_id] = abort_work
        heartbeat = threading.Thread(
            target=self._heartbeat,
            args=(run, heartbeat_stop, abort_work),
            name=f"control-translation-heartbeat-{run.status.run_id}",
            daemon=True,
        )
        work = threading.Thread(
            target=self._run_attempt,
            args=(run, abort_work, work_done, work_error),
            name=f"control-translation-attempt-{run.status.run_id}",
            daemon=True,
        )
        heartbeat.start()
        work.start()
        try:
            while not work_done.wait(0.05):
                if abort_work.is_set():
                    logger.info(
                        "Lifecycle attempt detached after cancellation or lease loss run_id=%s attempt=%s",
                        run.status.run_id,
                        run.attempt_number,
                    )
                    return
            if work_error:
                self._persist_attempt_failure(run, work_error[0])
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=1.0)
            with self._active_lock:
                self._active_attempts.pop(run.status.run_id, None)

    def _run_attempt(
        self,
        run: LifecycleRun,
        abort_work: threading.Event,
        work_done: threading.Event,
        work_error: list[Exception],
    ) -> None:
        try:
            self._process(run, abort_work)
        except OperationCancelled:
            logger.info(
                "Lifecycle execution observed cancellation request_id=%s correlation_id=%s run_id=%s",
                run.status.request_id,
                run.status.correlation_id,
                run.status.run_id,
            )
        except Exception as exc:
            logger.exception(
                "Lifecycle execution failed request_id=%s correlation_id=%s run_id=%s",
                run.status.request_id,
                run.status.correlation_id,
                run.status.run_id,
            )
            work_error.append(exc)
        finally:
            work_done.set()

    def _persist_attempt_failure(self, run: LifecycleRun, exc: Exception) -> None:
        try:
            repository = self._repository()
            prepared = repository.get_prepared_publication(run.status.run_id)
            if prepared is not None and prepared.publication_state == "publication-pending":
                logger.warning(
                    "Publication remains pending for recovery run_id=%s attempt=%s error_type=%s",
                    run.status.run_id,
                    run.attempt_number,
                    type(exc).__name__,
                )
                return
            repository.fail_lifecycle_run(
                run.status.run_id,
                worker_id=self._worker_id,
                attempt_number=run.attempt_number,
                failure=RunFailure(
                    code="translation_execution_failed",
                    detail=f"Translation execution failed ({type(exc).__name__}).",
                    retryable=True,
                ),
            )
        except PersistenceError:
            logger.exception("Unable to persist lifecycle failure run_id=%s", run.status.run_id)

    def _heartbeat(
        self,
        run: LifecycleRun,
        stop: threading.Event,
        abort_work: threading.Event,
    ) -> None:
        interval = self._settings.worker_heartbeat_seconds
        while not stop.wait(interval):
            try:
                if not self._repository().heartbeat_lifecycle_run(
                    run.status.run_id,
                    worker_id=self._worker_id,
                    attempt_number=run.attempt_number,
                    lease_seconds=self._settings.worker_lease_seconds,
                ):
                    abort_work.set()
                    return
                current = self._repository().get_lifecycle_run(run.status.run_id)
                if current is not None and current.cancel_requested:
                    abort_work.set()
            except PersistenceError:
                logger.exception(
                    "Lifecycle heartbeat failed run_id=%s",
                    run.status.run_id,
                )

    def _process(self, run: LifecycleRun, abort_work: threading.Event) -> None:
        repository = self._repository()
        prepared = repository.get_prepared_publication(run.status.run_id)
        if prepared is None:
            if self._abort_if_requested(repository, run, abort_work):
                return
            existing = repository.get_run(run.status.run_id)
            if existing is None:
                generated = capability.invoke_envelope(
                    run.request,
                    resolver=self._resolver(),
                    settings=self._settings,
                    cancellation_signal=abort_work,
                )
                result_id = f"control-translation-result:{run.status.run_id}"
                structured = generated.structured_result.model_copy(
                    update={"result_id": result_id}
                )
                existing = generated.model_copy(
                    update={
                        "run_id": run.status.run_id,
                        "result_id": result_id,
                        "request_id": run.status.request_id,
                        "correlation_id": run.status.correlation_id,
                        "structured_result": structured,
                        "result_ref": generated.result_ref.model_copy(
                            update={
                                "result_id": result_id,
                                "href": f"/v1/results/{result_id}",
                            }
                        ),
                    }
                )
                if self._abort_if_requested(repository, run, abort_work):
                    return
            lifecycle_result = build_lifecycle_result(
                existing, run.request, self._settings
            )
            completion = CanonicalCompletion(
                request_id=run.status.request_id,
                correlation_id=run.status.correlation_id,
                run_id=run.status.run_id,
                result_id=existing.result_id,
                terminal_state=lifecycle_result["terminal_state"],
                result_ref=DatabricksResultReference(
                    system="databricks",
                    catalog=self._settings.databricks_catalog,
                    schema=self._settings.databricks_schema,
                    table=self._settings.databricks_results_table,
                    key=existing.result_id,
                ),
                evidence_refs=lifecycle_result["evidence_refs"],
                content_sha256=lifecycle_result["content_sha256"],
                size_bytes=lifecycle_result["size_bytes"],
                created_at=existing.structured_result.produced_at,
            )
            with self._publish_lock:
                if self._abort_if_requested(repository, run, abort_work):
                    return
                staged = repository.prepare_lifecycle_publication(
                    run.status.run_id,
                    worker_id=self._worker_id,
                    attempt_number=run.attempt_number,
                    result_envelope=existing,
                    canonical_result=lifecycle_result,
                    completion=completion.model_dump(mode="json", by_alias=True),
                    request_hash=run.request_digest,
                    started_at=run.status.started_at or datetime.now(UTC),
                    result_id=existing.result_id,
                    terminal_state=lifecycle_result["terminal_state"],
                )
            if not staged:
                return
            prepared = repository.get_prepared_publication(run.status.run_id)
            if prepared is None:
                raise PersistenceError("Prepared result publication could not be read.")

        with self._publish_lock:
            if prepared.publication_state == "prepared" and self._abort_if_requested(
                repository, run, abort_work
            ):
                return
            if not repository.begin_lifecycle_publication(
                run.status.run_id,
                worker_id=self._worker_id,
                attempt_number=run.attempt_number,
            ):
                return
            repository.save_completed_run(
                prepared.request,
                prepared.result_envelope,
                request_hash=prepared.request_hash,
                started_at=prepared.started_at,
                canonical_result=prepared.canonical_result,
            )
            if prepared.terminal_state == "malfunction":
                repository.fail_lifecycle_run(
                    run.status.run_id,
                    worker_id=self._worker_id,
                    attempt_number=run.attempt_number,
                    failure=RunFailure(
                        code="control_translation_malfunction",
                        detail=prepared.result_envelope.structured_result.outcome_reason.detail,
                        retryable=True,
                    ),
                    result=prepared.canonical_result,
                )
                return
            completed = repository.complete_lifecycle_run(
                run.status.run_id,
                worker_id=self._worker_id,
                attempt_number=run.attempt_number,
                result=prepared.canonical_result,
                completion=prepared.completion,
                result_id=prepared.result_id,
                terminal_state=prepared.terminal_state,
            )
        logger.info(
            "metric=control_translation_lifecycle_terminal_total metric_value=1 "
            "request_id=%s correlation_id=%s run_id=%s result_id=%s persisted=%s",
            run.status.request_id,
            run.status.correlation_id,
            run.status.run_id,
            prepared.result_id,
            completed,
        )

    def _abort_if_requested(
        self,
        repository: RunRepository,
        run: LifecycleRun,
        abort_work: threading.Event,
    ) -> bool:
        """Honor cancellation and stop stale attempts before durable result writes."""
        current = repository.get_lifecycle_run(run.status.run_id)
        owns_attempt = (
            current is not None
            and current.status.status == "running"
            and current.worker_id == self._worker_id
            and current.attempt_number == run.attempt_number
        )
        if not owns_attempt:
            abort_work.set()
            logger.warning(
                "Lifecycle attempt fenced run_id=%s attempt=%s worker_id=%s",
                run.status.run_id,
                run.attempt_number,
                self._worker_id,
            )
            return True
        assert current is not None
        if current.publication_state == "publication-pending":
            return False
        if current.cancel_requested:
            repository.fail_lifecycle_run(
                run.status.run_id,
                worker_id=self._worker_id,
                attempt_number=run.attempt_number,
                failure=RunFailure(
                    code="canceled",
                    detail="Cooperative cancellation completed.",
                    retryable=False,
                ),
            )
            return True
        return bool(abort_work.is_set())


def build_lifecycle_result(
    result: ResultEnvelope, request: InvokeRequestEnvelope, settings: Settings
) -> dict:
    """Project the legacy result into the immutable async result contract."""
    structured = result.structured_result
    candidate = structured.primary_candidate
    terminal_state = (
        "translated"
        if structured.terminal_state is TerminalState.TRANSLATED
        else (
            "malfunction"
            if structured.terminal_state is TerminalState.MALFUNCTION
            else "not-translatable"
        )
    )
    evidence_refs = sorted(
        {
            reference
            for binding in structured.evidence_bindings
            for reference in binding.evidence_refs
        }
        | set(result.provenance)
    )
    primary_candidate = None
    artifacts: dict[str, dict[str, object]] = {}
    if candidate is not None:
        artifact = candidate.candidate_artifact
        content_ref = _canonical_artifact_ref(
            settings=settings,
            result_id=result.result_id,
        )
        primary_candidate = {
            "candidate_id": candidate.candidate_id,
            "target_control_class": candidate.target_control_class,
            "target_technology": candidate.target_technology,
            "target_policy_context_id": candidate.target_policy_context_id,
            "artifact_type": artifact.artifact_type,
            "content_ref": content_ref,
            "content_hash": artifact.content_hash,
            "candidate_metadata": (
                candidate.candidate_metadata.model_dump(mode="json")
                if candidate.candidate_metadata is not None
                else None
            ),
        }
        artifacts["primary"] = {
            "artifact_type": artifact.artifact_type,
            "media_type": _artifact_media_type(artifact.content_ref),
            "content": artifact.content_ref,
            "content_hash": artifact.content_hash,
            "emitted_as": artifact.emitted_as,
            "candidate_metadata": (
                candidate.candidate_metadata.model_dump(mode="json")
                if candidate.candidate_metadata is not None
                else None
            ),
        }
    payload = {
        "capability": "control-translation",
        "contract_id": "control-translation-result@1.0",
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "run_id": result.run_id,
        "result_id": result.result_id,
        "status": "completed",
        "terminal_state": terminal_state,
        "result_ref": {
            "system": "databricks",
            "catalog": settings.databricks_catalog,
            "schema": settings.databricks_schema,
            "table": settings.databricks_results_table,
            "key": result.result_id,
        },
        "evidence_refs": evidence_refs,
        "prose": structured.prose_summary,
        "primary_candidate": primary_candidate,
        "artifacts": artifacts,
        "inference": result.inference,
        "provenance": {
            "upstream_result_refs": (
                request.upstream_result_refs.model_dump(mode="json", by_alias=True)
                if request.upstream_result_refs is not None
                else None
            ),
            "loop_exhausted": (
                request.routing_metadata.loop_exhausted
                if request.routing_metadata is not None
                else None
            ),
            "completed_iterations": (
                request.routing_metadata.completed_iterations
                if request.routing_metadata is not None
                else None
            ),
            "max_iterations": (
                request.routing_metadata.max_iterations
                if request.routing_metadata is not None
                else None
            ),
        },
        "created_at": structured.produced_at.isoformat(),
    }
    content = canonical_result_bytes(payload)
    payload["content_sha256"] = f"sha256:{sha256(content).hexdigest()}"
    payload["size_bytes"] = len(content)
    return payload


def _canonical_artifact_ref(*, settings: Settings, result_id: str) -> str:
    """Point to artifact bytes inside the immutable canonical Databricks row."""
    encoded_result_id = quote(result_id, safe="")
    return (
        f"databricks://{settings.databricks_catalog}/"
        f"{settings.databricks_schema}/{settings.databricks_results_table}/"
        f"result_json?result_id={encoded_result_id}"
        "#/artifacts/primary/content"
    )


def _artifact_media_type(content: str) -> str:
    try:
        decoded = json.loads(content)
    except (TypeError, ValueError):
        return "text/plain;charset=utf-8"
    return (
        "application/json"
        if isinstance(decoded, (dict, list))
        else "text/plain;charset=utf-8"
    )
