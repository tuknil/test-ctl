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
    InvocationRequest,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunFailure,
    SharedContractV2InvokeRequest,
    shared_waf_primary_artifact_id,
)
from control_translation.persistence import (
    LifecycleRun,
    PersistenceError,
    RunRepository,
    canonical_result_bytes,
)
from control_translation.shared_contracts_v2 import SharedContractV2Error
from control_translation.terminal import TerminalState
from control_translation.upstream import UpstreamResultResolver

logger = logging.getLogger(__name__)

RepositoryProvider = Callable[[], RunRepository]
ResolverProvider = Callable[[], UpstreamResultResolver | None]
ResultReferenceFactory = Callable[[str], DatabricksResultReference]


class LifecycleWorker:
    """Claims persisted runs and executes them independently of HTTP requests."""

    def __init__(
        self,
        repository: RepositoryProvider,
        resolver: ResolverProvider,
        settings: Settings,
        result_reference_factory: ResultReferenceFactory | None = None,
    ) -> None:
        self._repository = repository
        self._resolver = resolver
        self._settings = settings
        self._result_reference_factory = result_reference_factory
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
            failure = (
                RunFailure(
                    code=exc.code,
                    detail=exc.detail,
                    retryable=False,
                )
                if isinstance(exc, SharedContractV2Error)
                else RunFailure(
                    code="translation_execution_failed",
                    detail=f"Translation execution failed ({type(exc).__name__}).",
                    retryable=True,
                )
            )
            repository.fail_lifecycle_run(
                run.status.run_id,
                worker_id=self._worker_id,
                attempt_number=run.attempt_number,
                failure=failure,
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
                if isinstance(run.request, SharedContractV2InvokeRequest):
                    generated = capability.invoke_shared_contract_v2(
                        run.request,
                        resolver=self._resolver(),
                        settings=self._settings,
                        cancellation_signal=abort_work,
                    )
                else:
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
                existing = ResultEnvelope.model_validate(
                    existing.model_dump(mode="json")
                )
                if self._abort_if_requested(repository, run, abort_work):
                    return
            result_reference = (
                self._result_reference_factory(existing.result_id)
                if self._result_reference_factory is not None
                else DatabricksResultReference(
                    system="databricks",
                    catalog=self._settings.databricks_catalog,
                    schema=self._settings.databricks_schema,
                    table=self._settings.databricks_results_table,
                    key=existing.result_id,
                )
            )
            lifecycle_result = build_lifecycle_result(
                existing,
                run.request,
                self._settings,
                result_reference=result_reference,
            )
            completion = CanonicalCompletion(
                request_id=run.status.request_id,
                correlation_id=run.status.correlation_id,
                run_id=run.status.run_id,
                result_id=existing.result_id,
                terminal_state=lifecycle_result["terminal_state"],
                result_ref=result_reference,
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
    result: ResultEnvelope,
    request: InvocationRequest,
    settings: Settings,
    *,
    result_reference: DatabricksResultReference | None = None,
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
    if structured.shared_contract_version is not None:
        aggregate_artifact_id = None
        if candidate is not None:
            aggregate = candidate.candidate_artifact
            aggregate_artifact_id = shared_waf_primary_artifact_id(
                aggregate.content_hash
            )
            artifacts[aggregate_artifact_id] = {
                "source_artifact_id": structured.subject.proven_pattern_id,
                "role": "primary",
                "kind": "policy-fragment",
                "order": 0,
                "artifact_type": aggregate.artifact_type,
                "media_type": _artifact_media_type(aggregate.content_ref),
                "content": aggregate.content_ref,
                "content_hash": aggregate.content_hash,
                "emitted_as": aggregate.emitted_as,
                "candidate_metadata": (
                    candidate.candidate_metadata.model_dump(mode="json")
                    if candidate.candidate_metadata is not None
                    else None
                ),
            }
        for item in structured.target_artifacts:
            artifacts[item.artifact_id] = {
                "source_artifact_id": item.source_artifact_id,
                "source_role": item.role,
                "role": "supporting",
                "kind": item.kind,
                "order": item.order + (1 if aggregate_artifact_id is not None else 0),
                "artifact_type": item.artifact_type,
                "media_type": _artifact_media_type(item.content),
                "content": item.content,
                "content_hash": item.content_hash,
                "emitted_as": "control-specific-mitigation-candidate",
            }
        if candidate is not None and aggregate_artifact_id is not None:
            aggregate = candidate.candidate_artifact
            primary_candidate = {
                "candidate_id": candidate.candidate_id,
                "target_control_class": candidate.target_control_class,
                "target_technology": candidate.target_technology,
                "target_policy_context_id": candidate.target_policy_context_id,
                "artifact_id": aggregate_artifact_id,
                "artifact_type": aggregate.artifact_type,
                "content_ref": _canonical_artifact_ref(
                    settings=settings,
                    result_id=result.result_id,
                    artifact_id=aggregate_artifact_id,
                    result_reference=result_reference,
                ),
                "content_hash": aggregate.content_hash,
                "candidate_metadata": (
                    candidate.candidate_metadata.model_dump(mode="json")
                    if candidate.candidate_metadata is not None
                    else None
                ),
            }
    elif candidate is not None:
        artifact = candidate.candidate_artifact
        content_ref = _canonical_artifact_ref(
            settings=settings,
            result_id=result.result_id,
            result_reference=result_reference,
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
        "contract_id": (
            "control-translation-result@2.0"
            if structured.shared_contract_version is not None
            else "control-translation-result@1.0"
        ),
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "run_id": result.run_id,
        "result_id": result.result_id,
        "status": "completed",
        "terminal_state": terminal_state,
        "result_ref": (
            result_reference
            or DatabricksResultReference(
                system="databricks",
                catalog=settings.databricks_catalog,
                schema=settings.databricks_schema,
                table=settings.databricks_results_table,
                key=result.result_id,
            )
        ).model_dump(mode="json", by_alias=True),
        "evidence_refs": evidence_refs,
        "prose": structured.prose_summary,
        "primary_candidate": primary_candidate,
        "artifacts": artifacts,
        "inference": result.inference,
        "provenance": {
            "upstream_inputs": [
                item.model_dump(mode="json", by_alias=True)
                for item in request.upstream_inputs
            ] if request.upstream_inputs is not None else None,
            "upstream_result_refs": (
                request.upstream_result_refs.model_dump(mode="json", by_alias=True)
                if isinstance(request, InvokeRequestEnvelope)
                and request.upstream_result_refs is not None
                else None
            ),
            "loop_exhausted": (
                request.routing_metadata.loop_exhausted
                if isinstance(request, InvokeRequestEnvelope)
                and request.routing_metadata is not None
                else None
            ),
            "completed_iterations": (
                request.routing_metadata.completed_iterations
                if isinstance(request, InvokeRequestEnvelope)
                and request.routing_metadata is not None
                else None
            ),
            "max_iterations": (
                request.routing_metadata.max_iterations
                if isinstance(request, InvokeRequestEnvelope)
                and request.routing_metadata is not None
                else None
            ),
        },
        "created_at": structured.produced_at.isoformat(),
    }
    if structured.shared_contract_version is not None:
        assert structured.pre_translation_verification is not None
        assert structured.accounting is not None
        payload.update(
            {
                "shared_contract_version": structured.shared_contract_version,
                "profile_id": structured.profile_id,
                "pre_translation_verification": structured.pre_translation_verification.model_dump(
                    mode="json"
                ),
                "accounting": structured.accounting.model_dump(mode="json"),
                "translation_mappings": [
                    item.model_dump(mode="json")
                    for item in structured.translation_mappings
                ],
                "translated_directives": [
                    item.model_dump(mode="json")
                    for item in structured.translated_directives
                ],
            }
        )
    content = canonical_result_bytes(payload)
    payload["content_sha256"] = f"sha256:{sha256(content).hexdigest()}"
    payload["size_bytes"] = len(content)
    return payload


def _canonical_artifact_ref(
    *,
    settings: Settings,
    result_id: str,
    artifact_id: str = "primary",
    result_reference: DatabricksResultReference | None = None,
) -> str:
    """Point to artifact bytes inside the selected immutable result object."""
    encoded_result_id = quote(result_id, safe="")
    if result_reference is not None and result_reference.system == "workflow-lab":
        return (
            f"workflow-lab-result://immutable-results/{encoded_result_id}"
            f"#/artifacts/{quote(artifact_id, safe='')}/content"
        )
    return (
        f"databricks://{settings.databricks_catalog}/"
        f"{settings.databricks_schema}/{settings.databricks_results_table}/"
        f"result_json?result_id={encoded_result_id}"
        f"#/artifacts/{quote(artifact_id, safe='')}/content"
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
