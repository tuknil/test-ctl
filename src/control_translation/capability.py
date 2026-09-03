"""Core capability orchestration: `control_translation.invoke(...)`.

This is the single entry point used by both the direct Python invocation
path and the FastAPI HTTP path (`api.py`). It owns terminal-state routing,
gate evaluation order, and result assembly. No agent or provider code
decides the terminal state directly -- they return typed data that this
function gates and interprets.
"""

from __future__ import annotations

import logging
import re
from hashlib import sha256
from uuid import uuid4

from control_translation.adapters import get_adapter
from control_translation.agents.translation_agent import (
    TranslationDoer,
    build_translation_doer,
)
from control_translation.cancellation import CancellationSignal, check_cancelled
from control_translation.config import Settings, get_settings
from control_translation.contracts import (
    BypassCounterexample,
    ControlTranslationRequest,
    ControlTranslationResult,
    DirectBypassValidationResult,
    EvidenceBinding,
    InputBindings,
    InvokeRequestEnvelope,
    OutcomeReason,
    ProofLoopQualification,
    ProofLoopRequestContext,
    ProofLoopTranslationRequirements,
    ResultEnvelope,
    ResultReference,
    Subject,
    TargetContext,
)
from control_translation.policy_reader.base import PolicyReader
from control_translation.policy_reader.fixtures import FixturePolicyReader
from control_translation.terminal import (
    TERMINAL_STATE_TO_STATUS,
    OutcomeReasonCode,
    TerminalState,
)
from control_translation.translation.engine import (
    EngineFailure,
    EngineSuccess,
    translate,
)
from control_translation.upstream import (
    UpstreamResolutionError,
    UpstreamResultResolver,
    resolve_proof_loop,
)

logger = logging.getLogger(__name__)

_TARGET_CONTROL_CLASSES = {
    "akamai-waf": "waf",
    "firewall-generic": "firewall",
    "edr-s1": "edr",
}

_CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _build_result(
    request: ControlTranslationRequest,
    terminal_state: TerminalState,
    reason_code: OutcomeReasonCode,
    detail: str,
    primary_candidate=None,
    prose_summary: str | None = None,
    configured_poc_defaults_used: bool = False,
    proof_loop_qualification: ProofLoopQualification | None = None,
    bypass_counterexample: BypassCounterexample | None = None,
    bypass_evidence_refs: list[str] | None = None,
) -> ControlTranslationResult:
    pattern = request.proven_pattern
    target_context = request.target_context
    assert pattern is not None
    assert target_context is not None
    assert target_context.target_technology is not None
    assert target_context.target_policy_context_id is not None
    return ControlTranslationResult(
        result_id=(
            f"control-translation-result:{pattern.vulnerability_id}:"
            f"{target_context.target_technology}:{uuid4()}"
        ),
        subject=Subject(
            vulnerability_id=pattern.vulnerability_id,
            proven_pattern_id=pattern.proven_pattern_id,
            selected_control_class=pattern.selected_control_class,
        ),
        input_bindings=InputBindings(
            target_technology=target_context.target_technology,
            target_policy_context_id=target_context.target_policy_context_id,
            configured_poc_defaults_used=configured_poc_defaults_used,
            current_policy_snapshot_id=request.current_policy_snapshot_id,
            translation_policy_id=request.translation_policy.translation_policy_id,
            proof_record_ids=list(pattern.proof_record_ids),
        ),
        terminal_state=terminal_state,
        outcome_reason=OutcomeReason(code=reason_code, detail=detail),
        proof_loop_qualification=proof_loop_qualification,
        bypass_counterexample=bypass_counterexample,
        primary_candidate=primary_candidate,
        evidence_bindings=(
            [
                EvidenceBinding(
                    claim="discriminator-preserved",
                    evidence_refs=list(pattern.proof_record_ids),
                ),
                EvidenceBinding(
                    claim="target-feature-supported",
                    evidence_refs=[request.target_context.target_technology],
                ),
            ]
            if primary_candidate is not None
            else (
                [
                    EvidenceBinding(
                        claim="limitation",
                        evidence_refs=list(bypass_evidence_refs or []),
                    )
                ]
                if bypass_evidence_refs
                else []
            )
        ),
        prose_summary=prose_summary or detail,
    )


def invoke(
    request: ControlTranslationRequest,
    *,
    settings: Settings | None = None,
    policy_reader: PolicyReader | None = None,
    doer: TranslationDoer | None = None,
    correlation_id: str | None = None,
    proof_loop_qualification: ProofLoopQualification | None = None,
    translation_requirements: ProofLoopTranslationRequirements | None = None,
    request_context: ProofLoopRequestContext | None = None,
    cancellation_signal: CancellationSignal | None = None,
) -> ResultEnvelope:
    """Direct Python invocation entry point. Providers are injectable for
    testing; defaults resolve from configured settings (fixture-backed)."""

    check_cancelled(cancellation_signal)
    settings = settings or get_settings()
    policy_reader = policy_reader or FixturePolicyReader()
    doer = doer or build_translation_doer(settings)

    request, configured_poc_defaults_used = _with_effective_target_context(
        request, settings
    )
    if request.proven_pattern is None:
        return _insufficient_context_envelope(
            detail="No proven pattern or upstream result references were supplied.",
            settings=settings,
            correlation_id=correlation_id,
            target_context=request.target_context,
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )

    pattern = request.proven_pattern
    target_context = request.target_context
    assert target_context is not None
    target_technology = target_context.target_technology
    assert target_technology is not None

    # Gate 1: scope-declined -- invalid/malformed target technology.
    adapter = get_adapter(target_technology)
    if adapter is None:
        result = _build_result(
            request,
            TerminalState.SCOPE_DECLINED,
            OutcomeReasonCode.INVALID_INPUT,
            detail=f"Target technology '{target_technology}' is outside configured coverage.",
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=False,
            correlation_id=correlation_id,
        )

    expected_class = _TARGET_CONTROL_CLASSES[target_technology]
    if pattern.selected_control_class.lower() != expected_class:
        result = _build_result(
            request,
            TerminalState.SCOPE_DECLINED,
            OutcomeReasonCode.INVALID_INPUT,
            detail=(
                f"Selected control class '{pattern.selected_control_class}' is not "
                f"compatible with target technology '{target_technology}' "
                f"(expected '{expected_class}')."
            ),
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=False,
            correlation_id=correlation_id,
        )

    # Gate 2: insufficient-context -- an ID alone is not policy content. Always
    # resolve the current snapshot so conflict checks cannot be bypassed.
    check_cancelled(cancellation_signal)
    snapshot = policy_reader.read_snapshot(
        target_technology,
        target_context.target_policy_context_id or "",
        cancellation_signal=cancellation_signal,
    )
    check_cancelled(cancellation_signal)
    if snapshot is None:
        result = _build_result(
            request,
            TerminalState.INSUFFICIENT_CONTEXT,
            OutcomeReasonCode.INSUFFICIENT_POLICY_CONTEXT,
            detail=(
                "No current policy snapshot available for "
                f"{target_technology}/{target_context.target_policy_context_id}; "
                "cannot safely translate without reading current policy."
            ),
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=False,
            correlation_id=correlation_id,
        )

    if (
        request.current_policy_snapshot_id is not None
        and request.current_policy_snapshot_id != snapshot.snapshot_id
    ):
        result = _build_result(
            request,
            TerminalState.SCOPE_DECLINED,
            OutcomeReasonCode.INVALID_INPUT,
            detail=(
                f"Requested policy snapshot '{request.current_policy_snapshot_id}' "
                f"does not match resolved snapshot '{snapshot.snapshot_id}'."
            ),
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=False,
            correlation_id=correlation_id,
        )

    # Attempt translation via engine (agent doer + mechanical judge gates).
    engine_result = translate(
        pattern=pattern,
        target_technology=target_technology,
        target_policy_context_id=target_context.target_policy_context_id or "",
        adapter=adapter,
        doer=doer,
        snapshot=snapshot,
        translation_requirements=translation_requirements,
        request_context=request_context,
        allow_narrower_translation=request.translation_policy.allow_narrower_translation,
        allow_equivalent_translation=request.translation_policy.allow_equivalent_translation,
        cancellation_signal=cancellation_signal,
    )
    check_cancelled(cancellation_signal)

    if isinstance(engine_result, EngineFailure):
        if engine_result.reason == "provider-failure":
            result = _build_result(
                request,
                TerminalState.MALFUNCTION,
                OutcomeReasonCode.PROVIDER_FAILURE,
                detail=engine_result.detail,
                configured_poc_defaults_used=configured_poc_defaults_used,
                proof_loop_qualification=proof_loop_qualification,
            )
        else:
            result = _build_result(
                request,
                TerminalState.CANNOT_EXPRESS,
                OutcomeReasonCode.UNSUPPORTED_FEATURE,
                detail=engine_result.detail,
                configured_poc_defaults_used=configured_poc_defaults_used,
                proof_loop_qualification=proof_loop_qualification,
            )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=engine_result.llm_invoked,
            proposal_source=engine_result.proposal_source,
            correlation_id=correlation_id,
        )

    assert isinstance(engine_result, EngineSuccess)
    candidate = engine_result.candidate
    if proof_loop_qualification and not proof_loop_qualification.bypass_cleared:
        candidate = candidate.model_copy(
            update={
                "limitations": [
                    *candidate.limitations,
                    (
                        "PoC candidate loop exhausted after "
                        f"{proof_loop_qualification.completed_iterations} iterations; "
                        "the latest Bypass Validation state was bypass-found. "
                        "This candidate is not bypass-cleared."
                    ),
                ]
            }
        )

    # Gate 3: scope-declined -- unresolved policy conflicts.
    if candidate.placement.conflict_notes:
        result = _build_result(
            request,
            TerminalState.SCOPE_DECLINED,
            OutcomeReasonCode.POLICY_CONFLICT,
            detail=(
                "Candidate conflicts with existing policy: "
                + "; ".join(candidate.placement.conflict_notes)
            ),
            primary_candidate=candidate,
            configured_poc_defaults_used=configured_poc_defaults_used,
            proof_loop_qualification=proof_loop_qualification,
        )
        return _envelope(
            result,
            settings=settings,
            llm_invoked=engine_result.llm_invoked,
            proposal_source=engine_result.proposal_source,
            correlation_id=correlation_id,
        )

    result = _build_result(
        request,
        TerminalState.TRANSLATED,
        OutcomeReasonCode.TRANSLATED,
        detail=(
            "Translation succeeded."
            if not proof_loop_qualification
            or proof_loop_qualification.bypass_cleared
            else (
                "Translation succeeded via the PoC exhaustion route; the latest "
                "candidate remains bypass-found and is not bypass-cleared."
            )
        ),
        primary_candidate=candidate,
        prose_summary=(
            f"Translated {'proven pattern' if not proof_loop_qualification or proof_loop_qualification.bypass_cleared else 'loop-exhausted candidate pattern'} "
            f"{pattern.proven_pattern_id} into a "
            f"{candidate.candidate_artifact.artifact_type} candidate "
            f"({candidate.implements_discriminator.translation} translation) "
            f"for {target_technology}."
        ),
        configured_poc_defaults_used=configured_poc_defaults_used,
        proof_loop_qualification=proof_loop_qualification,
    )
    return _envelope(
        result,
        settings=settings,
        llm_invoked=engine_result.llm_invoked,
        proposal_source=engine_result.proposal_source,
        correlation_id=correlation_id,
    )


def _envelope(
    result: ControlTranslationResult,
    *,
    settings: Settings,
    llm_invoked: bool,
    proposal_source: str = "none",
    correlation_id: str | None = None,
) -> ResultEnvelope:
    status = TERMINAL_STATE_TO_STATUS[result.terminal_state]
    effective_correlation_id = correlation_id or str(uuid4())
    return ResultEnvelope(
        run_id=str(uuid4()),
        result_id=result.result_id,
        status=status.value,
        terminal_state=result.terminal_state,
        correlation_id=effective_correlation_id,
        result_ref=ResultReference(
            result_id=result.result_id,
            href=f"/v1/results/{result.result_id}",
        ),
        structured_result=result,
        prose=result.prose_summary,
        reference_bundle={},
        provenance=list(result.input_bindings.proof_record_ids),
        confidence={},
        warnings=[],
        trace=[f"terminal_state={result.terminal_state.value}"],
        inference={
            "execution_mode": "live" if settings.is_live else "fixture",
            "provider": settings.model_provider,
            "model": settings.model_name,
            "llm_invoked": llm_invoked and settings.is_live,
            "proposal_source": proposal_source,
            "credentials_configured": settings.credentials_configured,
        },
    )


def invoke_envelope(
    envelope: InvokeRequestEnvelope,
    *,
    resolver: UpstreamResultResolver | None = None,
    settings: Settings | None = None,
    cancellation_signal: CancellationSignal | None = None,
) -> ResultEnvelope:
    """Wraps `invoke` to accept the full API request envelope shape."""

    check_cancelled(cancellation_signal)
    settings = settings or get_settings()
    request = envelope.input
    references = envelope.upstream_result_refs
    if references is not None:
        if resolver is None:
            result = _insufficient_context_envelope(
                detail="Referenced upstream results cannot be fetched with the current configuration.",
                settings=settings,
                correlation_id=envelope.correlation_id,
                target_context=request.target_context,
                configured_poc_defaults_used=request.target_context is None,
                reference_bundle=references.model_dump(mode="json", by_alias=True),
            )
            return _bind_request_context(result, envelope)
        try:
            resolved = resolve_proof_loop(
                references,
                resolver,
                correlation_id=envelope.correlation_id,
                subject_record_revision_id=envelope.subject_record_revision_id,
                routing_metadata=envelope.routing_metadata,
                expected_vulnerability_id=(
                    envelope.subject.vulnerability_id if envelope.subject else None
                ),
                expected_candidate_id=(
                    envelope.subject.candidate_id if envelope.subject else None
                ),
                cancellation_signal=cancellation_signal,
            )
        except UpstreamResolutionError as exc:
            logger.error(
                "Upstream proof-loop resolution failed correlation_id=%s "
                "subject_record_revision_id=%s",
                envelope.correlation_id or "-",
                envelope.subject_record_revision_id or "-",
                exc_info=(type(exc), exc, exc.__traceback__),
            )
            result = _insufficient_context_envelope(
                detail=str(exc),
                settings=settings,
                correlation_id=envelope.correlation_id,
                target_context=request.target_context,
                configured_poc_defaults_used=request.target_context is None,
                reference_bundle=references.model_dump(mode="json", by_alias=True),
            )
            return _bind_request_context(result, envelope)
        caller_target = request.target_context or TargetContext()
        request = request.model_copy(
            update={
                "proven_pattern": resolved.pattern,
                "target_context": TargetContext(
                    target_technology=(
                        caller_target.target_technology
                        or resolved.target_technology
                    ),
                    target_policy_context_id=(
                        caller_target.target_policy_context_id
                        or resolved.target_policy_context_id
                    ),
                ),
            }
        )

    result = invoke(
        request,
        settings=settings,
        correlation_id=envelope.correlation_id,
        proof_loop_qualification=(
            resolved.qualification if references is not None else None
        ),
        translation_requirements=(
            resolved.translation_requirements if references is not None else None
        ),
        request_context=(resolved.request_context if references is not None else None),
        cancellation_signal=cancellation_signal,
    )
    check_cancelled(cancellation_signal)
    if references is not None and resolved.qualification.route == "poc-exhaustion":
        structured = result.structured_result
        evidence_bindings = list(structured.evidence_bindings)
        if resolved.bypass_evidence_refs:
            evidence_bindings.append(
                EvidenceBinding(
                    claim="limitation",
                    evidence_refs=list(resolved.bypass_evidence_refs),
                )
            )
        result = result.model_copy(
            update={
                "structured_result": structured.model_copy(
                    update={
                        "bypass_counterexample": resolved.bypass_counterexample,
                        "evidence_bindings": evidence_bindings,
                    }
                )
            }
        )
    return _bind_request_context(result, envelope)


def normalize_direct_bypass_request(
    bypass_result: DirectBypassValidationResult,
) -> InvokeRequestEnvelope:
    """Create a durable internal request for a direct bypass compatibility call."""
    source_candidate_id = bypass_result.subject.vulnerability_id
    vulnerability_match = _CVE_ID.search(source_candidate_id)
    vulnerability_id = (
        vulnerability_match.group(0).upper()
        if vulnerability_match is not None
        else "unknown"
    )
    request = ControlTranslationRequest(
        proven_pattern={
            "proven_pattern_id": f"bypass-found:{source_candidate_id}",
            "vulnerability_id": vulnerability_id,
            "selected_control_class": "waf",
            "discriminator_id": source_candidate_id,
            "discriminator_description": bypass_result.feedback.observed_failure,
            "pattern_summary": bypass_result.feedback.do_not_repeat,
            "proof_record_ids": [
                bypass_result.mitigation_result_id,
                bypass_result.result_id,
            ],
        }
    )
    return InvokeRequestEnvelope(
        input=request,
        subject={
            "vulnerability_id": vulnerability_id,
            "candidate_id": source_candidate_id,
        },
        request_id=bypass_result.result_id,
        correlation_id=bypass_result.correlation_id,
        idempotency_key=bypass_result.result_id,
        scope_config={
            "compatibility_input_contract": bypass_result.contract_id,
            "source_bypass_result_id": bypass_result.result_id,
            "source_bypass_result_sha256": sha256(
                bypass_result.model_dump_json().encode("utf-8")
            ).hexdigest(),
        },
        provenance={
            "caller": "bypass-validation",
            "source": "direct-result-compatibility",
        },
    )


def decline_direct_bypass(
    request: InvokeRequestEnvelope,
    bypass_result: DirectBypassValidationResult,
    *,
    settings: Settings | None = None,
) -> ResultEnvelope:
    """Decline a directly submitted bypass result without inference."""
    settings = settings or get_settings()
    effective_request, configured_defaults = _with_effective_target_context(
        request.input, settings
    )
    evidence_refs = sorted(
        {
            bypass_result.bypass_counterexample.sample_ref,
            *bypass_result.bypass_counterexample.evidence_refs,
            *bypass_result.feedback.evidence_refs,
        }
    )
    result = _build_result(
        effective_request,
        TerminalState.SCOPE_DECLINED,
        OutcomeReasonCode.BYPASS_FOUND_REQUIRES_REGENERATION,
        detail=(
            "Bypass Validation proved that this candidate is bypassable. "
            "The direct result does not contain authoritative proof that the "
            "orchestration candidate loop exhausted 10 iterations; start a new "
            "generation cycle or submit the complete orchestration envelope."
        ),
        configured_poc_defaults_used=configured_defaults,
        bypass_counterexample=bypass_result.bypass_counterexample,
        bypass_evidence_refs=evidence_refs,
    )
    response = _envelope(
        result,
        settings=settings,
        llm_invoked=False,
        correlation_id=request.correlation_id,
    )
    response = _bind_request_context(response, request)
    return response.model_copy(
        update={
            "reference_bundle": {
                "mitigation_check": bypass_result.mitigation_result_ref.model_dump(
                    mode="json", by_alias=True
                ),
                "bypass_validation": bypass_result.result_ref.model_dump(
                    mode="json", by_alias=True
                ),
            }
        }
    )


def _with_effective_target_context(
    request: ControlTranslationRequest,
    settings: Settings,
) -> tuple[ControlTranslationRequest, bool]:
    caller_target = request.target_context or TargetContext()
    configured_defaults_used = (
        caller_target.target_technology is None
        or caller_target.target_policy_context_id is None
    )
    return (
        request.model_copy(
            update={
                "target_context": TargetContext(
                    target_technology=(
                        caller_target.target_technology
                        or settings.default_target_technology
                    ),
                    target_policy_context_id=(
                        caller_target.target_policy_context_id
                        or settings.default_target_policy_context_id
                    ),
                )
            }
        ),
        configured_defaults_used,
    )


def _bind_request_context(
    result: ResultEnvelope,
    request: InvokeRequestEnvelope,
) -> ResultEnvelope:
    references = request.upstream_result_refs
    return result.model_copy(
        update={
            "request_id": request.request_id,
            "upstream_result_refs": references,
            "reference_bundle": (
                references.model_dump(mode="json", by_alias=True)
                if references is not None
                else {}
            ),
        }
    )


def _insufficient_context_envelope(
    *,
    detail: str,
    settings: Settings,
    correlation_id: str | None,
    target_context: TargetContext | None,
    configured_poc_defaults_used: bool,
    reference_bundle: dict | None = None,
) -> ResultEnvelope:
    """Return a typed result when referenced inputs cannot be safely assembled."""
    technology = (
        target_context.target_technology
        if target_context and target_context.target_technology
        else settings.default_target_technology
    )
    policy_context = (
        target_context.target_policy_context_id
        if target_context and target_context.target_policy_context_id
        else settings.default_target_policy_context_id
    )
    result = ControlTranslationResult(
        result_id=f"control-translation-result:unknown:{technology}:{uuid4()}",
        subject=Subject(
            vulnerability_id="unknown",
            proven_pattern_id="unresolved",
            selected_control_class="unknown",
        ),
        input_bindings=InputBindings(
            target_technology=technology,
            target_policy_context_id=policy_context,
            configured_poc_defaults_used=configured_poc_defaults_used,
            translation_policy_id="control-translation-policy:mvp1",
            proof_record_ids=[],
        ),
        terminal_state=TerminalState.INSUFFICIENT_CONTEXT,
        outcome_reason=OutcomeReason(
            code=OutcomeReasonCode.INSUFFICIENT_PATTERN_CONTEXT,
            detail=detail,
        ),
        prose_summary=detail,
    )
    envelope = _envelope(
        result,
        settings=settings,
        llm_invoked=False,
        correlation_id=correlation_id,
    )
    return envelope.model_copy(update={"reference_bundle": reference_bundle or {}})
