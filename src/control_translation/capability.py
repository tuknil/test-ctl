"""Core capability orchestration: `control_translation.invoke(...)`.

This is the single entry point used by both the direct Python invocation
path and the FastAPI HTTP path (`api.py`). It owns terminal-state routing,
gate evaluation order, and result assembly. No agent or provider code
decides the terminal state directly -- they return typed data that this
function gates and interprets.
"""

from __future__ import annotations

from uuid import uuid4

from control_translation.adapters import get_adapter
from control_translation.agents.translation_agent import TranslationDoer, build_translation_doer
from control_translation.config import Settings, get_settings
from control_translation.contracts import (
    ControlTranslationRequest,
    ControlTranslationResult,
    EvidenceBinding,
    InputBindings,
    InvokeRequestEnvelope,
    OutcomeReason,
    ResultEnvelope,
    Subject,
)
from control_translation.policy_reader.base import PolicyReader
from control_translation.policy_reader.fixtures import FixturePolicyReader
from control_translation.terminal import (
    OutcomeReasonCode,
    TERMINAL_STATE_TO_STATUS,
    TerminalState,
)
from control_translation.translation.engine import EngineFailure, EngineSuccess, translate


def _build_result(
    request: ControlTranslationRequest,
    terminal_state: TerminalState,
    reason_code: OutcomeReasonCode,
    detail: str,
    primary_candidate=None,
    prose_summary: str | None = None,
) -> ControlTranslationResult:
    pattern = request.proven_pattern
    return ControlTranslationResult(
        result_id=(
            f"control-translation-result:{pattern.vulnerability_id}:"
            f"{request.target_context.target_technology}:1"
        ),
        subject=Subject(
            vulnerability_id=pattern.vulnerability_id,
            proven_pattern_id=pattern.proven_pattern_id,
            selected_control_class=pattern.selected_control_class,
        ),
        input_bindings=InputBindings(
            target_technology=request.target_context.target_technology,
            target_policy_context_id=request.target_context.target_policy_context_id,
            current_policy_snapshot_id=request.current_policy_snapshot_id,
            translation_policy_id=request.translation_policy.translation_policy_id,
            proof_record_ids=list(pattern.proof_record_ids),
        ),
        terminal_state=terminal_state,
        outcome_reason=OutcomeReason(code=reason_code, detail=detail),
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
            else []
        ),
        prose_summary=prose_summary or detail,
    )


def invoke(
    request: ControlTranslationRequest,
    *,
    settings: Settings | None = None,
    policy_reader: PolicyReader | None = None,
    doer: TranslationDoer | None = None,
) -> ResultEnvelope:
    """Direct Python invocation entry point. Providers are injectable for
    testing; defaults resolve from configured settings (fixture-backed)."""

    settings = settings or get_settings()
    policy_reader = policy_reader or FixturePolicyReader()
    doer = doer or build_translation_doer(settings)

    pattern = request.proven_pattern
    target_technology = request.target_context.target_technology

    # Gate 1: scope-declined -- invalid/malformed target technology.
    adapter = get_adapter(target_technology)
    if adapter is None:
        result = _build_result(
            request,
            TerminalState.SCOPE_DECLINED,
            OutcomeReasonCode.INVALID_INPUT,
            detail=f"Target technology '{target_technology}' is outside configured coverage.",
        )
        return _envelope(result)

    # Gate 2: insufficient-context -- no policy snapshot available and none
    # was supplied by the caller.
    snapshot = None
    if request.current_policy_snapshot_id is None:
        snapshot = policy_reader.read_snapshot(
            target_technology, request.target_context.target_policy_context_id
        )
        if snapshot is None:
            result = _build_result(
                request,
                TerminalState.INSUFFICIENT_CONTEXT,
                OutcomeReasonCode.INSUFFICIENT_POLICY_CONTEXT,
                detail=(
                    "No current policy snapshot available for "
                    f"{target_technology}/{request.target_context.target_policy_context_id}; "
                    "cannot safely translate without reading current policy."
                ),
            )
            return _envelope(result)

    # Attempt translation via engine (agent doer + mechanical judge gates).
    engine_result = translate(
        pattern=pattern,
        target_technology=target_technology,
        target_policy_context_id=request.target_context.target_policy_context_id,
        adapter=adapter,
        doer=doer,
        snapshot=snapshot,
    )

    if isinstance(engine_result, EngineFailure):
        if engine_result.reason == "provider-failure":
            result = _build_result(
                request,
                TerminalState.MALFUNCTION,
                OutcomeReasonCode.PROVIDER_FAILURE,
                detail=engine_result.detail,
            )
        else:
            result = _build_result(
                request,
                TerminalState.CANNOT_EXPRESS,
                OutcomeReasonCode.UNSUPPORTED_FEATURE,
                detail=engine_result.detail,
            )
        return _envelope(result)

    assert isinstance(engine_result, EngineSuccess)
    candidate = engine_result.candidate

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
        )
        return _envelope(result)

    result = _build_result(
        request,
        TerminalState.TRANSLATED,
        OutcomeReasonCode.TRANSLATED,
        detail="Translation succeeded.",
        primary_candidate=candidate,
        prose_summary=(
            f"Translated proven pattern {pattern.proven_pattern_id} into a "
            f"{candidate.candidate_artifact.artifact_type} candidate "
            f"({candidate.implements_discriminator.translation} translation) "
            f"for {target_technology}."
        ),
    )
    return _envelope(result)


def _envelope(result: ControlTranslationResult) -> ResultEnvelope:
    status = TERMINAL_STATE_TO_STATUS[result.terminal_state]
    return ResultEnvelope(
        run_id=str(uuid4()),
        status=status.value,
        terminal_state=result.terminal_state,
        structured_result=result,
        prose=result.prose_summary,
        reference_bundle={},
        provenance=list(result.input_bindings.proof_record_ids),
        confidence={},
        warnings=[],
        trace=[f"terminal_state={result.terminal_state.value}"],
    )


def invoke_envelope(envelope: InvokeRequestEnvelope) -> ResultEnvelope:
    """Wraps `invoke` to accept the full API request envelope shape."""

    return invoke(envelope.input)
