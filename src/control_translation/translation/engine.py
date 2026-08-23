"""Translation engine: orchestrates the doer (agent) call and the
deterministic judge gates (syntax validation + conflict detection).

This module returns either a validated `PrimaryCandidate` ready for a
`translated` verdict, or a structured failure reason the capability core
uses to route to `cannot-express` / `insufficient-context` / `malfunction`.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from control_translation.adapters.base import TargetAdapter
from control_translation.agents.translation_agent import TranslationDoer
from control_translation.contracts import (
    CandidateArtifact,
    CollateralImpactPrior,
    ImplementsDiscriminator,
    Placement,
    PrimaryCandidate,
    ProvenMitigationPattern,
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.translation import conflict_checker, syntax_validator


@dataclass
class EngineFailure:
    reason: str  # "unsupported-feature" | "policy-conflict" | "provider-failure"
    detail: str


@dataclass
class EngineSuccess:
    candidate: PrimaryCandidate


EngineResult = EngineFailure | EngineSuccess


def translate(
    pattern: ProvenMitigationPattern,
    target_technology: str,
    target_policy_context_id: str,
    adapter: TargetAdapter,
    doer: TranslationDoer,
    snapshot: PolicySnapshot | None,
    allow_narrower_translation: bool = True,
    allow_equivalent_translation: bool = True,
) -> EngineResult:
    # Mechanical gate 1: can this target technology plausibly express the
    # discriminator at all? Cheap check before spending an agent call.
    if not adapter.supports_feature(pattern.discriminator_description):
        return EngineFailure(
            reason="unsupported-feature",
            detail=(
                f"{target_technology} adapter does not recognize a supported "
                f"feature for discriminator: {pattern.discriminator_description}"
            ),
        )

    # Doer: propose a candidate artifact (agent output, not yet trusted).
    try:
        proposal = doer.propose(
            pattern=pattern,
            target_technology=target_technology,
            artifact_type=adapter.artifact_type,
            snapshot=snapshot,
        )
    except Exception as exc:  # provider/model failure
        return EngineFailure(reason="provider-failure", detail=str(exc))

    if proposal.translation_label not in ("exact", "equivalent", "narrower"):
        return EngineFailure(
            reason="provider-failure",
            detail=(
                "Doer returned an invalid translation_label: "
                f"{proposal.translation_label!r}"
            ),
        )

    if proposal.translation_label == "equivalent" and not allow_equivalent_translation:
        return EngineFailure(
            reason="unsupported-feature",
            detail="Translation policy does not allow equivalent translations.",
        )
    if proposal.translation_label == "narrower" and not allow_narrower_translation:
        return EngineFailure(
            reason="unsupported-feature",
            detail="Translation policy does not allow narrower translations.",
        )

    # Judge gate 1: syntax validation (mechanical).
    syntax_result = syntax_validator.validate(adapter, proposal.candidate_content)
    if not syntax_result.valid:
        return EngineFailure(
            reason="unsupported-feature",
            detail="; ".join(syntax_result.errors) or "Candidate failed syntax validation.",
        )

    # Judge gate 2: conflict/placement detection (mechanical).
    conflicts = conflict_checker.detect_conflicts(
        adapter, proposal.candidate_content, snapshot
    )

    content_hash = "sha256:" + sha256(proposal.candidate_content.encode("utf-8")).hexdigest()

    candidate = PrimaryCandidate(
        candidate_id=f"control-candidate:{pattern.vulnerability_id}:{target_technology}:1",
        target_control_class=pattern.selected_control_class,
        target_technology=target_technology,
        target_policy_context_id=target_policy_context_id,
        candidate_artifact=CandidateArtifact(
            artifact_type=adapter.artifact_type,
            content_ref=proposal.candidate_content,
            content_hash=content_hash,
        ),
        implements_discriminator=ImplementsDiscriminator(
            source_discriminator_id=pattern.discriminator_id,
            translation=proposal.translation_label,
            justification=proposal.justification,
            evidence_refs=list(pattern.proof_record_ids),
        ),
        placement=Placement(conflict_notes=conflicts),
        inherited_collateral_impact_prior=CollateralImpactPrior(
            verdict="unknown",
            confidence="unknown",
            basis="Not measured by control-translation; inherited placeholder.",
            measured=False,
        ),
        translation_assumptions=proposal.translation_assumptions,
        limitations=proposal.limitations,
        provenance=list(pattern.proof_record_ids),
    )
    return EngineSuccess(candidate=candidate)
