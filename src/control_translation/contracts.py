"""Pydantic models for the control-translation request/result contract.

Shape mirrors `docs/cfs-source.md` §1-§2 (`ControlTranslationRequest` /
`ControlTranslationResult`). These models are the trusted, validated data
that flow through the capability core. No raw text is treated as trusted
until it has passed through one of these models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from control_translation.terminal import OutcomeReasonCode, TerminalState


# ---------------------------------------------------------------------------
# Shared value types
# ---------------------------------------------------------------------------


class ProvenMitigationPattern(BaseModel):
    """A proven mitigation pattern produced upstream by the fast proof loop
    (defense-generation -> mitigation-check + bypass-validation)."""

    proven_pattern_id: str
    vulnerability_id: str
    selected_control_class: str
    discriminator_id: str
    discriminator_description: str
    pattern_summary: str
    proof_record_ids: list[str] = Field(min_length=2)

    @field_validator("proof_record_ids")
    @classmethod
    def validate_proof_lineage(cls, value: list[str]) -> list[str]:
        """Validate promotion lineage without re-performing upstream proof."""
        if len(value) != len(set(value)):
            raise ValueError("proof_record_ids must be unique")
        if not any(item.startswith("mitigation-check-result:") for item in value):
            raise ValueError("a mitigation-check result reference is required")
        if not any(item.startswith("bypass-validation-result:") for item in value):
            raise ValueError("a bypass-validation result reference is required")
        return value


class TargetContext(BaseModel):
    """Identifies the target control technology and policy context."""

    target_technology: str = Field(
        description="e.g. akamai-waf, firewall-generic, edr-s1"
    )
    target_policy_context_id: str


class TranslationPolicy(BaseModel):
    """Dials/config for how aggressive or conservative translation should be."""

    translation_policy_id: str = "control-translation-policy:mvp1"
    allow_narrower_translation: bool = True
    allow_equivalent_translation: bool = True


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class ControlTranslationRequest(BaseModel):
    """Input contract for a single control-translation invocation."""

    proven_pattern: ProvenMitigationPattern
    target_context: TargetContext
    translation_policy: TranslationPolicy = Field(default_factory=TranslationPolicy)
    current_policy_snapshot_id: Optional[str] = Field(
        default=None,
        description=(
            "Caller-supplied snapshot id. If omitted, the capability will "
            "attempt to read one via the configured PolicyReader provider."
        ),
    )


# ---------------------------------------------------------------------------
# Result substructures
# ---------------------------------------------------------------------------


class OutcomeReason(BaseModel):
    code: OutcomeReasonCode
    detail: str


class ImplementsDiscriminator(BaseModel):
    source_discriminator_id: str
    translation: str = Field(description="exact | equivalent | narrower")
    justification: str
    evidence_refs: list[str] = Field(default_factory=list)


class Placement(BaseModel):
    policy_section: Optional[str] = None
    ordering_constraints: list[str] = Field(default_factory=list)
    conflict_notes: list[str] = Field(default_factory=list)


class CollateralImpactPrior(BaseModel):
    verdict: str = Field(description="low | medium | high | unknown | abstained")
    confidence: str = Field(description="high | medium | low | unknown")
    basis: str
    measured: bool = False


class CandidateArtifact(BaseModel):
    artifact_type: str = Field(
        description="akamai-waf-rule | firewall-rule | proxy-policy | edr-rule | other"
    )
    content_ref: str
    content_hash: str
    emitted_as: str = "control-specific-mitigation-candidate"


class PrimaryCandidate(BaseModel):
    candidate_id: str
    target_control_class: str
    target_technology: str
    target_policy_context_id: str
    candidate_artifact: CandidateArtifact
    implements_discriminator: ImplementsDiscriminator
    placement: Placement = Field(default_factory=Placement)
    inherited_collateral_impact_prior: CollateralImpactPrior
    translation_assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)


class EvidenceBinding(BaseModel):
    claim: str = Field(
        description="discriminator-preserved | target-feature-supported | policy-placement | limitation"
    )
    evidence_refs: list[str] = Field(default_factory=list)


class Subject(BaseModel):
    vulnerability_id: str
    proven_pattern_id: str
    selected_control_class: str


class InputBindings(BaseModel):
    target_technology: str
    target_policy_context_id: str
    current_policy_snapshot_id: Optional[str] = None
    translation_policy_id: str
    proof_record_ids: list[str] = Field(default_factory=list)


class ControlTranslationResult(BaseModel):
    """Output contract. Field shape mirrors CFS §2 `ControlTranslationResult`."""

    contract_id: str = "control-translation@1.0"
    result_id: str
    produced_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    subject: Subject
    input_bindings: InputBindings
    terminal_state: TerminalState
    outcome_reason: OutcomeReason
    primary_candidate: Optional[PrimaryCandidate] = None
    evidence_bindings: list[EvidenceBinding] = Field(default_factory=list)
    prose_summary: str


# ---------------------------------------------------------------------------
# API envelope (per api-invocation-surface.md)
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    caller: Optional[str] = None
    source: Optional[str] = None


class InvokeRequestEnvelope(BaseModel):
    input: ControlTranslationRequest
    scope_config: dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None
    provenance: Optional[Provenance] = None


class ResultEnvelope(BaseModel):
    capability: str = "control-translation"
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    status: str
    terminal_state: TerminalState
    structured_result: ControlTranslationResult
    prose: str
    reference_bundle: dict[str, Any] = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list)
    confidence: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    trace: list[str] = Field(default_factory=list)
    inference: dict[str, Any] = Field(default_factory=dict)
