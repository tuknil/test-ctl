"""Pydantic models for the control-translation request/result contract.

Shape mirrors `docs/cfs-source.md` §1-§2 (`ControlTranslationRequest` /
`ControlTranslationResult`). These models are the trusted, validated data
that flow through the capability core. No raw text is treated as trusted
until it has passed through one of these models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

    target_technology: Optional[str] = Field(
        default=None,
        description="e.g. akamai-waf, firewall-generic, edr-s1"
    )
    target_policy_context_id: Optional[str] = None


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

    proven_pattern: Optional[ProvenMitigationPattern] = Field(
        default=None,
        description=(
            "Legacy direct-input form. Omit when authoritative upstream "
            "Databricks result references are supplied in the envelope."
        ),
    )
    target_context: Optional[TargetContext] = None
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
    configured_poc_defaults_used: bool = False
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
    proof_loop_qualification: Optional["ProofLoopQualification"] = None
    primary_candidate: Optional[PrimaryCandidate] = None
    evidence_bindings: list[EvidenceBinding] = Field(default_factory=list)
    prose_summary: str


# ---------------------------------------------------------------------------
# API envelope (per api-invocation-surface.md)
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    caller: Optional[str] = None
    source: Optional[str] = None


class DatabricksResultReference(BaseModel):
    """Authoritative pointer to one upstream result in Unity Catalog."""

    model_config = ConfigDict(populate_by_name=True)

    system: str
    catalog: str
    schema_name: str = Field(alias="schema", serialization_alias="schema")
    table: str
    key: str

    @model_validator(mode="after")
    def validate_databricks_reference(self) -> "DatabricksResultReference":
        if self.system.strip().lower() != "databricks":
            raise ValueError("upstream result references must use Databricks")
        if not all(
            value.strip()
            for value in (self.catalog, self.schema_name, self.table, self.key)
        ):
            raise ValueError("Databricks result-reference fields cannot be empty")
        return self


class ProofLoopRoutingMetadata(BaseModel):
    """Orchestration-owned routing facts for the latest candidate cycle."""

    loop_exhausted: bool
    completed_iterations: int = Field(ge=1)
    max_iterations: int = Field(ge=1)
    bypass_validation_terminal_state: Literal["no-bypass-found", "bypass-found"]
    bypass_validation_result_ref: DatabricksResultReference

    @model_validator(mode="after")
    def validate_route(self) -> "ProofLoopRoutingMetadata":
        if self.completed_iterations > self.max_iterations:
            raise ValueError("completed_iterations cannot exceed max_iterations")
        if self.bypass_validation_terminal_state == "no-bypass-found":
            if self.loop_exhausted:
                raise ValueError(
                    "loop_exhausted must be false when no bypass was found"
                )
        else:
            if not self.loop_exhausted:
                raise ValueError(
                    "bypass-found is accepted only when the candidate loop is exhausted"
                )
            if self.max_iterations != 10:
                raise ValueError(
                    "the PoC exhaustion route requires max_iterations to be 10"
                )
            if self.completed_iterations != self.max_iterations:
                raise ValueError(
                    "an exhausted candidate loop must complete max_iterations"
                )
        return self


class ProofLoopQualification(BaseModel):
    """Result qualification; loop exhaustion is not bypass clearance."""

    route: Literal["validated", "poc-exhaustion"]
    bypass_cleared: bool
    loop_exhausted: bool
    completed_iterations: int
    max_iterations: int
    bypass_validation_terminal_state: Literal["no-bypass-found", "bypass-found"]
    bypass_validation_result_ref: DatabricksResultReference


class UpstreamResultReferences(BaseModel):
    """Role-bound proof-loop records required for referenced invocation."""

    defense_generation: DatabricksResultReference
    mitigation_check: DatabricksResultReference
    bypass_validation: DatabricksResultReference


class InvokeRequestEnvelope(BaseModel):
    input: ControlTranslationRequest
    upstream_result_refs: Optional[UpstreamResultReferences] = None
    routing_metadata: Optional[ProofLoopRoutingMetadata] = None
    scope_config: dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = Field(default=None, max_length=255)
    correlation_id: Optional[str] = Field(default=None, min_length=1, max_length=255)
    idempotency_key: Optional[str] = Field(default=None, min_length=1, max_length=255)
    subject_record_revision_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Authoritative orchestration subject-record revision, when available.",
    )
    provenance: Optional[Provenance] = None

    @model_validator(mode="after")
    def validate_reference_routing(self) -> "InvokeRequestEnvelope":
        if self.upstream_result_refs is None and self.routing_metadata is not None:
            raise ValueError(
                "routing_metadata requires authoritative upstream_result_refs"
            )
        if self.upstream_result_refs is not None and self.routing_metadata is None:
            raise ValueError(
                "routing_metadata is required for referenced proof-loop invocation"
            )
        if self.upstream_result_refs and self.routing_metadata:
            expected = self.upstream_result_refs.bypass_validation.model_dump(
                mode="json", by_alias=True
            )
            actual = self.routing_metadata.bypass_validation_result_ref.model_dump(
                mode="json", by_alias=True
            )
            if actual != expected:
                raise ValueError(
                    "routing bypass reference must match upstream_result_refs.bypass_validation"
                )
        return self


class ResultReference(BaseModel):
    """Stable API reference to a durable capability result."""

    system: str = "control-translation"
    type: str = "result-api"
    result_id: str
    href: str


class ResultEnvelope(BaseModel):
    capability: str = "control-translation"
    contract_id: str = "control-translation@1.0"
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    result_id: str
    status: str
    terminal_state: TerminalState
    correlation_id: str
    result_ref: ResultReference
    structured_result: ControlTranslationResult
    prose: str
    reference_bundle: dict[str, Any] = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list)
    confidence: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    trace: list[str] = Field(default_factory=list)
    inference: dict[str, Any] = Field(default_factory=dict)


class RunSummary(BaseModel):
    """Safe dashboard projection that excludes request and artifact content."""

    run_id: str
    result_id: str
    correlation_id: str
    status: str
    terminal_state: TerminalState
    outcome_reason_code: str
    vulnerability_id: str
    target_technology: str
    artifact_type: Optional[str] = None
    started_at: datetime
    completed_at: datetime
    result_href: str


class RunListResponse(BaseModel):
    """Bounded page of durable runs for operational visibility."""

    items: list[RunSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    has_more: bool
    terminal_state_counts: dict[str, int] = Field(default_factory=dict)
