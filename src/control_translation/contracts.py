"""Pydantic models for the control-translation request/result contract.

Shape mirrors `docs/cfs-source.md` §1-§2 (`ControlTranslationRequest` /
`ControlTranslationResult`). These models are the trusted, validated data
that flow through the capability core. No raw text is treated as trusted
until it has passed through one of these models.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from control_translation.terminal import OutcomeReasonCode, TerminalState

# ---------------------------------------------------------------------------
# Shared value types
# ---------------------------------------------------------------------------


class StrictRequestModel(BaseModel):
    """Strict model used for all caller-controlled request contracts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class JsonBodyFieldFeature(StrictRequestModel):
    """Authoritative JSON request field proven by the upstream proof loop."""

    kind: Literal["json-body-field"] = "json-body-field"
    method: Literal["POST"]
    content_type: Literal["application/json"]
    field_path: list[str] = Field(min_length=1, max_length=16)
    value: str = Field(min_length=1, max_length=4096)
    value_match: Literal["exact", "contains-token", "field-present"]
    source: Literal["mitigation-check.test_basis.request"] = (
        "mitigation-check.test_basis.request"
    )

    @field_validator("field_path")
    @classmethod
    def validate_field_path(cls, value: list[str]) -> list[str]:
        safe_segment = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
        if not all(safe_segment.fullmatch(segment) for segment in value):
            raise ValueError(
                "field_path segments must contain only letters, digits, '_' or '-'"
            )
        return value

    @field_validator("value")
    @classmethod
    def validate_nonblank_value(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value


class ProvenMitigationPattern(StrictRequestModel):
    """A proven mitigation pattern produced upstream by the fast proof loop
    (defense-generation -> mitigation-check + bypass-validation)."""

    proven_pattern_id: str
    vulnerability_id: str
    selected_control_class: str
    discriminator_id: str
    discriminator_description: str
    pattern_summary: str
    proof_record_ids: list[str] = Field(min_length=2)
    json_body_field_feature: JsonBodyFieldFeature | None = None
    # What the Defense Generation candidate said it produced, e.g.
    # "modsecurity" or "wazuh-rule". It selects which deterministic compiler
    # can read pattern_summary, so it is the producer's word rather than a
    # guess from the content. Optional: a caller that omits it gets the
    # ModSecurity/Akamai path, which is what every existing caller means.
    upstream_artifact_type: str | None = None

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


class TargetContext(StrictRequestModel):
    """Identifies the target control technology and policy context."""

    target_technology: str | None = Field(
        default=None,
        description="e.g. akamai-waf, firewall-generic, edr-s1"
    )
    target_policy_context_id: str | None = None


class TranslationPolicy(StrictRequestModel):
    """Dials/config for how aggressive or conservative translation should be."""

    translation_policy_id: str = "control-translation-policy:mvp1"
    allow_narrower_translation: bool = True
    allow_equivalent_translation: bool = True
    allow_broader_translation: bool = True


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class ControlTranslationRequest(StrictRequestModel):
    """Input contract for a single control-translation invocation."""

    proven_pattern: ProvenMitigationPattern | None = Field(
        default=None,
        description=(
            "Legacy direct-input form. Omit when authoritative upstream "
            "Databricks result references are supplied in the envelope."
        ),
    )
    target_context: TargetContext | None = None
    translation_policy: TranslationPolicy = Field(default_factory=TranslationPolicy)
    current_policy_snapshot_id: str | None = Field(
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
    translation: str = Field(description="exact | equivalent | narrower | broader")
    justification: str
    evidence_refs: list[str] = Field(default_factory=list)


class Placement(BaseModel):
    policy_section: str | None = None
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


def shared_waf_primary_artifact_id(content_hash: str) -> str:
    digest = content_hash.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("shared WAF primary artifact hash is invalid")
    return "akamai-rule-set-" + digest


class CandidateSyntaxProfile(BaseModel):
    id: str
    family: str
    validation_level: Literal["shape-only"] = "shape-only"
    deployment_ready: Literal[False] = False


class RecommendedPolicyBinding(BaseModel):
    action: Literal["deny"] = "deny"
    attachment: Literal["security-policy-custom-rule-binding"] = (
        "security-policy-custom-rule-binding"
    )
    embedded_in_artifact: Literal[False] = False
    requires_operator_review: Literal[True] = True


class CandidateMetadata(BaseModel):
    syntax_profile: CandidateSyntaxProfile
    recommended_policy_binding: RecommendedPolicyBinding
    semantic_relationship: Literal[
        "exact", "equivalent", "narrower", "broader"
    ] | None = None


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
    candidate_metadata: CandidateMetadata | None = None


class EvidenceBinding(BaseModel):
    claim: str = Field(
        description="discriminator-preserved | target-feature-supported | policy-placement | limitation"
    )
    evidence_refs: list[str] = Field(default_factory=list)


class BypassCounterexample(BaseModel):
    """Bounded bypass evidence preserved for a declined exhausted route."""

    counterexample_id: str
    sample_ref: str
    variant_family: str
    observed_behavior: str
    evidence_refs: list[str] = Field(default_factory=list)


class ProofLoopTranslationRequirements(BaseModel):
    """Authoritative payload forms a target translation must preserve."""

    original_payload: str | None = None
    bypass_payload: str | None = None
    bypass_variant_or_encoding: str | None = None
    constraint_for_next_candidate: str | None = None
    post_waf_canonical_forms: list[str] = Field(default_factory=list)
    effective_request: dict[str, Any] | None = None
    mutation_location: dict[str, Any] | None = None

    @property
    def required_payloads(self) -> tuple[str, ...]:
        values = (
            self.original_payload,
            self.bypass_payload,
            *self.post_waf_canonical_forms,
        )
        return tuple(dict.fromkeys(value for value in values if value))

    @property
    def request_path(self) -> str | None:
        if not self.effective_request:
            return None
        path = self.effective_request.get("path")
        return path if isinstance(path, str) and path else None


class ProofLoopRequestContext(BaseModel):
    """Authoritative HTTP request proven by Mitigation Check."""

    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str

    @property
    def content_type(self) -> str:
        return next(
            (
                value.lower()
                for name, value in self.headers.items()
                if name.lower() == "content-type"
            ),
            "",
        )


class DirectBypassSubject(StrictRequestModel):
    candidate_fingerprint_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    candidate_id: str = Field(min_length=1)
    vulnerability_id: str = Field(min_length=1)


class DirectBypassOutcome(StrictRequestModel):
    code: Literal["bypass-found"]
    detail: str = Field(min_length=1)


class DirectBypassSearchBounds(StrictRequestModel):
    attempt_budget: int = Field(ge=1)
    attempts_executed: int = Field(ge=1)
    stop_reason: str = Field(min_length=1)
    timeout_seconds: int = Field(ge=1)
    variant_families_attempted: list[str]
    variant_families_out_of_scope: list[str]
    variant_families_requested: list[str]


class DirectBypassFeedbackCounterexample(StrictRequestModel):
    kind: str = Field(min_length=1)
    reference: str = Field(min_length=1)


class DirectBypassFeedback(StrictRequestModel):
    feedback_id: str = Field(min_length=1)
    source: Literal["bypass-validation"]
    rejected_candidate_id: str = Field(min_length=1)
    failed_gate: Literal["bypass"]
    observed_failure: str = Field(min_length=1)
    why_it_sucks: str = Field(min_length=1)
    do_not_repeat: str = Field(min_length=1)
    counterexample: DirectBypassFeedbackCounterexample
    evidence_refs: list[str]
    reusable: bool
    reusable_reason: str = Field(min_length=1)


class DirectBypassValidationResult(StrictRequestModel):
    """Deployed canonical bypass result accepted as a safe compatibility input."""

    contract_id: Literal["bypass-validation@1.0"]
    result_id: str = Field(pattern=r"^bypass-validation-result:.+")
    run_id: str = Field(min_length=1)
    result_ref: DatabricksResultReference
    produced_at: datetime
    subject: DirectBypassSubject
    input_bindings: dict[str, Any]
    terminal_state: Literal["bypass-found"]
    outcome_reason: DirectBypassOutcome
    search_bounds: DirectBypassSearchBounds
    bypass_counterexample: BypassCounterexample
    feedback: DirectBypassFeedback
    limitations: list[str]
    prose_summary: str

    @model_validator(mode="after")
    def validate_direct_result(self) -> DirectBypassValidationResult:
        if self.result_ref.key != self.result_id:
            raise ValueError("result_ref.key must equal result_id")
        expected_run_id = self.result_id.removeprefix(
            "bypass-validation-result:"
        )
        if self.run_id != expected_run_id:
            raise ValueError("bypass result_id must derive from run_id")
        prior = self.input_bindings.get("prior_mitigation_check")
        if not isinstance(prior, dict):
            raise TypeError("prior_mitigation_check is required")
        if prior.get("contract_id") != "mitigation-check@1.0":
            raise ValueError("prior mitigation-check contract is unsupported")
        if prior.get("terminal_state") != "blocked" or prior.get("match") is not True:
            raise ValueError("prior mitigation-check must be a matching blocked proof")
        prior_result_id = prior.get("result_id")
        prior_ref = prior.get("result_ref")
        if (
            not isinstance(prior_result_id, str)
            or not isinstance(prior_ref, dict)
            or prior_ref.get("key") != prior_result_id
        ):
            raise ValueError("prior mitigation-check result reference is invalid")
        prior_correlation = prior.get("correlation_id")
        if not isinstance(prior_correlation, str) or not prior_correlation:
            raise ValueError("prior mitigation-check correlation_id is required")
        if self.feedback.rejected_candidate_id != self.subject.candidate_id:
            raise ValueError("feedback rejected candidate does not match subject")
        return self

    @property
    def correlation_id(self) -> str:
        return str(
            self.input_bindings["prior_mitigation_check"]["correlation_id"]
        )

    @property
    def mitigation_result_id(self) -> str:
        return str(self.input_bindings["prior_mitigation_check"]["result_id"])

    @property
    def mitigation_result_ref(self) -> DatabricksResultReference:
        return DatabricksResultReference.model_validate(
            self.input_bindings["prior_mitigation_check"]["result_ref"]
        )


class Subject(BaseModel):
    vulnerability_id: str
    proven_pattern_id: str
    selected_control_class: str


class InputBindings(BaseModel):
    target_technology: str
    target_policy_context_id: str
    configured_poc_defaults_used: bool = False
    current_policy_snapshot_id: str | None = None
    translation_policy_id: str
    proof_record_ids: list[str] = Field(default_factory=list)


class CoverageAccounting(BaseModel):
    """Exact required-work accounting shared by the v2 verifier."""

    required_obligation_count: int = Field(ge=0)
    accounted_obligation_count: int = Field(ge=0)
    unaccounted_required_obligation_count: int = Field(ge=0)
    source_member_count: int = Field(ge=0)
    represented_source_member_count: int = Field(ge=0)
    unsupported_source_member_count: int = Field(ge=0)
    unaccounted_source_member_count: int = Field(ge=0)
    required_work_item_count: int = Field(ge=0)
    disposed_work_item_count: int = Field(ge=0)
    unaccounted_required_work_item_count: int = Field(ge=0)


class PreTranslationVerification(BaseModel):
    """Evidence that the complete four-result join passed before translation."""

    all_required_obligations_have_dg_mapping: Literal[True]
    all_required_obligations_have_mc_disposition: Literal[True]
    all_required_obligations_have_required_bv_disposition: Literal[True]
    candidate_attestation_verified: Literal[True]
    source_member_partition_complete: Literal[True]
    lineage_verified: Literal[True]
    required_obligation_count: int = Field(ge=1)
    dg_mapping_count: int = Field(ge=1)
    mc_disposition_count: int = Field(ge=1)
    bv_campaign_count: int = Field(ge=1)
    unaccounted_required_obligation_count: Literal[0]


class TargetTranslationArtifact(BaseModel):
    """One actual target artifact emitted from one DG cooperating artifact."""

    artifact_id: str = Field(min_length=1)
    source_artifact_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    order: int = Field(ge=0)
    artifact_type: str = Field(min_length=1)
    content: str = Field(min_length=1)
    content_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class TargetTranslationDirective(BaseModel):
    """A required DG directive bound to its emitted target artifact."""

    directive_id: str = Field(min_length=1)
    source_directive_id: str = Field(min_length=1)
    target_artifact_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    value: str = Field(min_length=1)
    required: bool


class TranslationMapping(BaseModel):
    """Exact CT disposition for one required CG obligation."""

    obligation_id: str = Field(min_length=1)
    target_artifact_ids: list[str] = Field(min_length=1)

    @field_validator("target_artifact_ids")
    @classmethod
    def validate_target_artifact_ids(cls, value: list[str]) -> list[str]:
        if any(not item for item in value) or len(value) != len(set(value)):
            raise ValueError("target_artifact_ids must be nonempty and unique")
        return value


class ControlTranslationResult(BaseModel):
    """Output contract. Field shape mirrors CFS §2 `ControlTranslationResult`."""

    contract_id: str = "control-translation@1.0"
    result_id: str
    produced_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    subject: Subject
    input_bindings: InputBindings
    terminal_state: TerminalState
    outcome_reason: OutcomeReason
    proof_loop_qualification: ProofLoopQualification | None = None
    bypass_counterexample: BypassCounterexample | None = None
    primary_candidate: PrimaryCandidate | None = None
    evidence_bindings: list[EvidenceBinding] = Field(default_factory=list)
    prose_summary: str
    shared_contract_version: Literal["2.0"] | None = None
    profile_id: Literal["waf-standard@1", "waf-standard@2"] | None = None
    pre_translation_verification: PreTranslationVerification | None = None
    accounting: CoverageAccounting | None = None
    target_artifacts: list[TargetTranslationArtifact] = Field(default_factory=list)
    translated_directives: list[TargetTranslationDirective] = Field(default_factory=list)
    translation_mappings: list[TranslationMapping] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_v2_completeness(self) -> ControlTranslationResult:
        v2_values = (
            self.profile_id,
            self.pre_translation_verification,
            self.accounting,
        )
        if self.shared_contract_version is None:
            if any(value is not None for value in v2_values) or any(
                (self.target_artifacts, self.translated_directives, self.translation_mappings)
            ):
                raise ValueError("v2 result fields require shared_contract_version")
            return self
        if (
            self.contract_id != "control-translation@2.0"
            or any(value is None for value in v2_values)
        ):
            raise ValueError("v2 result requires contract, profile, verification, and accounting")
        assert self.pre_translation_verification is not None
        assert self.accounting is not None
        count = self.pre_translation_verification.required_obligation_count
        if (
            self.accounting.required_obligation_count != count
            or self.accounting.accounted_obligation_count != count
            or self.accounting.unaccounted_required_obligation_count != 0
        ):
            raise ValueError("v2 verification and accounting counts differ")
        if self.terminal_state is not TerminalState.TRANSLATED:
            if any((self.target_artifacts, self.translated_directives, self.translation_mappings)):
                raise ValueError("non-translated v2 result cannot contain partial output")
            return self
        child_artifact_ids = [item.artifact_id for item in self.target_artifacts]
        primary_artifact_id = (
            shared_waf_primary_artifact_id(
                self.primary_candidate.candidate_artifact.content_hash
            )
            if self.primary_candidate is not None
            else None
        )
        artifact_ids = [*child_artifact_ids]
        if primary_artifact_id is not None:
            artifact_ids.append(primary_artifact_id)
        obligation_ids = [item.obligation_id for item in self.translation_mappings]
        if (
            primary_artifact_id is None
            or len(child_artifact_ids) != len(set(child_artifact_ids))
            or len(obligation_ids) != count
            or len(obligation_ids) != len(set(obligation_ids))
            or any(
                artifact_id not in artifact_ids
                for mapping in self.translation_mappings
                for artifact_id in mapping.target_artifact_ids
            )
            or any(
                directive.target_artifact_id not in artifact_ids
                for directive in self.translated_directives
            )
        ):
            raise ValueError("v2 translated output is incomplete or references absent artifacts")
        return self


# ---------------------------------------------------------------------------
# API envelope (per api-invocation-surface.md)
# ---------------------------------------------------------------------------


class Provenance(StrictRequestModel):
    caller: str | None = None
    source: str | None = None


class CompletionCallback(StrictRequestModel):
    """Legacy body callback shape; async submissions use transport headers."""

    url: AnyHttpUrl
    event_contract_id: Literal["capability-run-event@1.0"]


class DatabricksResultReference(StrictRequestModel):
    """Authoritative result pointer for the selected server-owned plane."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
    )

    system: Literal["databricks", "workflow-lab"]
    catalog: str | None = None
    schema_name: str | None = Field(default=None, alias="schema", serialization_alias="schema")
    table: str | None = None
    contract_id: str | None = None
    namespace: str | None = None
    key: str

    @model_validator(mode="after")
    def validate_databricks_reference(self) -> DatabricksResultReference:
        if self.system == "databricks":
            if (
                not all(value and value.strip() for value in (self.catalog, self.schema_name, self.table, self.key))
                or self.contract_id is not None
                or self.namespace is not None
            ):
                raise ValueError("Databricks result-reference fields are invalid")
        elif (
            self.contract_id != "workflow-lab-result-reference@1.0"
            or self.namespace != "immutable-results"
            or any(value is not None for value in (self.catalog, self.schema_name, self.table))
        ):
            raise ValueError("Workflow Lab result-reference fields are invalid")
        return self

    @model_serializer(mode="wrap")
    def serialize_reference(self, serializer):
        return {key: value for key, value in serializer(self).items() if value is not None}


class ProofLoopRoutingMetadata(StrictRequestModel):
    """Orchestration-owned routing facts for the latest candidate cycle."""

    loop_exhausted: bool
    completed_iterations: int = Field(ge=1)
    max_iterations: int = Field(ge=1)
    bypass_validation_terminal_state: Literal["no-bypass-found", "bypass-found"]
    bypass_validation_result_ref: DatabricksResultReference

    @model_validator(mode="after")
    def validate_route(self) -> ProofLoopRoutingMetadata:
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


class UpstreamResultReferences(StrictRequestModel):
    """Role-bound proof-loop records required for referenced invocation."""

    defense_generation: DatabricksResultReference
    mitigation_check: DatabricksResultReference
    bypass_validation: DatabricksResultReference


class InvocationSubject(StrictRequestModel):
    """Orchestration-owned subject binding for the selected candidate."""

    vulnerability_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)


class OrchestrationUpstreamInput(StrictRequestModel):
    """One immutable completion supplied by Temporal orchestration."""

    capability: Literal[
        "defense-generation", "mitigation-check", "bypass-validation"
    ]
    contract_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=255)
    result_id: str = Field(min_length=1, max_length=512)
    terminal_state: str = Field(min_length=1, max_length=128)
    status: Literal["completed"]
    request_id: str | None = Field(default=None, min_length=1, max_length=512)
    correlation_id: str = Field(min_length=1, max_length=255)
    result_ref: DatabricksResultReference
    evidence_refs: list[str] = Field(default_factory=list)
    content_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[a-f0-9]{64}$"
    )
    size_bytes: int | None = Field(default=None, ge=1, le=200 * 1024 * 1024)
    created_at: datetime | None = None

    @model_validator(mode="after")
    def validate_completion(self) -> OrchestrationUpstreamInput:
        accepted_contracts = {
            "defense-generation": {
                "defense-generation@1.0",
                "defense-generation-result@1.0",
            },
            "mitigation-check": {"mitigation-check@1.0"},
            # The deployed producer sends the common completion-envelope ID.
            # The canonical row itself is validated as bypass-validation@1.0.
            "bypass-validation": {
                "capability-completion@1.0",
                "bypass-validation@1.0",
            },
        }
        expected_states = {
            "defense-generation": "candidate-produced",
            "mitigation-check": "blocked",
            "bypass-validation": {"no-bypass-found", "bypass-found"},
        }
        if self.contract_id not in accepted_contracts[self.capability]:
            raise ValueError(
                f"unsupported {self.capability} completion contract"
            )
        expected = expected_states[self.capability]
        if isinstance(expected, set):
            valid_state = self.terminal_state in expected
        else:
            valid_state = self.terminal_state == expected
        if not valid_state:
            raise ValueError(
                f"invalid {self.capability} terminal state"
            )
        if self.result_ref.key != self.result_id:
            raise ValueError("result_ref.key must equal result_id")
        approved_references = {
            "defense-generation": (
                "defense-generation-result:",
                "36889_janus_dev",
                "defense_generation",
                "defense_generation_results",
            ),
            "mitigation-check": (
                "mitigation-check-result:",
                "36889_janus_dev",
                "mitigation-check",
                "mitigation_check",
            ),
            "bypass-validation": (
                "bypass-validation-result:",
                "36889_janus_dev",
                "bypass_validation",
                "bypass_validation_results",
            ),
        }
        prefix, catalog, schema, table = approved_references[self.capability]
        if not self.result_id.startswith(prefix):
            raise ValueError(
                f"{self.capability} result_id has an invalid identity"
            )
        if self.result_ref.system == "databricks" and (
            self.result_ref.catalog,
            self.result_ref.schema_name,
            self.result_ref.table,
        ) != (catalog, schema, table):
            raise ValueError(
                f"{self.capability} result_ref does not identify the approved table"
            )
        if any(not reference for reference in self.evidence_refs):
            raise ValueError("evidence references cannot be empty")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence references must be unique")
        bounded = (self.content_sha256, self.size_bytes, self.created_at)
        if any(value is not None for value in bounded) and (
            self.request_id is None
            or not all(value is not None for value in bounded)
        ):
            raise ValueError(
                "strict upstream locator requires request_id, content_sha256, "
                "size_bytes, and created_at"
            )
        return self

    @property
    def is_strict_locator(self) -> bool:
        return (
            self.request_id is not None
            and self.content_sha256 is not None
            and self.size_bytes is not None
            and self.created_at is not None
        )


class SharedContractV2UpstreamInput(StrictRequestModel):
    """One authenticated immutable completion in the four-result v2 join."""

    capability: Literal[
        "check-generation",
        "defense-generation",
        "mitigation-check",
        "bypass-validation",
    ]
    contract_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=255)
    result_id: str = Field(min_length=1, max_length=512)
    terminal_state: str = Field(min_length=1, max_length=128)
    status: Literal["completed"]
    request_id: str = Field(min_length=1, max_length=512)
    correlation_id: str = Field(min_length=1, max_length=255)
    result_ref: DatabricksResultReference
    evidence_refs: list[str] = Field(default_factory=list)
    content_sha256: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1, le=200 * 1024 * 1024)
    created_at: datetime

    @model_validator(mode="after")
    def validate_authenticated_locator(self) -> SharedContractV2UpstreamInput:
        expected = {
            "check-generation": (
                "check-generation@2.1",
                "completed",
                "check-generation-result:",
                "check_generation",
                "check_generation_results",
            ),
            "defense-generation": (
                "defense-generation-result@1.0",
                "candidate-produced",
                "defense-generation-result:",
                "defense_generation",
                "defense_generation_results",
            ),
            "mitigation-check": (
                "mitigation-check@1.0",
                "blocked",
                "mitigation-check-result:",
                "mitigation-check",
                "mitigation_check",
            ),
            "bypass-validation": (
                "bypass-validation@2.0",
                "no-bypass-found",
                "bypass-validation-result:",
                "bypass_validation",
                "bypass_validation_results",
            ),
        }
        contract, state, prefix, schema, table = expected[self.capability]
        if self.contract_id != contract or self.terminal_state != state:
            raise ValueError(f"unsupported {self.capability} v2 completion")
        if not self.result_id.startswith(prefix):
            raise ValueError(f"{self.capability} result_id has an invalid identity")
        if self.result_ref.key != self.result_id:
            raise ValueError("result_ref.key must equal result_id")
        if self.result_ref.system == "databricks" and (
            self.result_ref.catalog,
            self.result_ref.schema_name,
            self.result_ref.table,
        ) != ("36889_janus_dev", schema, table):
            raise ValueError(
                f"{self.capability} result_ref does not identify the approved table"
            )
        if any(not item for item in self.evidence_refs):
            raise ValueError("evidence references cannot be empty")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence references must be unique")
        return self


class OrchestrationRoutingContext(StrictRequestModel):
    """Temporal-owned routing decision for the completed proof loop."""

    route: Literal["validated", "loop-exhausted"]
    mitigation_check_terminal_state: Literal["blocked"]
    mitigation_check_match: Literal[True]
    bypass_validation_terminal_state: Literal[
        "no-bypass-found", "bypass-found"
    ]
    loop_exhausted: bool
    completed_iterations: int = Field(ge=1)
    max_iterations: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_route(self) -> OrchestrationRoutingContext:
        if self.route == "validated":
            if self.loop_exhausted or self.bypass_validation_terminal_state != "no-bypass-found":
                raise ValueError("validated route requires no-bypass-found")
        else:
            if (
                not self.loop_exhausted
                or self.bypass_validation_terminal_state != "bypass-found"
                or self.completed_iterations != self.max_iterations
                or self.max_iterations != 10
            ):
                raise ValueError(
                    "loop-exhausted route requires bypass-found at 10 of 10 iterations"
                )
        return self


class InvokeRequestEnvelope(StrictRequestModel):
    contract_id: Literal["control-translation@1.0"] | None = None
    input: ControlTranslationRequest = Field(default_factory=ControlTranslationRequest)
    subject: InvocationSubject | None = None
    upstream_inputs: list[OrchestrationUpstreamInput] | None = None
    routing_context: OrchestrationRoutingContext | None = None
    upstream_result_refs: UpstreamResultReferences | None = None
    routing_metadata: ProofLoopRoutingMetadata | None = None
    scope_config: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(default=None, max_length=255)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=255)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=255)
    subject_record_revision_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Authoritative orchestration subject-record revision, when available.",
    )
    provenance: Provenance | None = None
    callback: CompletionCallback | None = None

    @model_validator(mode="after")
    def validate_reference_routing(self) -> InvokeRequestEnvelope:
        locator_mode = any(
            value is not None
            for value in (
                self.upstream_inputs,
                self.routing_context,
            )
        )
        if locator_mode:
            if not all(
                value is not None
                for value in (
                    self.contract_id,
                    self.request_id,
                    self.correlation_id,
                    self.subject,
                    self.upstream_inputs,
                    self.routing_context,
                    self.provenance,
                )
            ):
                raise ValueError(
                    "orchestration requests require contract_id, request_id, "
                    "correlation_id, subject, upstream_inputs, routing_context, "
                    "and provenance"
                )
            assert self.upstream_inputs is not None
            if len(self.upstream_inputs) != 3:
                raise ValueError("orchestration requests require exactly three upstream inputs")
            inputs = {item.capability: item for item in self.upstream_inputs}
            if len(inputs) != 3:
                raise ValueError("orchestration upstream capabilities must be unique")
            strict_modes = [item.is_strict_locator for item in self.upstream_inputs]
            if any(strict_modes) and not all(strict_modes):
                raise ValueError(
                    "strict locator mode requires bounded metadata for all upstream inputs"
                )
            assert self.correlation_id is not None
            if any(
                item.correlation_id != self.correlation_id
                for item in self.upstream_inputs
            ):
                raise ValueError("upstream correlation_id does not match command")
            assert self.routing_context is not None
            if (
                inputs["bypass-validation"].terminal_state
                != self.routing_context.bypass_validation_terminal_state
            ):
                raise ValueError("routing bypass state does not match upstream completion")
            normalized_references = UpstreamResultReferences(
                defense_generation=inputs["defense-generation"].result_ref,
                mitigation_check=inputs["mitigation-check"].result_ref,
                bypass_validation=inputs["bypass-validation"].result_ref,
            )
            normalized_routing = ProofLoopRoutingMetadata(
                loop_exhausted=self.routing_context.loop_exhausted,
                completed_iterations=self.routing_context.completed_iterations,
                max_iterations=self.routing_context.max_iterations,
                bypass_validation_terminal_state=(
                    self.routing_context.bypass_validation_terminal_state
                ),
                bypass_validation_result_ref=inputs["bypass-validation"].result_ref,
            )
            if (
                self.upstream_result_refs is not None
                and self.upstream_result_refs != normalized_references
            ):
                raise ValueError(
                    "normalized upstream references do not match orchestration inputs"
                )
            if (
                self.routing_metadata is not None
                and self.routing_metadata != normalized_routing
            ):
                raise ValueError(
                    "normalized routing metadata does not match routing_context"
                )
            self.upstream_result_refs = normalized_references
            self.routing_metadata = normalized_routing
            if self.idempotency_key not in (None, self.request_id):
                raise ValueError("orchestration idempotency_key must equal request_id")
            self.idempotency_key = self.request_id

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
    request_id: str | None = None
    correlation_id: str
    result_ref: ResultReference
    upstream_result_refs: UpstreamResultReferences | None = None
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
    artifact_type: str | None = None
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


class SharedContractV2InvokeRequest(StrictRequestModel):
    """Additive stage-1 request for the exact authenticated four-result join."""

    contract_id: Literal["control-translation@2.0"]
    shared_contract_version: Literal["2.0"]
    profile_id: Literal["waf-standard@1", "waf-standard@2"]
    request_id: str = Field(min_length=1, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=255)
    upstream_inputs: tuple[
        SharedContractV2UpstreamInput,
        SharedContractV2UpstreamInput,
        SharedContractV2UpstreamInput,
        SharedContractV2UpstreamInput,
    ]
    target_context: TargetContext | None = None
    provenance: Provenance

    @model_validator(mode="after")
    def validate_exact_join(self) -> SharedContractV2InvokeRequest:
        required = {
            "check-generation",
            "defense-generation",
            "mitigation-check",
            "bypass-validation",
        }
        capabilities = {item.capability for item in self.upstream_inputs}
        if capabilities != required:
            raise ValueError("v2 requires exactly one CG, DG, MC, and BV locator")
        if any(
            item.correlation_id != self.correlation_id
            for item in self.upstream_inputs
        ):
            raise ValueError("upstream correlation_id does not match command")
        return self


InvocationRequest = InvokeRequestEnvelope | SharedContractV2InvokeRequest
InvokeAPIRequest = InvocationRequest | DirectBypassValidationResult


# ---------------------------------------------------------------------------
# Asynchronous capability lifecycle
# ---------------------------------------------------------------------------


RunLifecycleStatus = Literal[
    "queued", "running", "completed", "failed", "canceled"
]


class RunProgress(BaseModel):
    phase: str
    percent: int | None = Field(default=None, ge=0, le=100)
    message: str


class RunFailure(BaseModel):
    code: str
    detail: str
    retryable: bool


class CanonicalCompletion(BaseModel):
    capability: Literal["control-translation"] = "control-translation"
    contract_id: Literal["capability-completion@1.0"] = "capability-completion@1.0"
    request_id: str
    correlation_id: str
    run_id: str
    result_id: str
    status: Literal["completed"] = "completed"
    terminal_state: str
    result_ref: DatabricksResultReference
    evidence_refs: list[str] = Field(default_factory=list)
    content_sha256: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1)
    created_at: datetime


class CapabilityRunStatus(BaseModel):
    capability: Literal["control-translation"] = "control-translation"
    contract_id: Literal["capability-run-status@1.0"] = "capability-run-status@1.0"
    request_id: str
    correlation_id: str
    run_id: str
    status: RunLifecycleStatus
    terminal_state: str | None = None
    result_id: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    updated_at: datetime
    completed_at: datetime | None = None
    progress: RunProgress
    failure: RunFailure | None = None
    completion: CanonicalCompletion | None = None


class CapabilityRunSubmission(BaseModel):
    capability: Literal["control-translation"] = "control-translation"
    contract_id: Literal["control-translation-run-submission@1.0"] = (
        "control-translation-run-submission@1.0"
    )
    request_id: str
    correlation_id: str
    run_id: str
    status: RunLifecycleStatus
    status_url: str
    result_url: str
    accepted_at: datetime
