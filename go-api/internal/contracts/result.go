package contracts

import (
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
	"github.com/ATT-CSO/control-translation/go-api/internal/terminal"
)

// OutcomeReason binds a reason code to the terminal state.
type OutcomeReason struct {
	Code   terminal.ReasonCode `json:"code"`
	Detail string              `json:"detail"`
}

// ImplementsDiscriminator records how the candidate implements the source.
type ImplementsDiscriminator struct {
	SourceDiscriminatorID string   `json:"source_discriminator_id"`
	Translation           string   `json:"translation"`
	Justification         string   `json:"justification"`
	EvidenceRefs          []string `json:"evidence_refs"`
}

// Placement carries policy placement and detected conflicts.
type Placement struct {
	PolicySection       *string  `json:"policy_section"`
	OrderingConstraints []string `json:"ordering_constraints"`
	ConflictNotes       []string `json:"conflict_notes"`
}

// CollateralImpactPrior is inherited, never measured by this capability.
type CollateralImpactPrior struct {
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	Basis      string `json:"basis"`
	Measured   bool   `json:"measured"`
}

// CandidateArtifact is the proposed target artifact and its integrity hash.
type CandidateArtifact struct {
	ArtifactType string `json:"artifact_type"`
	ContentRef   string `json:"content_ref"`
	ContentHash  string `json:"content_hash"`
	EmittedAs    string `json:"emitted_as"`
}

// CandidateSyntaxProfile records that validation was shape-only.
type CandidateSyntaxProfile struct {
	ID              string `json:"id"`
	Family          string `json:"family"`
	ValidationLevel string `json:"validation_level"`
	DeploymentReady bool   `json:"deployment_ready"`
}

// RecommendedPolicyBinding keeps the action out of the artifact body.
type RecommendedPolicyBinding struct {
	Action                 string `json:"action"`
	Attachment             string `json:"attachment"`
	EmbeddedInArtifact     bool   `json:"embedded_in_artifact"`
	RequiresOperatorReview bool   `json:"requires_operator_review"`
}

// CandidateMetadata is emitted for Akamai candidates.
type CandidateMetadata struct {
	SyntaxProfile            CandidateSyntaxProfile   `json:"syntax_profile"`
	RecommendedPolicyBinding RecommendedPolicyBinding `json:"recommended_policy_binding"`
}

// AkamaiCandidateMetadata builds the fixed metadata the Python service emits.
func AkamaiCandidateMetadata() *CandidateMetadata {
	return &CandidateMetadata{
		SyntaxProfile: CandidateSyntaxProfile{
			ID:              "janus-akamai-like-custom-rule-demo@1",
			Family:          "akamai-like-custom-rule",
			ValidationLevel: "shape-only",
			DeploymentReady: false,
		},
		RecommendedPolicyBinding: RecommendedPolicyBinding{
			Action:                 "deny",
			Attachment:             "security-policy-custom-rule-binding",
			EmbeddedInArtifact:     false,
			RequiresOperatorReview: true,
		},
	}
}

// PrimaryCandidate is the single reviewable candidate an invocation produces.
type PrimaryCandidate struct {
	CandidateID                    string                  `json:"candidate_id"`
	TargetControlClass             string                  `json:"target_control_class"`
	TargetTechnology               string                  `json:"target_technology"`
	TargetPolicyContextID          string                  `json:"target_policy_context_id"`
	CandidateArtifact              CandidateArtifact       `json:"candidate_artifact"`
	ImplementsDiscriminator        ImplementsDiscriminator `json:"implements_discriminator"`
	Placement                      Placement               `json:"placement"`
	InheritedCollateralImpactPrior CollateralImpactPrior   `json:"inherited_collateral_impact_prior"`
	TranslationAssumptions         []string                `json:"translation_assumptions"`
	Limitations                    []string                `json:"limitations"`
	Provenance                     []string                `json:"provenance"`
	CandidateMetadata              *CandidateMetadata      `json:"candidate_metadata"`
}

// EvidenceBinding ties a claim to the records that support it.
type EvidenceBinding struct {
	Claim        string   `json:"claim"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// Subject identifies what was translated.
type Subject struct {
	VulnerabilityID      string `json:"vulnerability_id"`
	ProvenPatternID      string `json:"proven_pattern_id"`
	SelectedControlClass string `json:"selected_control_class"`
}

// InputBindings records the effective inputs the result was produced from.
type InputBindings struct {
	TargetTechnology          string   `json:"target_technology"`
	TargetPolicyContextID     string   `json:"target_policy_context_id"`
	ConfiguredPoCDefaultsUsed bool     `json:"configured_poc_defaults_used"`
	CurrentPolicySnapshotID   *string  `json:"current_policy_snapshot_id"`
	TranslationPolicyID       string   `json:"translation_policy_id"`
	ProofRecordIDs            []string `json:"proof_record_ids"`
}

// ControlTranslationResult is the durable business result.
type ControlTranslationResult struct {
	ContractID    string         `json:"contract_id"`
	ResultID      string         `json:"result_id"`
	ProducedAt    Time           `json:"produced_at"`
	Subject       Subject        `json:"subject"`
	InputBindings InputBindings  `json:"input_bindings"`
	TerminalState terminal.State `json:"terminal_state"`
	OutcomeReason OutcomeReason  `json:"outcome_reason"`
	// Loop exhaustion is not bypass clearance; the qualification says which.
	ProofLoopQualification *ProofLoopQualification `json:"proof_loop_qualification"`
	BypassCounterexample   *BypassCounterexample   `json:"bypass_counterexample"`
	PrimaryCandidate       *PrimaryCandidate       `json:"primary_candidate"`
	EvidenceBindings       []EvidenceBinding       `json:"evidence_bindings"`
	ProseSummary           string                  `json:"prose_summary"`
}

// ResultReference is the stable API reference to a durable result.
type ResultReference struct {
	System   string `json:"system"`
	Type     string `json:"type"`
	ResultID string `json:"result_id"`
	Href     string `json:"href"`
}

// ResultEnvelope is the response contract for a synchronous invocation.
type ResultEnvelope struct {
	Capability         string                    `json:"capability"`
	ContractID         string                    `json:"contract_id"`
	RunID              string                    `json:"run_id"`
	ResultID           string                    `json:"result_id"`
	Status             string                    `json:"status"`
	TerminalState      terminal.State            `json:"terminal_state"`
	RequestID          *string                   `json:"request_id"`
	CorrelationID      string                    `json:"correlation_id"`
	ResultRef          ResultReference           `json:"result_ref"`
	UpstreamResultRefs *UpstreamResultReferences `json:"upstream_result_refs"`
	StructuredResult   ControlTranslationResult  `json:"structured_result"`
	Prose              string                    `json:"prose"`
	ReferenceBundle    jsonx.Obj                 `json:"reference_bundle"`
	Provenance         []string                  `json:"provenance"`
	Confidence         jsonx.Obj                 `json:"confidence"`
	Warnings           []string                  `json:"warnings"`
	Trace              []string                  `json:"trace"`
	Inference          jsonx.Obj                 `json:"inference"`
}

// RunSummary is the safe dashboard projection: no request or artifact content.
type RunSummary struct {
	RunID             string         `json:"run_id"`
	ResultID          string         `json:"result_id"`
	CorrelationID     string         `json:"correlation_id"`
	Status            string         `json:"status"`
	TerminalState     terminal.State `json:"terminal_state"`
	OutcomeReasonCode string         `json:"outcome_reason_code"`
	VulnerabilityID   string         `json:"vulnerability_id"`
	TargetTechnology  string         `json:"target_technology"`
	ArtifactType      *string        `json:"artifact_type"`
	StartedAt         Time           `json:"started_at"`
	CompletedAt       Time           `json:"completed_at"`
	ResultHref        string         `json:"result_href"`
}

// RunListResponse is a bounded page of durable runs.
type RunListResponse struct {
	Items               []RunSummary   `json:"items"`
	Total               int            `json:"total"`
	Limit               int            `json:"limit"`
	Offset              int            `json:"offset"`
	HasMore             bool           `json:"has_more"`
	TerminalStateCounts map[string]int `json:"terminal_state_counts"`
}

// ---------------------------------------------------------------------------
// Asynchronous capability lifecycle
// ---------------------------------------------------------------------------

// RunProgress is the coarse public progress of a durable run.
type RunProgress struct {
	Phase   string `json:"phase"`
	Percent *int   `json:"percent"`
	Message string `json:"message"`
}

// RunFailure is the public failure shape for a durable run.
type RunFailure struct {
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	Retryable bool   `json:"retryable"`
}

// CanonicalCompletion is the compact completion orchestration consumes: it
// carries the immutable result's reference, digest, and byte size rather than
// the result itself.
type CanonicalCompletion struct {
	Capability    string                    `json:"capability"`
	ContractID    string                    `json:"contract_id"`
	RequestID     string                    `json:"request_id"`
	CorrelationID string                    `json:"correlation_id"`
	RunID         string                    `json:"run_id"`
	ResultID      string                    `json:"result_id"`
	Status        string                    `json:"status"`
	TerminalState string                    `json:"terminal_state"`
	ResultRef     DatabricksResultReference `json:"result_ref"`
	EvidenceRefs  []string                  `json:"evidence_refs"`
	ContentSHA256 string                    `json:"content_sha256"`
	SizeBytes     int                       `json:"size_bytes"`
	CreatedAt     Time                      `json:"created_at"`
}

// CapabilityRunStatus is the polled lifecycle status.
type CapabilityRunStatus struct {
	Capability    string               `json:"capability"`
	ContractID    string               `json:"contract_id"`
	RequestID     string               `json:"request_id"`
	CorrelationID string               `json:"correlation_id"`
	RunID         string               `json:"run_id"`
	Status        string               `json:"status"`
	TerminalState *string              `json:"terminal_state"`
	ResultID      *string              `json:"result_id"`
	CreatedAt     Time                 `json:"created_at"`
	StartedAt     *Time                `json:"started_at"`
	UpdatedAt     Time                 `json:"updated_at"`
	CompletedAt   *Time                `json:"completed_at"`
	Progress      RunProgress          `json:"progress"`
	Failure       *RunFailure          `json:"failure"`
	Completion    *CanonicalCompletion `json:"completion"`
}

// CapabilityRunSubmission is the 202 body for an accepted async submission.
type CapabilityRunSubmission struct {
	Capability    string `json:"capability"`
	ContractID    string `json:"contract_id"`
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	StatusURL     string `json:"status_url"`
	ResultURL     string `json:"result_url"`
	AcceptedAt    Time   `json:"accepted_at"`
}
