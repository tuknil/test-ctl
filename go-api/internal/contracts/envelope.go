package contracts

import "strings"

// Provenance names the caller and the system it called from.
type Provenance struct {
	Caller string `json:"caller"`
	Source string `json:"source"`
}

// InvocationSubject is the orchestration-owned binding for one candidate. It
// is what the fetched rows are checked against: a row belonging to a different
// vulnerability or candidate is refused, not translated.
type InvocationSubject struct {
	VulnerabilityID string `json:"vulnerability_id"`
	CandidateID     string `json:"candidate_id"`
}

// OrchestrationUpstreamInput is one immutable completion from Temporal. Its
// result_ref names the Databricks row this service reads.
type OrchestrationUpstreamInput struct {
	Capability    string                    `json:"capability"`
	ContractID    string                    `json:"contract_id"`
	RunID         string                    `json:"run_id"`
	ResultID      string                    `json:"result_id"`
	TerminalState string                    `json:"terminal_state"`
	Status        string                    `json:"status"`
	CorrelationID string                    `json:"correlation_id"`
	ResultRef     DatabricksResultReference `json:"result_ref"`
	EvidenceRefs  []string                  `json:"evidence_refs"`
}

var acceptedCompletionContracts = map[string]map[string]bool{
	"defense-generation": {
		"defense-generation@1.0":        true,
		"defense-generation-result@1.0": true,
	},
	"mitigation-check": {"mitigation-check@1.0": true},
	// The deployed producer sends the common completion-envelope ID. The
	// canonical row itself is validated as bypass-validation@1.0.
	"bypass-validation": {
		"capability-completion@1.0": true,
		"bypass-validation@1.0":     true,
	},
}

var expectedCompletionStates = map[string]map[string]bool{
	"defense-generation": {"candidate-produced": true},
	"mitigation-check":   {"blocked": true},
	"bypass-validation":  {"no-bypass-found": true, "bypass-found": true},
}

// Validate enforces the completion contract for one upstream input.
func (o *OrchestrationUpstreamInput) Validate() error {
	accepted, known := acceptedCompletionContracts[o.Capability]
	if !known {
		return invalid("upstream_inputs.capability", "unsupported capability")
	}
	if o.Status != "completed" {
		return invalid("upstream_inputs.status", "must be 'completed'")
	}
	if !accepted[o.ContractID] {
		return invalid("upstream_inputs.contract_id", "unsupported "+o.Capability+" completion contract")
	}
	if !expectedCompletionStates[o.Capability][o.TerminalState] {
		return invalid("upstream_inputs.terminal_state", "invalid "+o.Capability+" terminal state")
	}
	for field, value := range map[string]string{
		"run_id": o.RunID, "result_id": o.ResultID, "correlation_id": o.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return invalid("upstream_inputs."+field, "is required")
		}
	}
	if err := o.ResultRef.Validate("upstream_inputs.result_ref"); err != nil {
		return err
	}
	if o.ResultRef.Key != o.ResultID {
		return invalid("upstream_inputs.result_ref", "result_ref.key must equal result_id")
	}
	seen := map[string]bool{}
	for _, ref := range o.EvidenceRefs {
		if ref == "" {
			return invalid("upstream_inputs.evidence_refs", "evidence references cannot be empty")
		}
		if seen[ref] {
			return invalid("upstream_inputs.evidence_refs", "evidence references must be unique")
		}
		seen[ref] = true
	}
	return nil
}

// OrchestrationRoutingContext is the Temporal-owned routing decision.
type OrchestrationRoutingContext struct {
	Route                         string `json:"route"`
	MitigationCheckTerminalState  string `json:"mitigation_check_terminal_state"`
	MitigationCheckMatch          bool   `json:"mitigation_check_match"`
	BypassValidationTerminalState string `json:"bypass_validation_terminal_state"`
	LoopExhausted                 bool   `json:"loop_exhausted"`
	CompletedIterations           int    `json:"completed_iterations"`
	MaxIterations                 int    `json:"max_iterations"`
}

// Validate enforces the two accepted orchestration routes.
func (r *OrchestrationRoutingContext) Validate() error {
	if r.MitigationCheckTerminalState != "blocked" {
		return invalid("routing_context.mitigation_check_terminal_state", "must be 'blocked'")
	}
	if !r.MitigationCheckMatch {
		return invalid("routing_context.mitigation_check_match", "must be true")
	}
	if r.CompletedIterations < 1 || r.MaxIterations < 1 {
		return invalid("routing_context", "iteration counts must be at least 1")
	}
	switch r.Route {
	case "validated":
		if r.LoopExhausted || r.BypassValidationTerminalState != "no-bypass-found" {
			return invalid("routing_context", "validated route requires no-bypass-found")
		}
	case "loop-exhausted":
		if !r.LoopExhausted ||
			r.BypassValidationTerminalState != "bypass-found" ||
			r.CompletedIterations != r.MaxIterations ||
			r.MaxIterations != 10 {
			return invalid("routing_context",
				"loop-exhausted route requires bypass-found at 10 of 10 iterations")
		}
	default:
		return invalid("routing_context.route", "must be 'validated' or 'loop-exhausted'")
	}
	return nil
}

// InvokeRequestEnvelope is the POST /invoke request contract.
//
// Two accepted forms:
//
//   - referenced: contract_id + subject + upstream_inputs + routing_context,
//     which names the three Databricks rows to read. The rule is taken from
//     the Defense Generation row.
//   - direct: an inline input.proven_pattern, for fixtures and local testing.
type InvokeRequestEnvelope struct {
	ContractID              *string                      `json:"contract_id"`
	Input                   ControlTranslationRequest    `json:"input"`
	Subject                 *InvocationSubject           `json:"subject"`
	UpstreamInputs          []OrchestrationUpstreamInput `json:"upstream_inputs"`
	RoutingContext          *OrchestrationRoutingContext `json:"routing_context"`
	UpstreamResultRefs      *UpstreamResultReferences    `json:"upstream_result_refs"`
	RoutingMetadata         *ProofLoopRoutingMetadata    `json:"routing_metadata"`
	RequestID               *string                      `json:"request_id"`
	CorrelationID           *string                      `json:"correlation_id"`
	IdempotencyKey          *string                      `json:"idempotency_key"`
	SubjectRecordRevisionID *string                      `json:"subject_record_revision_id"`
	ProvenanceInfo          *Provenance                  `json:"provenance"`
}

// UnmarshalJSON rejects unknown fields, matching extra="forbid".
func (e *InvokeRequestEnvelope) UnmarshalJSON(data []byte) error {
	type alias InvokeRequestEnvelope
	value := alias{Input: ControlTranslationRequest{TranslationPolicy: DefaultTranslationPolicy()}}
	if err := strictUnmarshal(data, &value); err != nil {
		return err
	}
	*e = InvokeRequestEnvelope(value)
	return nil
}

// Validate normalizes an orchestration envelope into the referenced form and
// enforces the cross-field rules. It fills upstream_result_refs and
// routing_metadata from upstream_inputs and routing_context.
func (e *InvokeRequestEnvelope) Validate() error {
	if err := e.Input.Validate(); err != nil {
		return err
	}
	for field, value := range map[string]*string{
		"correlation_id":             e.CorrelationID,
		"idempotency_key":            e.IdempotencyKey,
		"subject_record_revision_id": e.SubjectRecordRevisionID,
	} {
		if value != nil && strings.TrimSpace(*value) == "" {
			return invalid(field, "must not be empty when supplied")
		}
	}
	if e.ContractID != nil && *e.ContractID != "control-translation@1.0" {
		return invalid("contract_id", "must be 'control-translation@1.0'")
	}
	if err := e.normalizeOrchestration(); err != nil {
		return err
	}

	if e.UpstreamResultRefs == nil && e.RoutingMetadata != nil {
		return invalid("routing_metadata", "routing_metadata requires authoritative upstream_result_refs")
	}
	if e.UpstreamResultRefs != nil && e.RoutingMetadata == nil {
		return invalid("routing_metadata", "routing_metadata is required for referenced proof-loop invocation")
	}
	if e.UpstreamResultRefs != nil {
		if err := e.UpstreamResultRefs.Validate(); err != nil {
			return err
		}
		if err := e.RoutingMetadata.Validate(); err != nil {
			return err
		}
		if !e.RoutingMetadata.BypassValidationResultRef.Equal(e.UpstreamResultRefs.BypassValidation) {
			return invalid("routing_metadata",
				"routing bypass reference must match upstream_result_refs.bypass_validation")
		}
	}
	return nil
}

func (e *InvokeRequestEnvelope) normalizeOrchestration() error {
	present := e.ContractID != nil || e.UpstreamInputs != nil || e.RoutingContext != nil
	if !present {
		return nil
	}
	if e.ContractID == nil || e.RequestID == nil || e.CorrelationID == nil ||
		e.Subject == nil || e.UpstreamInputs == nil || e.RoutingContext == nil ||
		e.ProvenanceInfo == nil {
		return invalid("", "orchestration requests require contract_id, request_id, "+
			"correlation_id, subject, upstream_inputs, routing_context, and provenance")
	}
	if strings.TrimSpace(e.Subject.VulnerabilityID) == "" || strings.TrimSpace(e.Subject.CandidateID) == "" {
		return invalid("subject", "vulnerability_id and candidate_id are required")
	}
	if len(e.UpstreamInputs) != 3 {
		return invalid("upstream_inputs", "orchestration requests require exactly three upstream inputs")
	}
	inputs := map[string]OrchestrationUpstreamInput{}
	for index := range e.UpstreamInputs {
		item := e.UpstreamInputs[index]
		if err := item.Validate(); err != nil {
			return err
		}
		inputs[item.Capability] = item
	}
	if len(inputs) != 3 {
		return invalid("upstream_inputs", "orchestration upstream capabilities must be unique")
	}
	for _, item := range e.UpstreamInputs {
		if item.CorrelationID != *e.CorrelationID {
			return invalid("upstream_inputs", "upstream correlation_id does not match command")
		}
	}
	if err := e.RoutingContext.Validate(); err != nil {
		return err
	}
	if inputs["bypass-validation"].TerminalState != e.RoutingContext.BypassValidationTerminalState {
		return invalid("routing_context", "routing bypass state does not match upstream completion")
	}

	normalizedRefs := &UpstreamResultReferences{
		DefenseGeneration: inputs["defense-generation"].ResultRef,
		MitigationCheck:   inputs["mitigation-check"].ResultRef,
		BypassValidation:  inputs["bypass-validation"].ResultRef,
	}
	normalizedRouting := &ProofLoopRoutingMetadata{
		LoopExhausted:                 e.RoutingContext.LoopExhausted,
		CompletedIterations:           e.RoutingContext.CompletedIterations,
		MaxIterations:                 e.RoutingContext.MaxIterations,
		BypassValidationTerminalState: e.RoutingContext.BypassValidationTerminalState,
		BypassValidationResultRef:     inputs["bypass-validation"].ResultRef,
	}
	if e.UpstreamResultRefs != nil && *e.UpstreamResultRefs != *normalizedRefs {
		return invalid("upstream_result_refs", "normalized upstream references do not match orchestration inputs")
	}
	if e.RoutingMetadata != nil && *e.RoutingMetadata != *normalizedRouting {
		return invalid("routing_metadata", "normalized routing metadata does not match routing_context")
	}
	e.UpstreamResultRefs = normalizedRefs
	e.RoutingMetadata = normalizedRouting
	if e.IdempotencyKey != nil && *e.IdempotencyKey != *e.RequestID {
		return invalid("idempotency_key", "orchestration idempotency_key must equal request_id")
	}
	e.IdempotencyKey = e.RequestID
	return nil
}
