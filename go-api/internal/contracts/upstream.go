package contracts

import "strings"

// DatabricksResultReference is an authoritative pointer to one upstream result
// row. The three references in a request are the only rows this service reads;
// it never searches for a recent or similar row.
type DatabricksResultReference struct {
	System string `json:"system"`
	// SchemaName serializes as "schema"; the Python model uses the same alias
	// because `schema` collides with BaseModel.schema().
	Catalog    string `json:"catalog"`
	SchemaName string `json:"schema"`
	Table      string `json:"table"`
	Key        string `json:"key"`
}

// Validate enforces that references point at Databricks and are complete.
func (d DatabricksResultReference) Validate(field string) error {
	if !strings.EqualFold(strings.TrimSpace(d.System), "databricks") {
		return invalid(field, "upstream result references must use Databricks")
	}
	for _, value := range []string{d.Catalog, d.SchemaName, d.Table, d.Key} {
		if strings.TrimSpace(value) == "" {
			return invalid(field, "Databricks result-reference fields cannot be empty")
		}
	}
	return nil
}

// Equal reports whether two references address the same row.
func (d DatabricksResultReference) Equal(other DatabricksResultReference) bool { return d == other }

// UpstreamResultReferences are the role-bound proof-loop records. The rule to
// compile is read from the Defense Generation row.
type UpstreamResultReferences struct {
	DefenseGeneration DatabricksResultReference `json:"defense_generation"`
	MitigationCheck   DatabricksResultReference `json:"mitigation_check"`
	BypassValidation  DatabricksResultReference `json:"bypass_validation"`
}

// Validate checks all three references.
func (u *UpstreamResultReferences) Validate() error {
	for field, ref := range map[string]DatabricksResultReference{
		"upstream_result_refs.defense_generation": u.DefenseGeneration,
		"upstream_result_refs.mitigation_check":   u.MitigationCheck,
		"upstream_result_refs.bypass_validation":  u.BypassValidation,
	} {
		if err := ref.Validate(field); err != nil {
			return err
		}
	}
	return nil
}

// ProofLoopRoutingMetadata carries orchestration-owned routing facts.
type ProofLoopRoutingMetadata struct {
	LoopExhausted                 bool                      `json:"loop_exhausted"`
	CompletedIterations           int                       `json:"completed_iterations"`
	MaxIterations                 int                       `json:"max_iterations"`
	BypassValidationTerminalState string                    `json:"bypass_validation_terminal_state"`
	BypassValidationResultRef     DatabricksResultReference `json:"bypass_validation_result_ref"`
}

// Validate enforces the two accepted routes and their iteration accounting.
func (m *ProofLoopRoutingMetadata) Validate() error {
	if m.CompletedIterations < 1 {
		return invalid("routing_metadata.completed_iterations", "must be at least 1")
	}
	if m.MaxIterations < 1 {
		return invalid("routing_metadata.max_iterations", "must be at least 1")
	}
	if m.CompletedIterations > m.MaxIterations {
		return invalid("routing_metadata", "completed_iterations cannot exceed max_iterations")
	}
	switch m.BypassValidationTerminalState {
	case "no-bypass-found":
		if m.LoopExhausted {
			return invalid("routing_metadata", "loop_exhausted must be false when no bypass was found")
		}
	case "bypass-found":
		if !m.LoopExhausted {
			return invalid("routing_metadata",
				"bypass-found is accepted only when the candidate loop is exhausted")
		}
		if m.MaxIterations != 10 {
			return invalid("routing_metadata", "the PoC exhaustion route requires max_iterations to be 10")
		}
		if m.CompletedIterations != m.MaxIterations {
			return invalid("routing_metadata", "an exhausted candidate loop must complete max_iterations")
		}
	default:
		return invalid("routing_metadata.bypass_validation_terminal_state",
			"must be 'no-bypass-found' or 'bypass-found'")
	}
	return m.BypassValidationResultRef.Validate("routing_metadata.bypass_validation_result_ref")
}

// ProofLoopQualification records the route. Loop exhaustion is not bypass
// clearance, and the result says so explicitly.
type ProofLoopQualification struct {
	Route                         string                    `json:"route"`
	BypassCleared                 bool                      `json:"bypass_cleared"`
	LoopExhausted                 bool                      `json:"loop_exhausted"`
	CompletedIterations           int                       `json:"completed_iterations"`
	MaxIterations                 int                       `json:"max_iterations"`
	BypassValidationTerminalState string                    `json:"bypass_validation_terminal_state"`
	BypassValidationResultRef     DatabricksResultReference `json:"bypass_validation_result_ref"`
}

// BypassCounterexample is bounded bypass evidence kept for an exhausted route,
// so an operator reviewing a not-bypass-cleared candidate can see why.
type BypassCounterexample struct {
	CounterexampleID string   `json:"counterexample_id"`
	SampleRef        string   `json:"sample_ref"`
	VariantFamily    string   `json:"variant_family"`
	ObservedBehavior string   `json:"observed_behavior"`
	EvidenceRefs     []string `json:"evidence_refs"`
}
