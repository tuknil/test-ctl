// Package contracts holds the control-translation request and result models.
//
// JSON shape matches the Python service, including explicit nulls for absent
// optional fields and empty arrays for empty lists, because the same UI reads
// both. This lean build carries only the fields its one execution path uses:
// the orchestration envelope, the proof-loop qualification, and the async
// lifecycle contracts are not part of it.
package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Time is an RFC3339 timestamp rendered the way Pydantic renders one:
// microsecond precision with a trailing Z.
type Time struct{ time.Time }

// MarshalJSON renders the timestamp in the Python service's exact format.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}

// UnmarshalJSON accepts any RFC3339 timestamp.
func (t *Time) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return fmt.Errorf("invalid timestamp %q", raw)
	}
	t.Time = parsed
	return nil
}

// Now returns the current time in the contract's representation.
func Now() Time { return Time{time.Now().UTC()} }

// strictUnmarshal decodes into target and rejects unknown fields. Custom
// UnmarshalJSON methods do not inherit the caller's DisallowUnknownFields
// setting, so every model that defines one must re-apply it or the Python
// models' extra="forbid" would silently stop being enforced.
func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// ValidationError reports a rejected request contract. The HTTP layer turns it
// into a 422.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

func invalid(field, reason string) error { return &ValidationError{Field: field, Reason: reason} }

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

// ProvenMitigationPattern is a pattern proven by the upstream fast proof loop.
// PatternSummary carries the authoritative defense-generation artifact: the
// ModSecurity SecRule this service compiles.
type ProvenMitigationPattern struct {
	ProvenPatternID          string   `json:"proven_pattern_id"`
	VulnerabilityID          string   `json:"vulnerability_id"`
	SelectedControlClass     string   `json:"selected_control_class"`
	DiscriminatorID          string   `json:"discriminator_id"`
	DiscriminatorDescription string   `json:"discriminator_description"`
	PatternSummary           string   `json:"pattern_summary"`
	ProofRecordIDs           []string `json:"proof_record_ids"`
}

// Validate checks promotion lineage without re-performing upstream proof.
func (p *ProvenMitigationPattern) Validate() error {
	for field, value := range map[string]string{
		"proven_pattern_id":         p.ProvenPatternID,
		"vulnerability_id":          p.VulnerabilityID,
		"selected_control_class":    p.SelectedControlClass,
		"discriminator_id":          p.DiscriminatorID,
		"discriminator_description": p.DiscriminatorDescription,
		"pattern_summary":           p.PatternSummary,
	} {
		if strings.TrimSpace(value) == "" {
			return invalid("proven_pattern."+field, "is required")
		}
	}
	if len(p.ProofRecordIDs) < 2 {
		return invalid("proven_pattern.proof_record_ids", "requires at least 2 items")
	}
	seen := map[string]bool{}
	var hasMitigation, hasBypass bool
	for _, id := range p.ProofRecordIDs {
		if seen[id] {
			return invalid("proven_pattern.proof_record_ids", "proof_record_ids must be unique")
		}
		seen[id] = true
		if strings.HasPrefix(id, "mitigation-check-result:") {
			hasMitigation = true
		}
		if strings.HasPrefix(id, "bypass-validation-result:") {
			hasBypass = true
		}
	}
	if !hasMitigation {
		return invalid("proven_pattern.proof_record_ids", "a mitigation-check result reference is required")
	}
	if !hasBypass {
		return invalid("proven_pattern.proof_record_ids", "a bypass-validation result reference is required")
	}
	return nil
}

// TargetContext identifies the target control technology and policy context.
type TargetContext struct {
	TargetTechnology      string `json:"target_technology"`
	TargetPolicyContextID string `json:"target_policy_context_id"`
}

// TranslationPolicy carries the dials for how aggressive translation may be.
type TranslationPolicy struct {
	TranslationPolicyID        string `json:"translation_policy_id"`
	AllowNarrowerTranslation   bool   `json:"allow_narrower_translation"`
	AllowEquivalentTranslation bool   `json:"allow_equivalent_translation"`
}

// DefaultTranslationPolicy matches the Python default_factory.
func DefaultTranslationPolicy() TranslationPolicy {
	return TranslationPolicy{
		TranslationPolicyID:        "control-translation-policy:mvp1",
		AllowNarrowerTranslation:   true,
		AllowEquivalentTranslation: true,
	}
}

// UnmarshalJSON applies the Python defaults for omitted policy fields.
func (t *TranslationPolicy) UnmarshalJSON(data []byte) error {
	type alias TranslationPolicy
	value := alias(DefaultTranslationPolicy())
	if err := strictUnmarshal(data, &value); err != nil {
		return err
	}
	*t = TranslationPolicy(value)
	return nil
}

// ControlTranslationRequest is the input contract for one invocation.
type ControlTranslationRequest struct {
	ProvenPattern           *ProvenMitigationPattern `json:"proven_pattern"`
	TargetContext           *TargetContext           `json:"target_context"`
	TranslationPolicy       TranslationPolicy        `json:"translation_policy"`
	CurrentPolicySnapshotID string                   `json:"current_policy_snapshot_id"`
}

// UnmarshalJSON applies the translation-policy default when it is omitted.
func (r *ControlTranslationRequest) UnmarshalJSON(data []byte) error {
	type alias ControlTranslationRequest
	value := alias{TranslationPolicy: DefaultTranslationPolicy()}
	if err := strictUnmarshal(data, &value); err != nil {
		return err
	}
	*r = ControlTranslationRequest(value)
	return nil
}

// Validate checks the embedded proven pattern when one was supplied.
func (r *ControlTranslationRequest) Validate() error {
	if r.ProvenPattern != nil {
		return r.ProvenPattern.Validate()
	}
	return nil
}
