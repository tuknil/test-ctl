// Package upstream resolves and validates authoritative proof-loop records.
//
// The rule this service compiles comes from the Defense Generation row's
// primary_candidate.artifact_content. This package fetches exactly the three
// rows named in the request's upstream_inputs and refuses to promote them
// into translation input unless correlation, subject, vulnerability, and
// candidate lineage all agree across all three. It never guesses and never
// falls back to a recent row.
//
// That validation is the point: without it the service would happily compile a
// rule belonging to a different candidate.
package upstream

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
)

// ErrResolution reports that a referenced record cannot safely be promoted.
var ErrResolution = errors.New("upstream resolution failed")

func resolutionError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrResolution, fmt.Sprintf(format, args...))
}

// Message strips the wrapper so the detail matches the Python service's text.
func Message(err error) string {
	text := err.Error()
	if prefix := ErrResolution.Error() + ": "; strings.HasPrefix(text, prefix) {
		return strings.TrimPrefix(text, prefix)
	}
	return text
}

// Record is one authoritative upstream result row.
type Record struct {
	ResultID                string
	TerminalState           string
	CorrelationID           *string
	SubjectRecordRevisionID *string
	Request                 map[string]any
	Result                  map[string]any
}

// Document is the whole row as one traversable object, matching the Python
// UpstreamRecord.document property.
func (r Record) Document() map[string]any {
	document := map[string]any{
		"result_id":      r.ResultID,
		"terminal_state": r.TerminalState,
		"request":        r.Request,
		"result":         r.Result,
	}
	if r.CorrelationID != nil {
		document["correlation_id"] = *r.CorrelationID
	} else {
		document["correlation_id"] = nil
	}
	if r.SubjectRecordRevisionID != nil {
		document["subject_record_revision_id"] = *r.SubjectRecordRevisionID
	} else {
		document["subject_record_revision_id"] = nil
	}
	return document
}

// Resolver fetches one authoritative upstream result row.
type Resolver interface {
	Fetch(reference contracts.DatabricksResultReference) (*Record, error)
}

// ResolvedProofLoop is the validated translation input assembled from three
// authoritative rows.
type ResolvedProofLoop struct {
	Pattern               contracts.ProvenMitigationPattern
	References            contracts.UpstreamResultReferences
	Qualification         contracts.ProofLoopQualification
	TargetTechnology      string
	TargetPolicyContextID string
	BypassCounterexample  *contracts.BypassCounterexample
	BypassEvidenceRefs    []string
}

// ResolveInput carries the caller-supplied identity the lineage is checked
// against.
type ResolveInput struct {
	References              contracts.UpstreamResultReferences
	Resolver                Resolver
	CorrelationID           string
	SubjectRecordRevisionID string
	RoutingMetadata         contracts.ProofLoopRoutingMetadata
	ExpectedVulnerabilityID string
	ExpectedCandidateID     string
}

const (
	roleDefense    = "Defense Generation"
	roleMitigation = "Mitigation Check"
	roleBypass     = "Bypass Validation"
)

// ResolveProofLoop fetches all three records and enforces proof state and
// cross-record lineage before any translation is attempted.
func ResolveProofLoop(in ResolveInput) (*ResolvedProofLoop, error) {
	if in.CorrelationID == "" {
		return nil, resolutionError("correlation_id is required for lineage validation")
	}
	hasOrchestrationSubject := in.ExpectedVulnerabilityID != "" && in.ExpectedCandidateID != ""
	if in.SubjectRecordRevisionID == "" && !hasOrchestrationSubject {
		return nil, resolutionError("subject_record_revision_id or an orchestration subject binding " +
			"is required for lineage validation")
	}

	requiredBypassState := in.RoutingMetadata.BypassValidationTerminalState
	roleRefs := []struct {
		role     string
		ref      contracts.DatabricksResultReference
		required string
	}{
		{roleDefense, in.References.DefenseGeneration, "candidate-produced"},
		{roleMitigation, in.References.MitigationCheck, "blocked"},
		{roleBypass, in.References.BypassValidation, requiredBypassState},
	}

	records := map[string]Record{}
	for _, entry := range roleRefs {
		record, err := in.Resolver.Fetch(entry.ref)
		if err != nil {
			if errors.Is(err, ErrResolution) {
				return nil, err
			}
			return nil, resolutionError("%s result could not be fetched", entry.role)
		}
		if record == nil {
			return nil, resolutionError("%s result reference was not found", entry.role)
		}
		if record.ResultID != entry.ref.Key {
			return nil, resolutionError("%s result ID does not match its reference", entry.role)
		}
		if record.TerminalState != entry.required {
			return nil, resolutionError("%s terminal state must be '%s'", entry.role, entry.required)
		}
		if err := validateRecordIdentity(entry.role, *record); err != nil {
			return nil, err
		}
		records[entry.role] = *record
	}

	for _, role := range []string{roleDefense, roleMitigation, roleBypass} {
		record := records[role]
		document := record.Document()
		recordCorrelation := oneValue(document, "correlation_id")
		recordSubject := oneValue(document, "subject_record_revision_id")
		if recordCorrelation != nil && *recordCorrelation != in.CorrelationID {
			return nil, resolutionError("%s correlation lineage could not be validated", role)
		}
		if recordCorrelation == nil && !hasOrchestrationSubject {
			return nil, resolutionError("%s correlation lineage could not be validated", role)
		}
		if in.SubjectRecordRevisionID != "" && recordSubject != nil &&
			*recordSubject != in.SubjectRecordRevisionID {
			return nil, resolutionError("%s subject lineage could not be validated", role)
		}
		if recordSubject == nil && !hasOrchestrationSubject {
			return nil, resolutionError("%s subject lineage could not be validated", role)
		}
	}

	var vulnerabilityID, candidateID string
	if hasOrchestrationSubject {
		vulnerabilityID, candidateID = in.ExpectedVulnerabilityID, in.ExpectedCandidateID
		for _, role := range []string{roleDefense, roleMitigation, roleBypass} {
			record := records[role]
			if value := roleVulnerabilityID(role, record); value != "" && value != vulnerabilityID {
				return nil, resolutionError("%s vulnerability lineage does not match orchestration subject", role)
			}
			if value := roleCandidateID(role, record); value != "" && value != candidateID {
				return nil, resolutionError("%s candidate lineage does not match orchestration subject", role)
			}
		}
		if roleVulnerabilityID(roleDefense, records[roleDefense]) == "" {
			return nil, resolutionError("Defense Generation vulnerability_id is missing")
		}
		if roleCandidateID(roleDefense, records[roleDefense]) == "" {
			return nil, resolutionError("Defense Generation candidate_id is missing")
		}
	} else {
		vulnerabilities := map[string]bool{}
		candidates := map[string]bool{}
		for _, role := range []string{roleDefense, roleMitigation, roleBypass} {
			document := records[role].Document()
			vulnerability := oneValue(document, "vulnerability_id")
			if vulnerability == nil {
				return nil, resolutionError("%s vulnerability_id is missing or ambiguous", role)
			}
			candidate := oneValue(document, "candidate_id")
			if candidate == nil {
				return nil, resolutionError("%s candidate_id is missing or ambiguous", role)
			}
			vulnerabilities[*vulnerability] = true
			candidates[*candidate] = true
			if role == roleDefense {
				vulnerabilityID, candidateID = *vulnerability, *candidate
			}
		}
		if len(vulnerabilities) != 1 {
			return nil, resolutionError("upstream vulnerability lineage does not match")
		}
		if len(candidates) != 1 {
			return nil, resolutionError("upstream candidate lineage does not match")
		}
	}

	defense := records[roleDefense]
	primaryCandidate, ok := defense.Result["primary_candidate"].(map[string]any)
	if !ok {
		return nil, resolutionError("Defense Generation primary_candidate is missing")
	}
	discriminator := firstString(primaryCandidate["discriminator"], defense.Request["discriminator"])
	if discriminator == "" {
		return nil, resolutionError("Defense Generation discriminator context is missing")
	}
	selectedControlClass := firstString(
		primaryCandidate["selected_control_class"], defense.Request["selected_control_class"])
	if selectedControlClass == "" {
		return nil, resolutionError("Defense Generation selected control class is missing")
	}
	artifactContent := firstString(primaryCandidate["artifact_content"])
	if artifactContent == "" {
		return nil, resolutionError("Defense Generation candidate artifact content is missing")
	}

	mitigationID := records[roleMitigation].ResultID
	bypassID := records[roleBypass].ResultID

	bypassCleared := requiredBypassState == "no-bypass-found"
	patternIDPrefix := "proven-pattern:"
	if !bypassCleared {
		patternIDPrefix = "loop-exhausted-pattern:"
	}
	pattern := contracts.ProvenMitigationPattern{
		ProvenPatternID:          patternIDPrefix + candidateID,
		VulnerabilityID:          vulnerabilityID,
		SelectedControlClass:     selectedControlClass,
		DiscriminatorID:          "discriminator:" + candidateID,
		DiscriminatorDescription: discriminator,
		PatternSummary:           artifactContent,
		ProofRecordIDs:           []string{mitigationID, bypassID},
	}
	if err := pattern.Validate(); err != nil {
		return nil, resolutionError("%s", err.Error())
	}

	route := "validated"
	if !bypassCleared {
		route = "poc-exhaustion"
	}
	qualification := contracts.ProofLoopQualification{
		Route:                         route,
		BypassCleared:                 bypassCleared,
		LoopExhausted:                 in.RoutingMetadata.LoopExhausted,
		CompletedIterations:           in.RoutingMetadata.CompletedIterations,
		MaxIterations:                 in.RoutingMetadata.MaxIterations,
		BypassValidationTerminalState: requiredBypassState,
		BypassValidationResultRef:     in.RoutingMetadata.BypassValidationResultRef,
	}

	bypassResult := records[roleBypass].Result
	rawCounterexample := bypassResult["bypass_counterexample"]
	var counterexample *contracts.BypassCounterexample
	if rawCounterexample != nil {
		parsed, err := parseCounterexample(rawCounterexample)
		if err != nil {
			return nil, resolutionError("Bypass Validation counterexample contract is malformed")
		}
		counterexample = parsed
	}
	evidenceSet := map[string]bool{}
	if counterexample != nil {
		for _, ref := range counterexample.EvidenceRefs {
			evidenceSet[ref] = true
		}
		evidenceSet[counterexample.SampleRef] = true
	}
	feedback, _ := bypassResult["feedback"].(map[string]any)
	_ = feedback
	if refs, ok := feedback["evidence_refs"].([]any); ok {
		for _, item := range refs {
			if text, ok := item.(string); ok && text != "" {
				evidenceSet[text] = true
			}
		}
	}
	evidenceRefs := sortedKeys(evidenceSet)

	return &ResolvedProofLoop{
		Pattern:               pattern,
		References:            in.References,
		Qualification:         qualification,
		TargetTechnology:      preferredString("target_technology", defense.Result, defense.Request),
		TargetPolicyContextID: preferredString("target_policy_context_id", defense.Result, defense.Request),
		BypassCounterexample:  counterexample,
		BypassEvidenceRefs:    evidenceRefs,
	}, nil
}

func validateRecordIdentity(role string, record Record) error {
	expected := map[string]struct {
		capability string
		contracts  map[string]bool
	}{
		roleDefense: {"defense-generation", map[string]bool{
			"defense-generation@1.0": true, "defense-generation-result@1.0": true}},
		roleMitigation: {"mitigation-check", map[string]bool{"mitigation-check@1.0": true}},
		roleBypass:     {"bypass-validation", map[string]bool{"bypass-validation@1.0": true}},
	}[role]

	if capability, present := record.Result["capability"]; present && capability != nil {
		if capability != expected.capability {
			return resolutionError("%s capability identity is invalid", role)
		}
	}
	if contractID, present := record.Result["contract_id"]; present && contractID != nil {
		text, _ := contractID.(string)
		if !expected.contracts[text] {
			return resolutionError("%s result contract is unsupported", role)
		}
	}
	return nil
}

func parseCounterexample(raw any) (*contracts.BypassCounterexample, error) {
	typed, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("counterexample is not an object")
	}
	counterexample := &contracts.BypassCounterexample{EvidenceRefs: []string{}}
	for field, target := range map[string]*string{
		"counterexample_id": &counterexample.CounterexampleID,
		"sample_ref":        &counterexample.SampleRef,
		"variant_family":    &counterexample.VariantFamily,
		"observed_behavior": &counterexample.ObservedBehavior,
	} {
		text, ok := typed[field].(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("counterexample.%s is required", field)
		}
		*target = text
	}
	if refs, ok := typed["evidence_refs"].([]any); ok {
		for _, item := range refs {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New("counterexample.evidence_refs must be strings")
			}
			counterexample.EvidenceRefs = append(counterexample.EvidenceRefs, text)
		}
	}
	return counterexample, nil
}

// ---------------------------------------------------------------------------
// Traversal helpers
// ---------------------------------------------------------------------------

// oneValue returns the value stored under key when the whole document holds
// exactly one distinct non-empty string for it, and nil when it is missing or
// ambiguous. Ambiguity is a lineage failure, never a pick-the-first choice.
func oneValue(document any, key string) *string {
	values := map[string]bool{}
	var visit func(value any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for childKey, childValue := range typed {
				if childKey == key {
					if text, ok := childValue.(string); ok && text != "" {
						values[text] = true
					}
				}
				visit(childValue)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(document)
	if len(values) != 1 {
		return nil
	}
	for value := range values {
		return &value
	}
	return nil
}

// roleVulnerabilityID extracts canonical vulnerability lineage without
// mistaking a candidate ID for one.
func roleVulnerabilityID(role string, record Record) string {
	switch role {
	case roleDefense:
		if primary, ok := record.Result["primary_candidate"].(map[string]any); ok {
			if value := firstString(primary["vulnerability_id"]); value != "" {
				return value
			}
		}
		return firstString(record.Request["vulnerability_id"])
	case roleBypass:
		if subject, ok := record.Result["subject"].(map[string]any); ok {
			if value := firstString(subject["vulnerability_id"]); strings.HasPrefix(value, "CVE-") {
				return value
			}
		}
		return ""
	default:
		if value := oneValue(record.Document(), "vulnerability_id"); value != nil {
			return *value
		}
		return ""
	}
}

// roleCandidateID extracts the selected source candidate rather than history
// or generated test variants.
func roleCandidateID(role string, record Record) string {
	switch role {
	case roleDefense:
		if primary, ok := record.Result["primary_candidate"].(map[string]any); ok {
			return firstString(primary["candidate_id"])
		}
		return ""
	case roleBypass:
		subject, ok := record.Result["subject"].(map[string]any)
		if !ok {
			return ""
		}
		if source := firstString(subject["source_candidate_id"]); source != "" {
			return source
		}
		// bypass-validation@1.0 currently places the source Defense candidate
		// in vulnerability_id and the generated test variant in candidate_id.
		// Only the former is source lineage.
		if legacy := firstString(subject["vulnerability_id"]); strings.HasPrefix(legacy, "candidate:") {
			return legacy
		}
		return ""
	default:
		if value := oneValue(record.Document(), "candidate_id"); value != nil {
			return *value
		}
		return ""
	}
}

func preferredString(key string, documents ...map[string]any) string {
	for _, document := range documents {
		if document == nil {
			continue
		}
		if value := firstString(document[key]); value != "" {
			return value
		}
		if primary, ok := document["primary_candidate"].(map[string]any); ok {
			if value := firstString(primary[key]); value != "" {
				return value
			}
		}
		if target, ok := document["target_context"].(map[string]any); ok {
			if value := firstString(target[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func firstString(values ...any) string {
	for _, value := range values {
		if text, ok := value.(string); ok && text != "" {
			return text
		}
	}
	return ""
}

func preferredNonEmpty(values ...any) string {
	for _, value := range values {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return text
		}
	}
	return ""
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
