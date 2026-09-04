package capability

import (
	"log/slog"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

// InvokeEnvelope accepts the full API request envelope.
//
// When the envelope names upstream results, the three Databricks rows are
// fetched and lineage-checked first, and the rule to compile is taken from the
// Defense Generation row's primary_candidate.artifact_content. An inline
// input.proven_pattern is used as-is.
func InvokeEnvelope(
	envelope contracts.InvokeRequestEnvelope,
	resolver upstream.Resolver,
	options Options,
) contracts.ResultEnvelope {
	options.defaults()
	request := envelope.Input
	references := envelope.UpstreamResultRefs
	options.CorrelationID = derefString(envelope.CorrelationID)

	var resolved *upstream.ResolvedProofLoop
	if references != nil {
		bundle := referenceBundle(*references)
		if resolver == nil {
			// Databricks is not configured, so the referenced rows cannot be
			// read. That is a typed decline, never an attempt to proceed
			// without the authoritative rule.
			result := insufficientContextEnvelope(insufficientContextInput{
				Detail:                    "Referenced upstream results cannot be fetched with the current configuration.",
				Settings:                  options.Settings,
				CorrelationID:             options.CorrelationID,
				TargetContext:             request.TargetContext,
				ConfiguredPoCDefaultsUsed: request.TargetContext == nil,
				ReferenceBundle:           bundle,
			})
			return bindRequestContext(result, envelope)
		}
		outcome, err := upstream.ResolveProofLoop(upstream.ResolveInput{
			References:              *references,
			Resolver:                resolver,
			CorrelationID:           options.CorrelationID,
			SubjectRecordRevisionID: derefString(envelope.SubjectRecordRevisionID),
			RoutingMetadata:         *envelope.RoutingMetadata,
			ExpectedVulnerabilityID: subjectVulnerability(envelope),
			ExpectedCandidateID:     subjectCandidate(envelope),
		})
		if err != nil {
			slog.Error("upstream proof-loop resolution failed",
				"correlation_id", orDash(options.CorrelationID),
				"subject_record_revision_id", orDash(derefString(envelope.SubjectRecordRevisionID)),
				"error", err)
			result := insufficientContextEnvelope(insufficientContextInput{
				Detail:                    upstream.Message(err),
				Settings:                  options.Settings,
				CorrelationID:             options.CorrelationID,
				TargetContext:             request.TargetContext,
				ConfiguredPoCDefaultsUsed: request.TargetContext == nil,
				ReferenceBundle:           bundle,
			})
			return bindRequestContext(result, envelope)
		}
		resolved = outcome

		caller := contracts.TargetContext{}
		if request.TargetContext != nil {
			caller = *request.TargetContext
		}
		if caller.TargetTechnology == "" {
			caller.TargetTechnology = resolved.TargetTechnology
		}
		if caller.TargetPolicyContextID == "" {
			caller.TargetPolicyContextID = resolved.TargetPolicyContextID
		}
		request.ProvenPattern = &resolved.Pattern
		request.TargetContext = &caller
		options.ProofLoopQualification = &resolved.Qualification
	}

	result := Invoke(request, options)

	// A loop-exhausted candidate keeps the bypass evidence that explains why it
	// is not bypass-cleared, so an operator reviewing it can see the counterexample.
	if resolved != nil && resolved.Qualification.Route == "poc-exhaustion" {
		structured := result.StructuredResult
		if len(resolved.BypassEvidenceRefs) > 0 {
			structured.EvidenceBindings = append(structured.EvidenceBindings, contracts.EvidenceBinding{
				Claim:        "limitation",
				EvidenceRefs: append([]string{}, resolved.BypassEvidenceRefs...),
			})
		}
		structured.BypassCounterexample = resolved.BypassCounterexample
		result.StructuredResult = structured
	}
	return bindRequestContext(result, envelope)
}

func bindRequestContext(
	result contracts.ResultEnvelope,
	envelope contracts.InvokeRequestEnvelope,
) contracts.ResultEnvelope {
	result.RequestID = envelope.RequestID
	result.UpstreamResultRefs = envelope.UpstreamResultRefs
	if envelope.UpstreamResultRefs != nil {
		result.ReferenceBundle = referenceBundle(*envelope.UpstreamResultRefs)
	} else {
		result.ReferenceBundle = jsonx.Obj{}
	}
	return result
}

// referenceBundle echoes exactly which rows were read, so a result can be
// traced back to its sources.
func referenceBundle(references contracts.UpstreamResultReferences) jsonx.Obj {
	encode := func(ref contracts.DatabricksResultReference) jsonx.Obj {
		return jsonx.Obj{}.
			Set("system", ref.System).
			Set("catalog", ref.Catalog).
			Set("schema", ref.SchemaName).
			Set("table", ref.Table).
			Set("key", ref.Key)
	}
	return jsonx.Obj{}.
		Set("defense_generation", encode(references.DefenseGeneration)).
		Set("mitigation_check", encode(references.MitigationCheck)).
		Set("bypass_validation", encode(references.BypassValidation))
}

func subjectVulnerability(envelope contracts.InvokeRequestEnvelope) string {
	if envelope.Subject == nil {
		return ""
	}
	return envelope.Subject.VulnerabilityID
}

func subjectCandidate(envelope contracts.InvokeRequestEnvelope) string {
	if envelope.Subject == nil {
		return ""
	}
	return envelope.Subject.CandidateID
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
