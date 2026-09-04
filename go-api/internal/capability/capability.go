// Package capability owns terminal-state routing, gate evaluation order, and
// result assembly for one control-translation invocation.
//
// Ported from src/control_translation/capability.py. No agent or provider code
// decides the terminal state directly: they return typed data that this
// package gates and interprets.
package capability

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/ATT-CSO/control-translation/go-api/internal/adapters"
	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
	"github.com/ATT-CSO/control-translation/go-api/internal/policy"
	"github.com/ATT-CSO/control-translation/go-api/internal/terminal"
	"github.com/ATT-CSO/control-translation/go-api/internal/translation"
)

// Options carries the injectable providers for one invocation.
type Options struct {
	Settings               config.Settings
	PolicyReader           policy.Reader
	CorrelationID          string
	ProofLoopQualification *contracts.ProofLoopQualification
}

func (o *Options) defaults() {
	if o.PolicyReader == nil {
		o.PolicyReader = policy.FixtureReader{}
	}
}

// Invoke is the direct invocation entry point.
func Invoke(request contracts.ControlTranslationRequest, options Options) contracts.ResultEnvelope {
	options.defaults()
	settings := options.Settings

	request, configuredDefaultsUsed := withEffectiveTargetContext(request, settings)
	if request.ProvenPattern == nil {
		return insufficientContextEnvelope(insufficientContextInput{
			Detail:                    "No proven pattern or upstream result references were supplied.",
			Settings:                  settings,
			CorrelationID:             options.CorrelationID,
			TargetContext:             request.TargetContext,
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
		})
	}

	pattern := *request.ProvenPattern
	targetTechnology := request.TargetContext.TargetTechnology
	targetPolicyContextID := request.TargetContext.TargetPolicyContextID

	// Gate 1: the target technology this build can translate to.
	//
	// A firewall or EDR candidate is a control this deployment does not carry,
	// not a malformed request, so it is cannot-express with the contract's
	// purpose-built reason code rather than invalid-input. The distinction is
	// what orchestration routes on: invalid-input says fix the request,
	// cannot-express says this capability cannot produce the artifact.
	adapter := adapters.Get(targetTechnology)
	if adapter == nil {
		result := buildResult(buildResultInput{
			Request:                   request,
			TerminalState:             terminal.CannotExpress,
			ReasonCode:                terminal.ReasonUnsupportedTargetTechnology,
			Detail:                    unsupportedTargetDetail(targetTechnology),
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, "none", options.CorrelationID)
	}

	expectedClass := adapters.TargetControlClasses[targetTechnology]
	if !strings.EqualFold(pattern.SelectedControlClass, expectedClass) {
		result := buildResult(buildResultInput{
			Request:       request,
			TerminalState: terminal.ScopeDeclined,
			ReasonCode:    terminal.ReasonInvalidInput,
			Detail: fmt.Sprintf(
				"Selected control class '%s' is not compatible with target technology '%s' (expected '%s').",
				pattern.SelectedControlClass, targetTechnology, expectedClass),
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, "none", options.CorrelationID)
	}

	// Gate 2: insufficient-context -- an ID alone is not policy content.
	// Always resolve the snapshot so conflict checks cannot be bypassed.
	snapshot := options.PolicyReader.ReadSnapshot(targetTechnology, targetPolicyContextID)
	if snapshot == nil {
		result := buildResult(buildResultInput{
			Request:       request,
			TerminalState: terminal.InsufficientContext,
			ReasonCode:    terminal.ReasonInsufficientPolicyContext,
			Detail: fmt.Sprintf(
				"No current policy snapshot available for %s/%s; cannot safely translate without reading current policy.",
				targetTechnology, targetPolicyContextID),
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, "none", options.CorrelationID)
	}
	if request.CurrentPolicySnapshotID != "" && request.CurrentPolicySnapshotID != snapshot.SnapshotID {
		result := buildResult(buildResultInput{
			Request:       request,
			TerminalState: terminal.ScopeDeclined,
			ReasonCode:    terminal.ReasonInvalidInput,
			Detail: fmt.Sprintf("Requested policy snapshot '%s' does not match resolved snapshot '%s'.",
				request.CurrentPolicySnapshotID, snapshot.SnapshotID),
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, "none", options.CorrelationID)
	}

	// Attempt translation (deterministic paths, then doer, then judge gates).
	outcome := translation.Translate(translation.Input{
		Pattern:                    pattern,
		TargetTechnology:           targetTechnology,
		TargetPolicyContextID:      targetPolicyContextID,
		Adapter:                    adapter,
		Snapshot:                   snapshot,
		AllowNarrowerTranslation:   request.TranslationPolicy.AllowNarrowerTranslation,
		AllowEquivalentTranslation: request.TranslationPolicy.AllowEquivalentTranslation,
	})

	if outcome.Failure != nil {
		state, code := terminal.CannotExpress, terminal.ReasonUnsupportedFeature
		if outcome.Failure.Reason == "provider-failure" {
			state, code = terminal.Malfunction, terminal.ReasonProviderFailure
		}
		result := buildResult(buildResultInput{
			Request:                   request,
			TerminalState:             state,
			ReasonCode:                code,
			Detail:                    outcome.Failure.Detail,
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, outcome.Failure.ProposalSource, options.CorrelationID)
	}

	candidate := outcome.Success.Candidate
	qualification := options.ProofLoopQualification
	if qualification != nil && !qualification.BypassCleared {
		// Loop exhaustion is not bypass clearance. The candidate is emitted,
		// but it says so about itself.
		candidate.Limitations = append(candidate.Limitations, fmt.Sprintf(
			"PoC candidate loop exhausted after %d iterations; the latest Bypass "+
				"Validation state was bypass-found. This candidate is not bypass-cleared.",
			qualification.CompletedIterations))
	}

	// Gate 3: scope-declined -- unresolved policy conflicts.
	if len(candidate.Placement.ConflictNotes) > 0 {
		result := buildResult(buildResultInput{
			Request:                   request,
			TerminalState:             terminal.ScopeDeclined,
			ReasonCode:                terminal.ReasonPolicyConflict,
			Detail:                    "Candidate conflicts with existing policy: " + strings.Join(candidate.Placement.ConflictNotes, "; "),
			PrimaryCandidate:          &candidate,
			ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
			ProofLoopQualification:    options.ProofLoopQualification,
		})
		return envelope(result, settings, outcome.Success.ProposalSource, options.CorrelationID)
	}

	result := buildResult(buildResultInput{
		Request:          request,
		TerminalState:    terminal.Translated,
		ReasonCode:       terminal.ReasonTranslated,
		Detail:           translatedDetail(qualification),
		PrimaryCandidate: &candidate,
		ProseSummary: fmt.Sprintf(
			"Translated proven pattern %s into a %s candidate (%s translation) for %s.",
			pattern.ProvenPatternID, candidate.CandidateArtifact.ArtifactType,
			candidate.ImplementsDiscriminator.Translation, targetTechnology),
		ConfiguredPoCDefaultsUsed: configuredDefaultsUsed,
		ProofLoopQualification:    qualification,
	})
	return envelope(result, settings, outcome.Success.ProposalSource, options.CorrelationID)
}

// unsupportedTargetDetail explains the decline in terms the caller can act on:
// whether the technology is a known control this build does not carry, or an
// identifier the contract does not define at all.
func unsupportedTargetDetail(targetTechnology string) string {
	supported := strings.Join(adapters.SupportedTechnologies(), ", ")
	if controlClass, known := adapters.KnownTechnologies[targetTechnology]; known {
		return fmt.Sprintf(
			"Target technology '%s' (%s control class) is a valid capability target, "+
				"but this deployment translates only to %s. Route the %s candidate to a "+
				"deployment that carries that adapter, or regenerate it for %s.",
			targetTechnology, controlClass, supported, controlClass, supported)
	}
	return fmt.Sprintf(
		"Target technology '%s' is not a recognized capability target. "+
			"This deployment translates only to %s.", targetTechnology, supported)
}

func translatedDetail(qualification *contracts.ProofLoopQualification) string {
	if qualification != nil && !qualification.BypassCleared {
		return "Translation succeeded via the PoC exhaustion route; the latest " +
			"candidate remains bypass-found and is not bypass-cleared."
	}
	return "Translation succeeded."
}

type buildResultInput struct {
	Request                   contracts.ControlTranslationRequest
	TerminalState             terminal.State
	ReasonCode                terminal.ReasonCode
	Detail                    string
	PrimaryCandidate          *contracts.PrimaryCandidate
	ProseSummary              string
	ConfiguredPoCDefaultsUsed bool
	ProofLoopQualification    *contracts.ProofLoopQualification
}

func buildResult(in buildResultInput) contracts.ControlTranslationResult {
	pattern := in.Request.ProvenPattern
	target := in.Request.TargetContext

	var snapshotID *string
	if in.Request.CurrentPolicySnapshotID != "" {
		value := in.Request.CurrentPolicySnapshotID
		snapshotID = &value
	}
	evidence := []contracts.EvidenceBinding{}
	switch {
	case in.PrimaryCandidate != nil:
		evidence = []contracts.EvidenceBinding{
			{Claim: "discriminator-preserved", EvidenceRefs: append([]string{}, pattern.ProofRecordIDs...)},
			{Claim: "target-feature-supported", EvidenceRefs: []string{target.TargetTechnology}},
		}
	}
	prose := in.ProseSummary
	if prose == "" {
		prose = in.Detail
	}
	if !terminal.ReasonValidFor(in.TerminalState, in.ReasonCode) {
		// Programmer error, caught before a result is ever emitted.
		slog.Error("invalid reason code for terminal state",
			"terminal_state", in.TerminalState, "reason_code", in.ReasonCode)
	}
	return contracts.ControlTranslationResult{
		ContractID: "control-translation@1.0",
		ResultID: fmt.Sprintf("control-translation-result:%s:%s:%s",
			pattern.VulnerabilityID, target.TargetTechnology, uuid.NewString()),
		ProducedAt: contracts.Now(),
		Subject: contracts.Subject{
			VulnerabilityID:      pattern.VulnerabilityID,
			ProvenPatternID:      pattern.ProvenPatternID,
			SelectedControlClass: pattern.SelectedControlClass,
		},
		InputBindings: contracts.InputBindings{
			TargetTechnology:          target.TargetTechnology,
			TargetPolicyContextID:     target.TargetPolicyContextID,
			ConfiguredPoCDefaultsUsed: in.ConfiguredPoCDefaultsUsed,
			CurrentPolicySnapshotID:   snapshotID,
			TranslationPolicyID:       in.Request.TranslationPolicy.TranslationPolicyID,
			ProofRecordIDs:            append([]string{}, pattern.ProofRecordIDs...),
		},
		TerminalState:          in.TerminalState,
		OutcomeReason:          contracts.OutcomeReason{Code: in.ReasonCode, Detail: in.Detail},
		ProofLoopQualification: in.ProofLoopQualification,
		PrimaryCandidate:       in.PrimaryCandidate,
		EvidenceBindings:       evidence,
		ProseSummary:           prose,
	}
}

func envelope(
	result contracts.ControlTranslationResult,
	settings config.Settings,
	proposalSource string,
	correlationID string,
) contracts.ResultEnvelope {
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	return contracts.ResultEnvelope{
		Capability:    "control-translation",
		ContractID:    "control-translation@1.0",
		RunID:         uuid.NewString(),
		ResultID:      result.ResultID,
		Status:        string(terminal.StatusFor(result.TerminalState)),
		TerminalState: result.TerminalState,
		CorrelationID: correlationID,
		ResultRef: contracts.ResultReference{
			System:   "control-translation",
			Type:     "result-api",
			ResultID: result.ResultID,
			Href:     "/v1/results/" + result.ResultID,
		},
		StructuredResult: result,
		Prose:            result.ProseSummary,
		ReferenceBundle:  jsonx.Obj{},
		Provenance:       append([]string{}, result.InputBindings.ProofRecordIDs...),
		Confidence:       jsonx.Obj{},
		Warnings:         []string{},
		Trace:            []string{"terminal_state=" + string(result.TerminalState)},
		Inference: jsonx.Obj{}.
			Set("execution_mode", executionMode(settings)).
			Set("provider", settings.ModelProvider).
			Set("model", settings.ModelName).
			Set("llm_invoked", false).
			Set("proposal_source", proposalSource).
			Set("credentials_configured", settings.CredentialsConfigured()),
	}
}

func executionMode(settings config.Settings) string {
	if settings.IsLive() {
		return "live"
	}
	return "fixture"
}

func withEffectiveTargetContext(
	request contracts.ControlTranslationRequest,
	settings config.Settings,
) (contracts.ControlTranslationRequest, bool) {
	caller := contracts.TargetContext{}
	if request.TargetContext != nil {
		caller = *request.TargetContext
	}
	configuredDefaultsUsed := caller.TargetTechnology == "" || caller.TargetPolicyContextID == ""
	effective := contracts.TargetContext{
		TargetTechnology:      caller.TargetTechnology,
		TargetPolicyContextID: caller.TargetPolicyContextID,
	}
	if effective.TargetTechnology == "" {
		effective.TargetTechnology = settings.DefaultTargetTechnology
	}
	if effective.TargetPolicyContextID == "" {
		effective.TargetPolicyContextID = settings.DefaultTargetPolicyContext
	}
	request.TargetContext = &effective
	return request, configuredDefaultsUsed
}

type insufficientContextInput struct {
	Detail                    string
	Settings                  config.Settings
	CorrelationID             string
	TargetContext             *contracts.TargetContext
	ConfiguredPoCDefaultsUsed bool
	ReferenceBundle           jsonx.Obj
}

// insufficientContextEnvelope returns a typed result when referenced inputs
// cannot be safely assembled.
func insufficientContextEnvelope(in insufficientContextInput) contracts.ResultEnvelope {
	technology := in.Settings.DefaultTargetTechnology
	policyContext := in.Settings.DefaultTargetPolicyContext
	if in.TargetContext != nil {
		if in.TargetContext.TargetTechnology != "" {
			technology = in.TargetContext.TargetTechnology
		}
		if in.TargetContext.TargetPolicyContextID != "" {
			policyContext = in.TargetContext.TargetPolicyContextID
		}
	}
	result := contracts.ControlTranslationResult{
		ContractID: "control-translation@1.0",
		ResultID:   fmt.Sprintf("control-translation-result:unknown:%s:%s", technology, uuid.NewString()),
		ProducedAt: contracts.Now(),
		Subject: contracts.Subject{
			VulnerabilityID:      "unknown",
			ProvenPatternID:      "unresolved",
			SelectedControlClass: "unknown",
		},
		InputBindings: contracts.InputBindings{
			TargetTechnology:          technology,
			TargetPolicyContextID:     policyContext,
			ConfiguredPoCDefaultsUsed: in.ConfiguredPoCDefaultsUsed,
			TranslationPolicyID:       "control-translation-policy:mvp1",
			ProofRecordIDs:            []string{},
		},
		TerminalState: terminal.InsufficientContext,
		OutcomeReason: contracts.OutcomeReason{
			Code:   terminal.ReasonInsufficientPatternContext,
			Detail: in.Detail,
		},
		EvidenceBindings: []contracts.EvidenceBinding{},
		ProseSummary:     in.Detail,
	}
	resultEnvelope := envelope(result, in.Settings, "none", in.CorrelationID)
	if in.ReferenceBundle != nil {
		resultEnvelope.ReferenceBundle = in.ReferenceBundle
	}
	return resultEnvelope
}
