package translation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ATT-CSO/control-translation/go-api/internal/adapters"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
)

// Failure is a structured reason the capability core routes to
// cannot-express or malfunction.
type Failure struct {
	Reason         string // "unsupported-feature" | "provider-failure"
	Detail         string
	ProposalSource string
}

// Success carries a validated candidate ready for a translated verdict.
type Success struct {
	Candidate      contracts.PrimaryCandidate
	ProposalSource string
}

// Result is either a Failure or a Success; exactly one is non-nil.
type Result struct {
	Failure *Failure
	Success *Success
}

// Input carries everything Translate needs for one attempt.
type Input struct {
	Pattern                    contracts.ProvenMitigationPattern
	TargetTechnology           string
	TargetPolicyContextID      string
	Adapter                    adapters.Adapter
	Snapshot                   *adapters.PolicySnapshot
	AllowNarrowerTranslation   bool
	AllowEquivalentTranslation bool
}

// Translate compiles the proven ModSecurity rule and runs the judge gates.
//
// There is exactly one execution path. A rule the compiler cannot express
// produces cannot-express rather than a guess or a model call.
func Translate(in Input) Result {
	proposal := CompileAkamaiCustomRule(in.Pattern)
	if proposal == nil {
		return failure("unsupported-feature", fmt.Sprintf(
			"The proven ModSecurity rule for %s uses a construct with no certain "+
				"Akamai equivalent, so it cannot be compiled deterministically.",
			in.Pattern.VulnerabilityID))
	}
	if fail := proposalPolicyFailure(*proposal, in.AllowNarrowerTranslation, in.AllowEquivalentTranslation); fail != nil {
		return Result{Failure: fail}
	}

	candidateContent, err := normalizeCandidateContent(proposal.CandidateContent)
	if err != nil {
		return failure("provider-failure", err.Error())
	}

	// Judge gate 1: syntax validation (mechanical). The compiler builds the
	// rule, but the adapter decides whether the shape is acceptable.
	if syntax := in.Adapter.ValidateSyntax(candidateContent); !syntax.Valid {
		detail := strings.Join(syntax.Errors, "; ")
		if detail == "" {
			detail = "Candidate failed syntax validation."
		}
		return failure("unsupported-feature", detail)
	}

	// Judge gate 2: conflict/placement detection (mechanical).
	conflicts := in.Adapter.DetectConflicts(candidateContent, in.Snapshot)
	if conflicts == nil {
		conflicts = []string{}
	}

	digest := sha256.Sum256([]byte(candidateContent))
	contentHash := "sha256:" + hex.EncodeToString(digest[:])

	candidate := contracts.PrimaryCandidate{
		CandidateID: fmt.Sprintf("control-candidate:%s:%s:%s",
			in.Pattern.VulnerabilityID, in.TargetTechnology,
			strings.TrimPrefix(contentHash, "sha256:")[:16]),
		TargetControlClass:    in.Pattern.SelectedControlClass,
		TargetTechnology:      in.TargetTechnology,
		TargetPolicyContextID: in.TargetPolicyContextID,
		CandidateArtifact: contracts.CandidateArtifact{
			ArtifactType: in.Adapter.ArtifactType(),
			ContentRef:   candidateContent,
			ContentHash:  contentHash,
			EmittedAs:    "control-specific-mitigation-candidate",
		},
		ImplementsDiscriminator: contracts.ImplementsDiscriminator{
			SourceDiscriminatorID: in.Pattern.DiscriminatorID,
			Translation:           proposal.TranslationLabel,
			Justification:         proposal.Justification,
			EvidenceRefs:          copyStrings(in.Pattern.ProofRecordIDs),
		},
		Placement: contracts.Placement{
			OrderingConstraints: []string{},
			ConflictNotes:       conflicts,
		},
		InheritedCollateralImpactPrior: contracts.CollateralImpactPrior{
			Verdict:    "unknown",
			Confidence: "unknown",
			Basis:      "Not measured by control-translation; inherited placeholder.",
			Measured:   false,
		},
		TranslationAssumptions: copyStrings(proposal.TranslationAssumptions),
		Limitations:            copyStrings(proposal.Limitations),
		Provenance:             copyStrings(in.Pattern.ProofRecordIDs),
		CandidateMetadata:      contracts.AkamaiCandidateMetadata(),
	}
	return Result{Success: &Success{
		Candidate:      candidate,
		ProposalSource: "deterministic-modsec-rule",
	}}
}

func failure(reason, detail string) Result {
	return Result{Failure: &Failure{
		Reason: reason, Detail: detail, ProposalSource: "deterministic-modsec-rule",
	}}
}

func copyStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return append([]string{}, items...)
}

func normalizeCandidateContent(content any) (string, error) {
	if text, ok := content.(string); ok {
		return text, nil
	}
	encoded, err := jsonx.MarshalString(content)
	if err != nil {
		return "", fmt.Errorf("the compiled candidate is not serializable")
	}
	return encoded, nil
}

func proposalPolicyFailure(proposal Proposal, allowNarrower, allowEquivalent bool) *Failure {
	switch proposal.TranslationLabel {
	case "exact", "equivalent", "narrower":
	default:
		return &Failure{
			Reason:         "provider-failure",
			Detail:         fmt.Sprintf("Invalid translation_label: '%s'", proposal.TranslationLabel),
			ProposalSource: "deterministic-modsec-rule",
		}
	}
	if proposal.TranslationLabel == "equivalent" && !allowEquivalent {
		return &Failure{
			Reason:         "unsupported-feature",
			Detail:         "Translation policy does not allow equivalent translations.",
			ProposalSource: "deterministic-modsec-rule",
		}
	}
	if proposal.TranslationLabel == "narrower" && !allowNarrower {
		return &Failure{
			Reason:         "unsupported-feature",
			Detail:         "Translation policy does not allow narrower translations.",
			ProposalSource: "deterministic-modsec-rule",
		}
	}
	return nil
}
