// Package translation compiles a proven ModSecurity rule into an Akamai
// custom WAF rule and runs the deterministic judge gates over the result.
//
// There is no model in this service and no fallback doer: a rule the compiler
// cannot express with certainty produces `cannot-express`, never a guess.
package translation

// Proposal is compiler output. It is not trusted until it has passed the
// judge gates in engine.go.
type Proposal struct {
	// CandidateContent is the Akamai custom-rule object, serialized to a
	// string before validation.
	CandidateContent       any
	TranslationLabel       string // equivalent | narrower
	Justification          string
	TranslationAssumptions []string
	Limitations            []string
}
