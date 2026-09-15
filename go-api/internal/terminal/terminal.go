// Package terminal defines the terminal states, reason codes, and routing
// precedence for one control-translation invocation.
//
// Ported from src/control_translation/terminal.py. Precedence matters: when
// more than one condition applies, the earliest-listed state wins.
package terminal

// State is a terminal state the capability may emit for one invocation.
type State string

const (
	Translated          State = "translated"
	CannotExpress       State = "cannot-express"
	InsufficientContext State = "insufficient-context"
	ScopeDeclined       State = "scope-declined"
	Malfunction         State = "malfunction"
)

// ReasonCode is bound to a terminal state, per CFS §2 outcome_reason.code.
type ReasonCode string

const (
	ReasonTranslated                  ReasonCode = "translated"
	ReasonUnsupportedTargetTechnology ReasonCode = "unsupported-target-technology"
	ReasonUnsupportedFeature          ReasonCode = "unsupported-feature"
	ReasonPolicyConflict              ReasonCode = "policy-conflict"
	ReasonInsufficientPolicyContext   ReasonCode = "insufficient-policy-context"
	ReasonInsufficientPatternContext  ReasonCode = "insufficient-pattern-context"
	ReasonInvalidInput                ReasonCode = "invalid-input"
	ReasonLoopExhaustedWithBypass     ReasonCode = "loop-exhausted-with-bypass"
	ReasonBypassFoundRequiresRegen    ReasonCode = "bypass-found-requires-regeneration"
	ReasonProviderFailure             ReasonCode = "provider-failure"
	ReasonResultAssemblyFailure       ReasonCode = "result-assembly-failure"
)

// Status is the envelope-level status per the invocation-surface convention.
type Status string

const (
	StatusSucceeded   Status = "succeeded"
	StatusDeclined    Status = "declined"
	StatusMalfunction Status = "malfunction"
)

// AllStates lists the terminal states in precedence order, most authoritative
// first. capability evaluates gates in this order and stops at the first fire.
var AllStates = []State{ScopeDeclined, InsufficientContext, CannotExpress, Malfunction, Translated}

// DeclaredStates is the /schema listing order, matching the Python enum's
// declaration order rather than the precedence order.
var DeclaredStates = []State{Translated, CannotExpress, InsufficientContext, ScopeDeclined, Malfunction}

// ValidReasonCodes catches programmer error before a result is emitted.
var ValidReasonCodes = map[State][]ReasonCode{
	Translated:          {ReasonTranslated},
	CannotExpress:       {ReasonUnsupportedTargetTechnology, ReasonUnsupportedFeature},
	InsufficientContext: {ReasonInsufficientPolicyContext, ReasonInsufficientPatternContext},
	ScopeDeclined: {
		ReasonInvalidInput,
		ReasonPolicyConflict,
		ReasonLoopExhaustedWithBypass,
		ReasonBypassFoundRequiresRegen,
	},
	Malfunction: {ReasonProviderFailure, ReasonResultAssemblyFailure},
}

// StatusFor maps a terminal state onto the envelope status.
func StatusFor(state State) Status {
	switch state {
	case Translated:
		return StatusSucceeded
	case Malfunction:
		return StatusMalfunction
	default:
		return StatusDeclined
	}
}

// ReasonValidFor reports whether a reason code may accompany a terminal state.
func ReasonValidFor(state State, code ReasonCode) bool {
	for _, valid := range ValidReasonCodes[state] {
		if valid == code {
			return true
		}
	}
	return false
}
