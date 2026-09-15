// Package adapters holds the target-technology integration.
//
// This build carries one adapter: Akamai. Adding a real integration (real
// Akamai EdgeGrid API access, or another target technology) means adding an
// adapter here; the capability core does not change.
package adapters

// SyntaxValidation is the mechanical judge verdict for a proposed artifact.
type SyntaxValidation struct {
	Valid  bool
	Errors []string
}

// PolicySnapshot is a read of current live policy for a target technology.
type PolicySnapshot struct {
	SnapshotID            string   `json:"snapshot_id"`
	TargetTechnology      string   `json:"target_technology"`
	TargetPolicyContextID string   `json:"target_policy_context_id"`
	ExistingRuleIDs       []string `json:"existing_rule_ids"`
	ExistingRuleSummaries []string `json:"existing_rule_summaries"`
	IsFixture             bool     `json:"is_fixture"`
}

// Adapter is what the capability needs from a target control technology.
type Adapter interface {
	// TargetTechnology is the registry key, e.g. "akamai-waf".
	TargetTechnology() string
	// ArtifactType names the produced artifact, e.g. "akamai-waf-rule".
	ArtifactType() string
	// ValidateSyntax is the deterministic shape check: the judge gate.
	ValidateSyntax(candidateContent string) SyntaxValidation
	// DetectConflicts returns conflict notes, empty when none were detected.
	DetectConflicts(candidateContent string, snapshot *PolicySnapshot) []string
}

var registry = map[string]Adapter{"akamai-waf": AkamaiWAF{}}

// Get returns the adapter for a target technology, or nil when unsupported.
func Get(targetTechnology string) Adapter {
	adapter, ok := registry[targetTechnology]
	if !ok {
		return nil
	}
	return adapter
}

// Registry exposes the adapters for the /schema endpoint.
func Registry() []Adapter { return []Adapter{registry["akamai-waf"]} }

// SupportedTechnologies lists what this build can translate to, for the
// decline emitted when a request names something else.
func SupportedTechnologies() []string {
	names := make([]string, 0, len(registry))
	for _, adapter := range Registry() {
		names = append(names, adapter.TargetTechnology())
	}
	return names
}

// KnownTechnologies are the target technologies the capability contract
// defines. A request naming one of these is a control this deployment simply
// does not carry; anything else is very likely a typo or a bad binding, and
// the decline says which.
var KnownTechnologies = map[string]string{
	"akamai-waf":       "waf",
	"firewall-generic": "firewall",
	"edr-s1":           "edr",
}

// TargetControlClasses binds each target technology to its control class.
var TargetControlClasses = map[string]string{"akamai-waf": "waf"}
