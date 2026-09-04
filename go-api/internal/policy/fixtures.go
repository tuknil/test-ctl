// Package policy reads the current live policy for a target technology.
//
// No real Akamai API client exists yet; only the deterministic fixture reader
// is provided. A real reader is future work: until it exists, the conflict
// gate compares candidates against bundled snapshots, not live policy.
package policy

import "github.com/ATT-CSO/control-translation/go-api/internal/adapters"

// Reader is what the capability needs from the world to read current policy.
type Reader interface {
	// ReadSnapshot returns the current snapshot, or nil when unavailable.
	ReadSnapshot(targetTechnology, targetPolicyContextID string) *adapters.PolicySnapshot
}

type key struct{ technology, context string }

var fixtureSnapshots = map[key]adapters.PolicySnapshot{
	{"akamai-waf", "akamai-policy:example:rev-17"}: {
		SnapshotID:            "policy-snapshot:akamai:example:rev-17",
		TargetTechnology:      "akamai-waf",
		TargetPolicyContextID: "akamai-policy:example:rev-17",
		ExistingRuleIDs:       []string{"rule-1001", "rule-1002"},
		ExistingRuleSummaries: []string{
			"rule-1001: block known SQLi patterns in query string",
			"rule-1002: rate-limit login endpoint",
		},
		IsFixture: true,
	},
}

// FixtureReader is the deterministic offline Reader implementation.
type FixtureReader struct{}

// ReadSnapshot implements Reader.
func (FixtureReader) ReadSnapshot(targetTechnology, targetPolicyContextID string) *adapters.PolicySnapshot {
	snapshot, ok := fixtureSnapshots[key{targetTechnology, targetPolicyContextID}]
	if !ok {
		return nil
	}
	return &snapshot
}
