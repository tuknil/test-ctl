package translation

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
)

const provenSecRule = `SecRule ARGS:Researcher "@rx (?i)(?:'\s+OR\s+'1'='1|` +
	`%27\s*(?:OR|%4f%52)\s*%271%27%3[dD]%271)" ` +
	`"id:152405,phase:2,deny,status:403,log,` +
	`msg:'JANUS candidate: block evidenced Researcher SQLi variants',` +
	`tag:'janus-candidate'"`

func testPattern(summary string) contracts.ProvenMitigationPattern {
	return contracts.ProvenMitigationPattern{
		ProvenPatternID:          "proven-pattern:test",
		VulnerabilityID:          "CVE-2026-77392",
		SelectedControlClass:     "waf",
		DiscriminatorID:          "discriminator:test",
		DiscriminatorDescription: "Blocks the proven exploitation request.",
		PatternSummary:           summary,
		ProofRecordIDs: []string{
			"mitigation-check-result:a", "bypass-validation-result:b",
		},
	}
}

func compiledJSON(t *testing.T, summary string) string {
	t.Helper()
	proposal := CompileAkamaiCustomRule(testPattern(summary))
	if proposal == nil {
		t.Fatalf("compiler declined a rule it should express: %s", summary)
	}
	encoded, err := jsonx.MarshalString(proposal.CandidateContent)
	if err != nil {
		t.Fatalf("candidate content is not serializable: %v", err)
	}
	return encoded
}

// The compiled bytes are hashed into content_hash and returned as content_ref,
// so the Go and Python compilers must agree exactly, key order included.
func TestNamedArgumentRegexMatchesPythonBytes(t *testing.T) {
	const want = `{"name":"JANUS-CVE-2026-77392-Researcher",` +
		`"description":"JANUS candidate: block evidenced Researcher SQLi variants",` +
		`"operation":"AND","conditions":[{"type":"argsPostMatch","positiveMatch":true,` +
		`"parameter":"Researcher","valueCase":false,"valueWildcard":true,` +
		`"value":["*'?*OR?*'1'='1*","*%27*OR*%271%27%3d%271*","*%27*OR*%271%27%3D%271*",` +
		`"*%27*%4f%52*%271%27%3d%271*","*%27*%4f%52*%271%27%3D%271*"]}],` +
		`"tag":["JANUS","CVE-2026-77392","modsec-derived","virtual-patch","janus-candidate"]}`

	if got := compiledJSON(t, provenSecRule); got != want {
		t.Errorf("compiled rule bytes differ from the Python service\n got: %s\nwant: %s", got, want)
	}
}

func TestAnchoredLiteralCompilesWithEncodingVariants(t *testing.T) {
	got := compiledJSON(t, `SecRule ARGS_POST:token "@rx ^drop table users$" "id:1,deny"`)

	var rule struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	condition := rule.Conditions[0]
	if condition["valueWildcard"] != false || condition["valueCase"] != true {
		t.Errorf("anchored case-sensitive literal should not use wildcards: %v", condition)
	}
	want := []any{
		"drop table users", "drop%20table%20users",
		"drop+table+users", "drop%2520table%2520users",
	}
	values, _ := condition["value"].([]any)
	if len(values) != len(want) {
		t.Fatalf("got %d values, want %d: %v", len(values), len(want), values)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Errorf("value[%d] = %v, want %v", index, values[index], want[index])
		}
	}
}

func TestUnmappableSourcesDecline(t *testing.T) {
	for _, summary := range []string{
		"Block requests whose Content-Type header contains OGNL syntax.",
		"SecRule ARGS deny SQL injection",
		`SecRule ARGS:u "@rx ^a\s{2,}b$" "id:8,deny"`,
		`SecRule ARGS:u "@rx ^a(?=.*b)c$" "id:9,deny"`,
		`SecRule ARGS:u "@rx ^(?:abc)+$" "id:10,deny"`,
		`SecRule TX:anomaly_score "@gt 5" "id:11,deny"`,
		`SecRule ARGS:u "@rx (a)\1" "id:12,deny"`,
		`SecRule ARGS:u "@validateByteRange 32-126" "id:13,deny"`,
		`SecRule ARGS:/^user_/ "@contains x" "id:14,deny"`,
	} {
		if CompileAkamaiCustomRule(testPattern(summary)) != nil {
			t.Errorf("compiler should have declined: %s", summary)
		}
	}
}

func TestChainedRulesCompileIntoOneAndOperation(t *testing.T) {
	got := compiledJSON(t,
		"SecRule REQUEST_URI \"@rx ^/api/v1/\" \"id:5,phase:1,chain,deny\"\n"+
			`SecRule ARGS:cmd "@contains ;curl " "id:5"`)

	var rule struct {
		Operation  string           `json:"operation"`
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	if rule.Operation != "AND" {
		t.Errorf("chained rules must join with AND, got %q", rule.Operation)
	}
	if len(rule.Conditions) != 2 ||
		rule.Conditions[0]["type"] != "pathMatch" ||
		rule.Conditions[1]["type"] != "argsPostMatch" {
		t.Errorf("unexpected conditions: %v", rule.Conditions)
	}
}

func TestAlternativeVariablesCompileIntoOneOrOperation(t *testing.T) {
	got := compiledJSON(t,
		`SecRule ARGS_GET|REQUEST_BODY "@contains ../../etc/passwd" "id:6,deny"`)

	var rule struct {
		Operation  string           `json:"operation"`
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	if rule.Operation != "OR" {
		t.Errorf("alternative variables must join with OR, got %q", rule.Operation)
	}
	if rule.Conditions[0]["type"] != "uriQueryMatch" || rule.Conditions[1]["type"] != "argsPostMatch" {
		t.Errorf("unexpected conditions: %v", rule.Conditions)
	}
}

func TestFidelityLabels(t *testing.T) {
	exact := CompileAkamaiCustomRule(
		testPattern(`SecRule ARGS_POST:token "@rx ^drop table users$" "id:1,deny"`))
	generalized := CompileAkamaiCustomRule(testPattern(provenSecRule))

	if exact == nil || exact.TranslationLabel != "equivalent" {
		t.Errorf("lossless mapping should be equivalent, got %v", exact)
	}
	if generalized == nil || generalized.TranslationLabel != "narrower" {
		t.Errorf("generalized mapping should be narrower, got %v", generalized)
	}
}

// Encoding ladders: defense generation enumerates recursive encodings of one
// character per group. Expanding those positionally is a cross-product that
// explodes, so the compiler aligns them and emits one value per depth.

const encodingLadderRule = `SecRule REQUEST_BODY "@rx person` +
	`(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)0` +
	`(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)` +
	`(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)` +
	`(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)` +
	`(?:=|%3D|%253D|%25253D|%2525253D|%252525253D|%25252525253D)malicious" ` +
	`"id:108001,phase:2,deny,status:403,log,msg:'JANUS candidate',tag:'janus-candidate'"`

func TestEncodingLaddersAlignByDepthInsteadOfExploding(t *testing.T) {
	got := compiledJSON(t, encodingLadderRule)

	var rule struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	values, _ := rule.Conditions[0]["value"].([]any)

	// Seven depths, not 7^5 = 16807 mixed-depth combinations.
	want := []string{
		"*person[0][]=malicious*",
		"*person%5B0%5D%5B%5D%3Dmalicious*",
		"*person%255B0%255D%255B%255D%253Dmalicious*",
		"*person%25255B0%25255D%25255B%25255D%25253Dmalicious*",
		"*person%2525255B0%2525255D%2525255B%2525255D%2525253Dmalicious*",
		"*person%252525255B0%252525255D%252525255B%252525255D%252525253Dmalicious*",
		"*person%25252525255B0%25252525255D%25252525255B%25252525255D%25252525253Dmalicious*",
	}
	if len(values) != len(want) {
		t.Fatalf("got %d values, want %d: %v", len(values), len(want), values)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Errorf("value[%d] = %v\n           want %v", index, values[index], want[index])
		}
	}
}

// Every emitted value is a depth the source rule actually matches, so the
// candidate is a subset of the source: it can never over-block.
func TestAlignedLadderValuesAreASubsetOfTheSourceRule(t *testing.T) {
	got := compiledJSON(t, encodingLadderRule)
	source := regexp.MustCompile(`person(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)0` +
		`(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)` +
		`(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)` +
		`(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)` +
		`(?:=|%3D|%253D|%25253D|%2525253D|%252525253D|%25252525253D)malicious`)

	var rule struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	for _, value := range rule.Conditions[0]["value"].([]any) {
		body := strings.Trim(value.(string), "*")
		if !source.MatchString(body) {
			t.Errorf("emitted value %q is not matched by the source rule", body)
		}
	}
}

func TestAlignedLadderIsLabelledNarrowerAndSaysWhy(t *testing.T) {
	proposal := CompileAkamaiCustomRule(testPattern(encodingLadderRule))
	if proposal == nil {
		t.Fatal("the compiler declined an aligned ladder")
	}

	if proposal.TranslationLabel != "narrower" {
		t.Errorf("label = %q, want narrower", proposal.TranslationLabel)
	}
	var explained, wronglyWidened bool
	for _, limitation := range proposal.Limitations {
		if strings.Contains(limitation, "differing depths") {
			explained = true
		}
		// Aligning ladders drops combinations; it never adds any.
		if strings.Contains(limitation, "broader set of requests") {
			wronglyWidened = true
		}
	}
	if !explained {
		t.Errorf("the narrowing must be explained: %v", proposal.Limitations)
	}
	if wronglyWidened {
		t.Errorf("ladder alignment must not be reported as widening: %v", proposal.Limitations)
	}
}

// An ordinary alternation is not a ladder and must keep expanding normally.
func TestOrdinaryAlternationIsNotTreatedAsALadder(t *testing.T) {
	got := compiledJSON(t, `SecRule ARGS:u "@rx (?:alpha|beta|gamma)" "id:1,deny"`)

	var rule struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(got), &rule); err != nil {
		t.Fatalf("compiled rule is not valid JSON: %v", err)
	}
	if values, _ := rule.Conditions[0]["value"].([]any); len(values) != 3 {
		t.Errorf("an ordinary alternation should expand to 3 values, got %v", values)
	}
}

// Ladders of different lengths have no common depth to align on, so the
// compiler declines rather than guessing which depths pair up.
func TestLaddersOfDifferingDepthsDecline(t *testing.T) {
	rule := `SecRule REQUEST_BODY "@rx a(?:\[|%5B|%255B)b(?:\]|%5D)c" "id:1,deny"`

	if CompileAkamaiCustomRule(testPattern(rule)) != nil {
		t.Error("ladders of differing depths must not be aligned")
	}
}

// The alignment does not lift the overall value cap.
func TestAlignedExpansionIsStillBounded(t *testing.T) {
	var groups strings.Builder
	for index := 0; index < 3; index++ {
		groups.WriteString(`(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)`)
	}
	alternation := `(?:` + strings.Repeat("x|", 9) + `y)`
	rule := `SecRule REQUEST_BODY "@rx ` + alternation + groups.String() + `" "id:1,deny"`

	// 10 branches x 7 depths = 70 values, past the 32-value cap.
	if CompileAkamaiCustomRule(testPattern(rule)) != nil {
		t.Error("aligned expansion must still respect the value cap")
	}
}
