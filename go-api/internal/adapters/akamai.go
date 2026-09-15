package adapters

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Documented Akamai custom-rule condition `type` values (the subset used here),
// sourced from docs/syntexresearch.md.
var validConditionTypes = map[string]bool{
	"requestHeaderMatch":      true,
	"requestHeaderValueMatch": true,
	"argsPostMatch":           true,
	"argsPostJSONMatch":       true,
	"argsPostXMLMatch":        true,
	"pathMatch":               true,
	"uriQueryMatch":           true,
	"ipMatch":                 true,
	"requestMethodMatch":      true,
	"cookieMatch":             true,
}

// Keys that indicate an action was (incorrectly) embedded in the rule body.
var forbiddenActionKeys = []string{"action", "alert", "deny"}

var syntheticRequestHeaders = map[string]bool{
	"request-uri":  true,
	"request_uri":  true,
	"request-body": true,
	"request_body": true,
}

const headerValueCondition = "requestHeaderValueMatch"

// AkamaiWAF validates the shape of an Akamai Application Security custom rule
// (App & API Protector / Kona Site Defender). It is NOT verified against a
// real tenant; live EdgeGrid API access is an open integration.
//
// The rule action (alert/deny/none) is assigned separately when the rule is
// attached to a security policy, so a valid rule body must not embed one.
type AkamaiWAF struct{}

// TargetTechnology implements Adapter.
func (AkamaiWAF) TargetTechnology() string { return "akamai-waf" }

// ArtifactType implements Adapter.
func (AkamaiWAF) ArtifactType() string { return "akamai-waf-rule" }

// ValidateSyntax implements Adapter.
func (a AkamaiWAF) ValidateSyntax(candidateContent string) SyntaxValidation {
	var rule map[string]json.RawMessage
	if err := json.Unmarshal([]byte(candidateContent), &rule); err != nil {
		var any any
		if json.Unmarshal([]byte(candidateContent), &any) == nil {
			return SyntaxValidation{Errors: []string{"Akamai custom rule must be a JSON object."}}
		}
		return SyntaxValidation{Errors: []string{fmt.Sprintf("Candidate is not valid JSON: %s", err)}}
	}

	var errs []string
	var forbidden []string
	for _, key := range forbiddenActionKeys {
		if _, present := rule[key]; present {
			forbidden = append(forbidden, key)
		}
	}
	if len(forbidden) > 0 {
		sort.Strings(forbidden)
		errs = append(errs, "Custom rule body must not embed an action ("+
			strings.Join(forbidden, ", ")+"); the action is assigned separately on the security policy.")
	}

	var operation string
	_ = json.Unmarshal(rule["operation"], &operation)
	if operation != "AND" && operation != "OR" {
		errs = append(errs, "Field 'operation' must be 'AND' or 'OR'.")
	}

	var conditions []map[string]any
	if err := json.Unmarshal(rule["conditions"], &conditions); err != nil || len(conditions) == 0 {
		errs = append(errs, "Field 'conditions' must be a non-empty array.")
	} else {
		for index, condition := range conditions {
			errs = append(errs, conditionErrors(index, condition)...)
		}
	}
	if len(errs) > 0 {
		return SyntaxValidation{Errors: errs}
	}
	return SyntaxValidation{Valid: true}
}

func conditionErrors(index int, condition map[string]any) []string {
	prefix := fmt.Sprintf("conditions[%d]", index)
	var errs []string

	conditionType, _ := condition["type"].(string)
	if !validConditionTypes[conditionType] {
		errs = append(errs, fmt.Sprintf("%s.type %s is not a recognized Akamai condition type.",
			prefix, quotePython(condition["type"])))
	}
	if _, ok := condition["positiveMatch"].(bool); !ok {
		errs = append(errs, prefix+".positiveMatch must be a boolean.")
	}
	if !validConditionValue(condition["value"]) {
		errs = append(errs, prefix+".value must be a non-empty array or a string.")
	}
	if conditionType == "argsPostJSONMatch" {
		parameter, ok := condition["parameter"].(string)
		if !ok || strings.TrimSpace(parameter) == "" {
			errs = append(errs, prefix+".parameter must identify the JSON field for argsPostJSONMatch.")
		}
	}
	header, hasHeader := condition["header"]
	if conditionType == headerValueCondition {
		name, ok := header.(string)
		switch {
		case !ok || strings.TrimSpace(name) == "":
			errs = append(errs, prefix+".header must name a real request header for requestHeaderValueMatch.")
		case syntheticRequestHeaders[strings.ToLower(strings.TrimSpace(name))]:
			errs = append(errs, fmt.Sprintf(
				"%s.header %s is synthetic; use pathMatch for URI paths or an argsPost condition for request bodies.",
				prefix, quotePython(header)))
		}
	} else if hasHeader {
		errs = append(errs, prefix+".header is valid only for requestHeaderValueMatch.")
	}
	return errs
}

func validConditionValue(value any) bool {
	switch typed := value.(type) {
	case string:
		return typed != ""
	case []any:
		if len(typed) == 0 {
			return false
		}
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || text == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// DetectConflicts implements Adapter.
func (AkamaiWAF) DetectConflicts(candidateContent string, snapshot *PolicySnapshot) []string {
	if snapshot == nil {
		return nil
	}
	var rule struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if json.Unmarshal([]byte(candidateContent), &rule) != nil {
		return nil
	}
	types := map[string]bool{}
	for _, condition := range rule.Conditions {
		if conditionType, ok := condition["type"].(string); ok {
			types[conditionType] = true
		}
	}
	var conflicts []string
	for _, summary := range snapshot.ExistingRuleSummaries {
		lowered := strings.ToLower(summary)
		// Precedence mirrors Python's `and`/`or` binding exactly.
		if (strings.Contains(lowered, "content-type") && types[headerValueCondition]) ||
			(strings.Contains(lowered, "query string") && types["uriQueryMatch"]) {
			conflicts = append(conflicts, "Existing rule may overlap: "+summary)
		}
	}
	return conflicts
}

// quotePython renders a value the way Python's %r renders it, so validation
// messages match the Python service's byte for byte.
func quotePython(value any) string {
	switch typed := value.(type) {
	case nil:
		return "None"
	case string:
		if strings.Contains(typed, "'") && !strings.Contains(typed, `"`) {
			return `"` + typed + `"`
		}
		return "'" + strings.ReplaceAll(typed, `'`, `\'`) + "'"
	case bool:
		if typed {
			return "True"
		}
		return "False"
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(encoded)
	}
}
