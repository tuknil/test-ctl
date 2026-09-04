package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/store/storetest"
)

// The referenced route: the request names three Databricks rows, and the rule
// to compile is read from the Defense Generation row's
// primary_candidate.artifact_content.

const (
	correlationID   = "uat-CVE-2026-77392-20260903T152339Z"
	vulnerabilityID = "CVE-2026-77392"
	candidateID     = "candidate:CVE-2026-77392:waf:299b5006199761b2"
	defenseResultID = "defense-generation-result:e85fc08fd0be841b04cb101d"
	mitigationID    = "mitigation-check-result:cc36cf06d9de373492f56335"
	bypassID        = "bypass-validation-result:bvrun_93b4300a10f78749aa5212e7"
)

func reference(schema, table, key string) map[string]any {
	return map[string]any{
		"system": "databricks", "catalog": "36889_janus_dev",
		"schema": schema, "table": table, "key": key,
	}
}

func upstreamInput(capability, contractID, resultID, terminalState, schema, table string) map[string]any {
	return map[string]any{
		"capability": capability, "contract_id": contractID,
		"run_id": "run:" + resultID, "result_id": resultID,
		"terminal_state": terminalState, "status": "completed",
		"correlation_id": correlationID,
		"result_ref":     reference(schema, table, resultID),
	}
}

// orchestrationBody is the envelope shape the deployed Temporal caller sends.
func orchestrationBody(requestID string) string {
	body := map[string]any{
		"contract_id":    "control-translation@1.0",
		"request_id":     requestID,
		"correlation_id": correlationID,
		"subject": map[string]any{
			"vulnerability_id": vulnerabilityID, "candidate_id": candidateID,
		},
		"upstream_inputs": []any{
			upstreamInput("defense-generation", "defense-generation@1.0", defenseResultID,
				"candidate-produced", "defense_generation", "defense_generation_results"),
			upstreamInput("mitigation-check", "mitigation-check@1.0", mitigationID,
				"blocked", "mitigation-check", "mitigation_check"),
			upstreamInput("bypass-validation", "capability-completion@1.0", bypassID,
				"no-bypass-found", "bypass_validation", "bypass_validation_results"),
		},
		"routing_context": map[string]any{
			"route": "validated", "mitigation_check_terminal_state": "blocked",
			"mitigation_check_match":           true,
			"bypass_validation_terminal_state": "no-bypass-found",
			"loop_exhausted":                   false,
			"completed_iterations":             2, "max_iterations": 10,
		},
		"provenance": map[string]any{"caller": "janus-orchestration", "source": "temporal"},
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

// seedProofLoop registers the three rows the resolver will read. The column
// order matches each role's SELECT.
func seedProofLoop(fake *storetest.FakeWorkspace, artifactContent string) {
	seedProofLoopForTarget(fake, artifactContent, "waf", "akamai-waf")
}

// seedProofLoopForTarget seeds a proof loop whose Defense Generation row names
// a specific control class and target technology.
func seedProofLoopForTarget(
	fake *storetest.FakeWorkspace, artifactContent, controlClass, targetTechnology string,
) {
	defenseRequest, _ := json.Marshal(map[string]any{
		"vulnerability_id": vulnerabilityID, "selected_control_class": controlClass,
		"correlation_id": correlationID,
	})
	defenseResult, _ := json.Marshal(map[string]any{
		"correlation_id":    correlationID,
		"target_technology": targetTechnology,
		"primary_candidate": map[string]any{
			"vulnerability_id": vulnerabilityID, "candidate_id": candidateID,
			"selected_control_class": controlClass,
			"discriminator": "Submit the Researcher parameter with SQL injection " +
				"syntax and observe the authentication bypass.",
			"artifact_content": artifactContent,
		},
	})
	fake.UpstreamRow(defenseResultID,
		defenseResultID, "candidate-produced", string(defenseRequest), string(defenseResult))

	mitigationResult, _ := json.Marshal(map[string]any{
		"correlation_id": correlationID, "terminal_state": "blocked",
		"vulnerability_id": vulnerabilityID, "candidate_id": candidateID,
	})
	fake.UpstreamRow(mitigationID, mitigationID, string(mitigationResult))

	bypassResult, _ := json.Marshal(map[string]any{
		"correlation_id": correlationID, "terminal_state": "no-bypass-found",
		"subject": map[string]any{
			"vulnerability_id": vulnerabilityID, "source_candidate_id": candidateID,
		},
	})
	fake.UpstreamRow(bypassID, bypassID, "no-bypass-found", correlationID, "{}", string(bypassResult))
}

func TestReferencedRequestCompilesTheRuleFromTheDefenseGenerationRow(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoop(fake, provenSecRule)

	recorder := post(t, handler, "/invoke", orchestrationBody("req-referenced-1"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("invoke = %d: %s", recorder.Code, recorder.Body.String())
	}
	payload := decode(t, recorder)
	if payload["terminal_state"] != "translated" {
		t.Fatalf("terminal_state = %v: %s", payload["terminal_state"], recorder.Body.String())
	}
	structured := payload["structured_result"].(map[string]any)

	// The pattern was assembled from the fetched rows, not from the request.
	subject := structured["subject"].(map[string]any)
	if subject["vulnerability_id"] != vulnerabilityID ||
		subject["proven_pattern_id"] != "proven-pattern:"+candidateID {
		t.Errorf("subject was not derived from the upstream rows: %v", subject)
	}

	// The compiled rule is the one carried by artifact_content.
	candidate := structured["primary_candidate"].(map[string]any)
	var rule map[string]any
	if err := json.Unmarshal(
		[]byte(candidate["candidate_artifact"].(map[string]any)["content_ref"].(string)), &rule); err != nil {
		t.Fatalf("candidate content is not JSON: %v", err)
	}
	if rule["name"] != "JANUS-CVE-2026-77392-Researcher" {
		t.Errorf("the compiled rule does not come from the Defense Generation artifact: %v", rule["name"])
	}

	// The proof records are the mitigation and bypass rows that were read.
	bindings := structured["input_bindings"].(map[string]any)["proof_record_ids"].([]any)
	if len(bindings) != 2 || bindings[0] != mitigationID || bindings[1] != bypassID {
		t.Errorf("unexpected proof records: %v", bindings)
	}

	// The response echoes exactly which rows were read.
	bundle := payload["reference_bundle"].(map[string]any)
	defense := bundle["defense_generation"].(map[string]any)
	if defense["table"] != "defense_generation_results" || defense["key"] != defenseResultID {
		t.Errorf("unexpected reference bundle: %v", bundle)
	}
	qualification := structured["proof_loop_qualification"].(map[string]any)
	if qualification["route"] != "validated" || qualification["bypass_cleared"] != true {
		t.Errorf("unexpected qualification: %v", qualification)
	}
}

// A rule the compiler cannot express is still a typed decline on this route.
func TestReferencedRequestDeclinesAnUnmappableRule(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoop(fake, `SecRule ARGS:u "@rx ^a\s{2,}b$" "id:8,deny"`)

	payload := decode(t, post(t, handler, "/invoke", orchestrationBody("req-referenced-2")))

	if payload["terminal_state"] != "cannot-express" {
		t.Errorf("terminal_state = %v, want cannot-express", payload["terminal_state"])
	}
}

// Lineage is the point of the read. Every one of these makes the service
// refuse to compile a rule rather than compile the wrong one.
func TestReferencedRequestRefusesBrokenLineage(t *testing.T) {
	cases := map[string]func(fake *storetest.FakeWorkspace){
		"missing defense row": func(fake *storetest.FakeWorkspace) {
			fake.DropUpstreamRow(defenseResultID)
		},
		"wrong terminal state": func(fake *storetest.FakeWorkspace) {
			fake.UpstreamRow(defenseResultID, defenseResultID, "candidate-rejected", "{}", "{}")
		},
		"result id does not match the reference": func(fake *storetest.FakeWorkspace) {
			fake.UpstreamRow(defenseResultID, "defense-generation-result:someone-else",
				"candidate-produced", "{}", "{}")
		},
		"correlation belongs to another run": func(fake *storetest.FakeWorkspace) {
			result, _ := json.Marshal(map[string]any{
				"correlation_id": "a-different-correlation",
				"primary_candidate": map[string]any{
					"vulnerability_id": vulnerabilityID, "candidate_id": candidateID,
					"selected_control_class": "waf", "discriminator": "d",
					"artifact_content": provenSecRule,
				},
			})
			fake.UpstreamRow(defenseResultID,
				defenseResultID, "candidate-produced", "{}", string(result))
		},
		"candidate belongs to another subject": func(fake *storetest.FakeWorkspace) {
			result, _ := json.Marshal(map[string]any{
				"correlation_id": correlationID,
				"primary_candidate": map[string]any{
					"vulnerability_id":       vulnerabilityID,
					"candidate_id":           "candidate:CVE-2026-77392:waf:a-different-candidate",
					"selected_control_class": "waf", "discriminator": "d",
					"artifact_content": provenSecRule,
				},
			})
			fake.UpstreamRow(defenseResultID,
				defenseResultID, "candidate-produced", "{}", string(result))
		},
		"artifact content is missing": func(fake *storetest.FakeWorkspace) {
			result, _ := json.Marshal(map[string]any{
				"correlation_id": correlationID,
				"primary_candidate": map[string]any{
					"vulnerability_id": vulnerabilityID, "candidate_id": candidateID,
					"selected_control_class": "waf", "discriminator": "d",
				},
			})
			fake.UpstreamRow(defenseResultID,
				defenseResultID, "candidate-produced", "{}", string(result))
		},
	}

	index := 0
	for name, breakIt := range cases {
		index++
		t.Run(name, func(t *testing.T) {
			handler, fake := newTestServer(t)
			seedProofLoop(fake, provenSecRule)
			breakIt(fake)

			payload := decode(t, post(t, handler, "/invoke",
				orchestrationBody(fmt.Sprintf("req-lineage-%d", index))))

			if payload["terminal_state"] != "insufficient-context" {
				t.Fatalf("terminal_state = %v, want insufficient-context", payload["terminal_state"])
			}
			if payload["structured_result"].(map[string]any)["primary_candidate"] != nil {
				t.Error("broken lineage must never produce a candidate")
			}
		})
	}
}

// The approved-table check: a reference pointing somewhere else is refused
// before any row is read.
func TestReferencedRequestRefusesAnUnapprovedTable(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoop(fake, provenSecRule)
	body := strings.Replace(orchestrationBody("req-table-1"),
		`"table":"defense_generation_results"`, `"table":"some_other_table"`, 1)

	payload := decode(t, post(t, handler, "/invoke", body))

	if payload["terminal_state"] != "insufficient-context" {
		t.Errorf("an unapproved table must be refused: %v", payload["terminal_state"])
	}
}

// Without a configured reader the request is a typed decline, not an attempt
// to proceed without the authoritative rule.
func TestReferencedRequestWithoutAResolverDeclines(t *testing.T) {
	handler := newServerWithoutResolver(t)

	payload := decode(t, post(t, handler, "/invoke", orchestrationBody("req-noresolver-1")))

	if payload["terminal_state"] != "insufficient-context" {
		t.Fatalf("terminal_state = %v", payload["terminal_state"])
	}
	if len(payload["reference_bundle"].(map[string]any)) != 3 {
		t.Errorf("the reference bundle should still be reported: %v", payload["reference_bundle"])
	}
}

func TestOrchestrationEnvelopeRequiresItsFullFieldGroup(t *testing.T) {
	handler, _ := newTestServer(t)
	// contract_id present but subject and provenance missing.
	body := `{"contract_id":"control-translation@1.0","request_id":"x","correlation_id":"y","input":{}}`

	if code := post(t, handler, "/invoke", body).Code; code != http.StatusUnprocessableEntity {
		t.Errorf("a partial orchestration envelope = %d, want 422", code)
	}
}

// The PoC exhaustion route: the candidate is still translated, but it must
// carry the fact that it was never bypass-cleared, plus the evidence.
func TestLoopExhaustedRouteMarksTheCandidateNotBypassCleared(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoop(fake, provenSecRule)

	bypassResult, _ := json.Marshal(map[string]any{
		"correlation_id": correlationID, "terminal_state": "bypass-found",
		"subject": map[string]any{
			"vulnerability_id": vulnerabilityID, "source_candidate_id": candidateID,
		},
		"bypass_counterexample": map[string]any{
			"counterexample_id": "bypass:example:encoding",
			"sample_ref":        "evidence://bypass/example/sample",
			"variant_family":    "encoding",
			"observed_behavior": "reached-protected-target",
			"evidence_refs":     []string{"evidence://target/example"},
		},
	})
	fake.UpstreamRow(bypassID, bypassID, "bypass-found", correlationID, "{}", string(bypassResult))

	body := orchestrationBody("req-exhausted-1")
	body = strings.ReplaceAll(body, `"no-bypass-found"`, `"bypass-found"`)
	body = strings.Replace(body, `"route":"validated"`, `"route":"loop-exhausted"`, 1)
	body = strings.Replace(body, `"loop_exhausted":false`, `"loop_exhausted":true`, 1)
	body = strings.Replace(body, `"completed_iterations":2`, `"completed_iterations":10`, 1)

	payload := decode(t, post(t, handler, "/invoke", body))

	if payload["terminal_state"] != "translated" {
		t.Fatalf("terminal_state = %v: %s", payload["terminal_state"], payload)
	}
	structured := payload["structured_result"].(map[string]any)
	qualification := structured["proof_loop_qualification"].(map[string]any)
	if qualification["route"] != "poc-exhaustion" || qualification["bypass_cleared"] != false {
		t.Errorf("unexpected qualification: %v", qualification)
	}
	candidate := structured["primary_candidate"].(map[string]any)
	cleared := false
	for _, limitation := range candidate["limitations"].([]any) {
		if strings.Contains(limitation.(string), "not bypass-cleared") {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("an exhausted candidate must say it is not bypass-cleared: %v", candidate["limitations"])
	}
	if structured["bypass_counterexample"] == nil {
		t.Error("the bypass evidence must be preserved for operator review")
	}
}
