package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// This build translates only to Akamai. A firewall or EDR candidate is a
// control it does not carry -- not a malformed request -- so it must decline
// in a way orchestration can route on, and it must do so through every entry
// point without losing the subject or the durable record.

func targetBody(targetTechnology, controlClass, policyContext string) string {
	body := requestBody(provenSecRule)
	body = strings.Replace(body, `"selected_control_class":"waf"`,
		`"selected_control_class":"`+controlClass+`"`, 1)
	body = strings.Replace(body, `"target_technology":"akamai-waf"`,
		`"target_technology":"`+targetTechnology+`"`, 1)
	return strings.Replace(body, `"target_policy_context_id":"akamai-policy:example:rev-17"`,
		`"target_policy_context_id":"`+policyContext+`"`, 1)
}

func TestFirewallAndEdrCandidatesDeclineAsUnsupportedTargets(t *testing.T) {
	cases := map[string]struct{ technology, controlClass string }{
		"firewall": {"firewall-generic", "firewall"},
		"edr":      {"edr-s1", "edr"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			handler, fake := newTestServer(t)

			recorder := post(t, handler, "/invoke",
				targetBody(testCase.technology, testCase.controlClass, "policy:example"))

			// A decline is a result, not an error: the caller gets 200 and a
			// typed body it can route on.
			if recorder.Code != http.StatusOK {
				t.Fatalf("invoke = %d, want 200: %s", recorder.Code, recorder.Body.String())
			}
			payload := decode(t, recorder)
			if payload["terminal_state"] != "cannot-express" || payload["status"] != "declined" {
				t.Fatalf("terminal_state = %v / status = %v",
					payload["terminal_state"], payload["status"])
			}
			structured := payload["structured_result"].(map[string]any)
			reason := structured["outcome_reason"].(map[string]any)

			// The contract has a purpose-built code for exactly this. Using
			// invalid-input instead would tell the caller to fix the request.
			if reason["code"] != "unsupported-target-technology" {
				t.Errorf("reason code = %v, want unsupported-target-technology", reason["code"])
			}
			detail := reason["detail"].(string)
			for _, want := range []string{testCase.technology, testCase.controlClass, "akamai-waf"} {
				if !strings.Contains(detail, want) {
					t.Errorf("the detail should name %q so the caller can act on it: %s", want, detail)
				}
			}
			if structured["primary_candidate"] != nil {
				t.Error("a declined translation must not produce a candidate")
			}

			// The subject survives, so the decline is attributable.
			subject := structured["subject"].(map[string]any)
			if subject["vulnerability_id"] != "CVE-2026-77392" {
				t.Errorf("the subject was lost: %v", subject)
			}
			if structured["input_bindings"].(map[string]any)["target_technology"] != testCase.technology {
				t.Errorf("the requested target was lost: %v", structured["input_bindings"])
			}

			// A decline is still a durable, auditable run.
			if len(fake.Rows()) != 1 {
				t.Fatalf("the decline should be persisted, got %d rows", len(fake.Rows()))
			}
			run := decode(t, get(t, handler, "/runs/"+payload["run_id"].(string)))
			if run["terminal_state"] != "cannot-express" {
				t.Errorf("the durable run does not match: %v", run["terminal_state"])
			}
		})
	}
}

// An identifier the contract does not define at all gets a different message,
// because that is a typo or a bad binding rather than a missing adapter.
func TestUnrecognizedTargetIsDistinguishedFromAMissingAdapter(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, post(t, handler, "/invoke",
		targetBody("palo-alto-panorama", "firewall", "policy:example")))

	reason := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)
	if reason["code"] != "unsupported-target-technology" {
		t.Fatalf("reason code = %v", reason["code"])
	}
	if !strings.Contains(reason["detail"].(string), "not a recognized capability target") {
		t.Errorf("an unknown identifier should say so: %s", reason["detail"])
	}
}

// The target is checked before the policy snapshot, so an unsupported target
// declines for the right reason rather than for a missing fixture snapshot.
func TestUnsupportedTargetIsReportedBeforeMissingPolicyContext(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, post(t, handler, "/invoke",
		targetBody("firewall-generic", "firewall", "does-not-exist")))

	reason := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)
	if reason["code"] != "unsupported-target-technology" {
		t.Errorf("reason code = %v, want unsupported-target-technology", reason["code"])
	}
}

// A control class that does not match its target is a genuinely invalid
// pairing, and stays scope-declined/invalid-input.
func TestMismatchedControlClassRemainsInvalidInput(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, post(t, handler, "/invoke",
		targetBody("akamai-waf", "firewall", "akamai-policy:example:rev-17")))

	if payload["terminal_state"] != "scope-declined" {
		t.Fatalf("terminal_state = %v, want scope-declined", payload["terminal_state"])
	}
	reason := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)
	if reason["code"] != "invalid-input" {
		t.Errorf("reason code = %v, want invalid-input", reason["code"])
	}
}

// A queued run for an unsupported target completes with its decline. It must
// not fail, retry, or leave the run stuck: nothing about it is transient.
func TestAsyncRunForAnUnsupportedTargetCompletesWithItsDecline(t *testing.T) {
	handler, _ := newTestServer(t)
	body := strings.Replace(targetBody("edr-s1", "edr", "policy:example"), `{"input"`,
		`{"request_id":"run-edr","correlation_id":"corr-run-edr","input"`, 1)

	recorder := submit(t, handler, body, asyncHeaders("run-edr"))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", recorder.Code, recorder.Body.String())
	}
	runID := decode(t, recorder)["run_id"].(string)

	status := waitForStatus(t, handler, runID, "completed")
	if status["terminal_state"] != "cannot-express" {
		t.Errorf("terminal_state = %v", status["terminal_state"])
	}
	if status["failure"] != nil {
		t.Errorf("a decline is not a failure: %v", status["failure"])
	}
	result := decode(t, get(t, handler, "/v1/control-translation-runs/"+runID+"/result"))
	if result["terminal_state"] != "cannot-express" {
		t.Errorf("the immutable result should carry the decline: %v", result["terminal_state"])
	}
}

// The referenced route reaches the same decline: the rows are read and
// lineage-checked, then the target is refused with the references preserved.
func TestReferencedRequestForAFirewallCandidateDeclinesWithItsReferences(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoopForTarget(fake, provenSecRule, "firewall", "firewall-generic")

	payload := decode(t, post(t, handler, "/invoke", orchestrationBody("req-firewall")))

	if payload["terminal_state"] != "cannot-express" {
		t.Fatalf("terminal_state = %v: %s", payload["terminal_state"], payload)
	}
	reason := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)
	if reason["code"] != "unsupported-target-technology" {
		t.Errorf("reason code = %v", reason["code"])
	}
	// The rows were read and validated, so the caller can still trace the run.
	bundle := payload["reference_bundle"].(map[string]any)
	if len(bundle) != 3 {
		t.Errorf("the references should be preserved: %v", bundle)
	}
	subject := payload["structured_result"].(map[string]any)["subject"].(map[string]any)
	if subject["proven_pattern_id"] != "proven-pattern:"+candidateID {
		t.Errorf("the resolved subject was lost: %v", subject)
	}
}
