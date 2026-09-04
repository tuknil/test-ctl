// Package storetest provides a fake Databricks workspace so the store and the
// HTTP surface can be exercised without a live warehouse.
package storetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// FakeWorkspace is a minimal stand-in for the Databricks Statement Execution
// API. It understands only the handful of statements this service issues,
// which is enough to exercise the client, the row mapping, and the
// read-back verification without a live warehouse.
type FakeWorkspace struct {
	Server *httptest.Server

	mu   sync.Mutex
	rows []map[string]string
	// upstream holds the proof-loop rows a referenced request reads, keyed by
	// result_id.
	upstream map[string][]*string
	// Fail makes the next statement return a workspace error.
	Fail bool
}

// UpstreamRow registers one proof-loop row for the resolver to read. The
// column order matches the SELECT the resolver issues for that role.
func (f *FakeWorkspace) UpstreamRow(resultID string, columns ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upstream == nil {
		f.upstream = map[string][]*string{}
	}
	values := make([]*string, 0, len(columns))
	for index := range columns {
		values = append(values, ptr(columns[index]))
	}
	f.upstream[resultID] = values
}

// DropUpstreamRow removes a registered row, so a missing reference can be
// exercised.
func (f *FakeWorkspace) DropUpstreamRow(resultID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.upstream, resultID)
}

var mergeValues = regexp.MustCompile(`(?s)MERGE INTO`)

// NewFakeWorkspace starts the fake and returns it with the test's cleanup
// already registered.
func NewFakeWorkspace(t *testing.T) *FakeWorkspace {
	t.Helper()
	fake := &FakeWorkspace{}
	fake.Server = httptest.NewServer(http.HandlerFunc(fake.handle))
	t.Cleanup(fake.Server.Close)
	return fake
}

// Rows returns a copy of the stored rows.
func (f *FakeWorkspace) Rows() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string{}, f.rows...)
}

func (f *FakeWorkspace) handle(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/oidc/v1/token") {
		writeJSON(w, map[string]any{"access_token": "fake-token", "expires_in": 3600})
		return
	}
	var request struct {
		Statement  string `json:"statement"`
		Parameters []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"parameters"`
	}
	_ = json.NewDecoder(r.Body).Decode(&request)

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail {
		writeJSON(w, map[string]any{"status": map[string]any{
			"state": "FAILED",
			"error": map[string]any{"error_code": "TEST_FAILURE", "message": "injected"},
		}})
		return
	}
	values := map[string]string{}
	for _, item := range request.Parameters {
		values[item.Name] = item.Value
	}

	statement := request.Statement
	var data [][]*string
	switch {
	case mergeValues.MatchString(statement):
		// Positional MERGE parameters, in the order the store binds them.
		row := map[string]string{
			"result_id": values["2"], "run_id": values["3"], "request_id": values["4"],
			"correlation_id": values["5"], "capability": values["6"], "contract_id": values["7"],
			"terminal_state": values["8"], "status": values["9"],
			"request_json": values["11"], "result_json": values["12"],
			"completion_json": values["13"], "result_sha256": values["14"],
			"result_size_bytes": values["15"], "created_at": values["18"],
		}
		// WHEN NOT MATCHED: an existing result_id is never overwritten.
		for _, existing := range f.rows {
			if existing["result_id"] == row["result_id"] {
				writeJSON(w, succeeded(nil))
				return
			}
		}
		f.rows = append(f.rows, row)
	case strings.Contains(statement, "SELECT run_id, result_sha256, result_size_bytes"):
		if row := f.findBy("result_id", values["1"]); row != nil {
			data = [][]*string{{ptr(row["run_id"]), ptr(row["result_sha256"]), ptr(row["result_size_bytes"])}}
		}
	case strings.Contains(statement, "SELECT TO_JSON(completion_json), TO_JSON(request_json)"):
		if row := f.findBy("request_id", values["1"]); row != nil {
			data = [][]*string{{ptr(row["completion_json"]), ptr(row["request_json"])}}
		}
	case strings.Contains(statement, "SELECT TO_JSON(completion_json) FROM"):
		column := "run_id"
		if strings.Contains(statement, "WHERE result_id = ?") {
			column = "result_id"
		}
		if row := f.findBy(column, values["1"]); row != nil {
			data = [][]*string{{ptr(row["completion_json"])}}
		}
	case strings.Contains(statement, "SELECT COUNT(*)"):
		data = [][]*string{{ptr(itoa(len(f.rows)))}}
	case strings.Contains(statement, "GROUP BY terminal_state"):
		counts := map[string]int{}
		for _, row := range f.rows {
			counts[row["terminal_state"]]++
		}
		for state, count := range counts {
			data = append(data, []*string{ptr(state), ptr(itoa(count))})
		}
	case strings.Contains(statement, "SELECT\n\t\t\trun_id,"), strings.Contains(statement, "ORDER BY created_at DESC"):
		for _, row := range f.rows {
			var envelope struct {
				StructuredResult struct {
					OutcomeReason struct{ Code string } `json:"outcome_reason"`
					Subject       struct {
						VulnerabilityID string `json:"vulnerability_id"`
					} `json:"subject"`
					InputBindings struct {
						TargetTechnology string `json:"target_technology"`
					} `json:"input_bindings"`
					PrimaryCandidate *struct {
						CandidateArtifact struct {
							ArtifactType string `json:"artifact_type"`
						} `json:"candidate_artifact"`
					} `json:"primary_candidate"`
					ProducedAt string `json:"produced_at"`
				} `json:"structured_result"`
			}
			_ = json.Unmarshal([]byte(row["completion_json"]), &envelope)
			artifact := (*string)(nil)
			if envelope.StructuredResult.PrimaryCandidate != nil {
				artifact = ptr(envelope.StructuredResult.PrimaryCandidate.CandidateArtifact.ArtifactType)
			}
			data = append(data, []*string{
				ptr(row["run_id"]), ptr(row["result_id"]), ptr(row["correlation_id"]),
				ptr(row["status"]), ptr(row["terminal_state"]),
				ptr(envelope.StructuredResult.OutcomeReason.Code),
				ptr(envelope.StructuredResult.Subject.VulnerabilityID),
				ptr(envelope.StructuredResult.InputBindings.TargetTechnology),
				artifact, ptr(row["created_at"]), ptr(envelope.StructuredResult.ProducedAt),
			})
		}
	case strings.Contains(statement, "SELECT 1 FROM"):
		data = [][]*string{{ptr("1")}}
	case strings.Contains(statement, "WHERE result_id = ? LIMIT 2"):
		// The resolver's read of one proof-loop row.
		if row, ok := f.upstream[values["1"]]; ok {
			data = [][]*string{row}
		}
	}
	writeJSON(w, succeeded(data))
}

func (f *FakeWorkspace) findBy(column, value string) map[string]string {
	for _, row := range f.rows {
		if row[column] == value {
			return row
		}
	}
	return nil
}

func succeeded(data [][]*string) map[string]any {
	return map[string]any{
		"status": map[string]any{"state": "SUCCEEDED"},
		"result": map[string]any{"data_array": data},
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func ptr(value string) *string { return &value }

func itoa(value int) string { return strconv.Itoa(value) }

// FakeSettings returns settings pointed at a fake workspace.
func FakeSettings() config.Settings {
	return config.Settings{
		RunMode: "fixture", ModelProvider: "none", ModelName: "not-configured",
		EnableDocs: true, Host: "127.0.0.1", Port: 8000,
		DatabricksServerHostname:   "fake.databricks.example",
		DatabricksHTTPPath:         "/sql/1.0/warehouses/abc",
		DatabricksAuthType:         "pat",
		DatabricksToken:            "fake-pat",
		DatabricksCatalog:          "test_catalog",
		DatabricksSchema:           "control_translation",
		DatabricksResultsTable:     "control_translation_results",
		DatabasePath:               "lifecycle.db",
		ServiceReplicaCount:        1,
		WorkerPollSeconds:          0.02,
		WorkerLeaseSeconds:         30,
		WorkerHeartbeatSeconds:     5,
		WorkerMaxAttempts:          3,
		WorkerShutdownGraceSeconds: 2,
		DefaultTargetTechnology:    "akamai-waf",
		DefaultTargetPolicyContext: "akamai-policy:example:rev-17",
		CORSAllowedOrigins:         []string{"http://127.0.0.1:8080"},
	}
}
