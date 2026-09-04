// Package storetest provides a fake warehouse so the store, the upstream
// reader and the HTTP surface can be exercised without a live Databricks.
//
// It implements databricks.Querier, so tests sit at the SQL boundary and can
// assert the statement text and the bound arguments -- the same place
// tests/test_upstream_databricks.py and tests/test_databricks_persistence.py
// assert in the Python service.
package storetest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// FakeWorkspace understands only the handful of statements this service
// issues, which is enough to exercise the client, the row mapping, and the
// read-back verification.
type FakeWorkspace struct {
	mu   sync.Mutex
	rows []map[string]string
	// upstream holds the proof-loop rows a referenced request reads, keyed by
	// result_id. A key may map to several rows so ambiguity can be exercised.
	upstream map[string][][]*string
	// Fail makes every statement return a workspace error.
	Fail bool
	// Unreachable makes Ping fail while statements still work.
	Unreachable bool

	statements []Statement
}

// Statement is one executed statement and the arguments bound to it.
type Statement struct {
	SQL  string
	Args []string
}

// NewFakeWorkspace returns an empty warehouse.
func NewFakeWorkspace(t *testing.T) *FakeWorkspace {
	t.Helper()
	return &FakeWorkspace{}
}

// Statements returns everything executed so far, in order.
func (f *FakeWorkspace) Statements() []Statement {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Statement{}, f.statements...)
}

// LastStatementMatching returns the most recent statement containing needle.
func (f *FakeWorkspace) LastStatementMatching(needle string) (Statement, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for index := len(f.statements) - 1; index >= 0; index-- {
		if strings.Contains(f.statements[index].SQL, needle) {
			return f.statements[index], true
		}
	}
	return Statement{}, false
}

// Rows returns a copy of the stored result rows.
func (f *FakeWorkspace) Rows() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string{}, f.rows...)
}

// UpstreamRow registers one proof-loop row. The column order matches the
// SELECT the resolver issues for that role.
func (f *FakeWorkspace) UpstreamRow(resultID string, columns ...string) {
	f.UpstreamRowsFor(resultID, columns)
}

// UpstreamRowsFor registers several rows for one result_id, so an ambiguous
// reference can be exercised.
func (f *FakeWorkspace) UpstreamRowsFor(resultID string, rows ...[]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upstream == nil {
		f.upstream = map[string][][]*string{}
	}
	converted := make([][]*string, 0, len(rows))
	for _, row := range rows {
		values := make([]*string, 0, len(row))
		for index := range row {
			values = append(values, ptr(row[index]))
		}
		converted = append(converted, values)
	}
	f.upstream[resultID] = converted
}

// DropUpstreamRow removes a registered row, so a missing reference can be
// exercised.
func (f *FakeWorkspace) DropUpstreamRow(resultID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.upstream, resultID)
}

// OverwriteRow replaces fields on a stored result row, so a read-back mismatch
// can be exercised.
func (f *FakeWorkspace) OverwriteRow(resultID string, fields map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for index, row := range f.rows {
		if row["result_id"] == resultID {
			for key, value := range fields {
				f.rows[index][key] = value
			}
			return
		}
	}
}

// Ping implements databricks.Querier.
func (f *FakeWorkspace) Ping() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail || f.Unreachable {
		return errors.New("the Databricks warehouse is unreachable")
	}
	return nil
}

// Exec implements databricks.Querier.
func (f *FakeWorkspace) Exec(statement string, args ...any) error {
	_, err := f.Query(statement, args...)
	return err
}

// Query implements databricks.Querier.
func (f *FakeWorkspace) Query(statement string, args ...any) ([][]*string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bound := make([]string, 0, len(args))
	for _, arg := range args {
		bound = append(bound, argText(arg))
	}
	f.statements = append(f.statements, Statement{SQL: statement, Args: bound})
	if f.Fail {
		return nil, errors.New("the Databricks statement failed")
	}

	switch {
	case strings.Contains(statement, "MERGE INTO"):
		f.merge(bound)
		return nil, nil

	case strings.Contains(statement, "SELECT run_id, result_sha256, result_size_bytes"):
		if row := f.findBy("result_id", bound[0]); row != nil {
			return [][]*string{{ptr(row["run_id"]), ptr(row["result_sha256"]), ptr(row["result_size_bytes"])}}, nil
		}

	case strings.Contains(statement, "SELECT TO_JSON(completion_json), TO_JSON(request_json)"):
		if row := f.findBy("request_id", bound[0]); row != nil {
			return [][]*string{{ptr(row["completion_json"]), ptr(row["request_json"])}}, nil
		}

	case strings.Contains(statement, "SELECT TO_JSON(completion_json) FROM"):
		column := "run_id"
		if strings.Contains(statement, "WHERE result_id = ?") {
			column = "result_id"
		}
		if row := f.findBy(column, bound[0]); row != nil {
			return [][]*string{{ptr(row["completion_json"])}}, nil
		}

	case strings.Contains(statement, "SELECT COUNT(*)"):
		return [][]*string{{ptr(strconv.Itoa(len(f.rows)))}}, nil

	case strings.Contains(statement, "GROUP BY terminal_state"):
		counts := map[string]int{}
		for _, row := range f.rows {
			counts[row["terminal_state"]]++
		}
		var data [][]*string
		for state, count := range counts {
			data = append(data, []*string{ptr(state), ptr(strconv.Itoa(count))})
		}
		return data, nil

	case strings.Contains(statement, "ORDER BY created_at DESC"):
		return f.listRows(), nil

	case strings.Contains(statement, "WHERE result_id = ? LIMIT 2"):
		return f.upstream[bound[0]], nil

	case strings.Contains(statement, "SELECT 1 FROM"):
		return [][]*string{{ptr("1")}}, nil
	}
	return nil, nil
}

// merge applies WHEN NOT MATCHED semantics: an existing result_id is never
// overwritten, which is what makes a retry safe.
func (f *FakeWorkspace) merge(args []string) {
	row := map[string]string{
		"result_id": args[1], "run_id": args[2], "request_id": args[3],
		"correlation_id": args[4], "capability": args[5], "contract_id": args[6],
		"terminal_state": args[7], "status": args[8],
		"request_json": args[10], "result_json": args[11], "completion_json": args[12],
		"result_sha256": args[13], "result_size_bytes": args[14], "created_at": args[17],
	}
	for _, existing := range f.rows {
		if existing["result_id"] == row["result_id"] {
			return
		}
	}
	f.rows = append(f.rows, row)
}

func (f *FakeWorkspace) listRows() [][]*string {
	var data [][]*string
	for _, row := range f.rows {
		data = append(data, []*string{
			ptr(row["run_id"]), ptr(row["result_id"]), ptr(row["correlation_id"]),
			ptr(row["status"]), ptr(row["terminal_state"]),
			ptr(jsonPath(row["completion_json"], "outcome_reason", "code")),
			ptr(jsonPath(row["completion_json"], "subject", "vulnerability_id")),
			ptr(jsonPath(row["completion_json"], "input_bindings", "target_technology")),
			ptr(artifactType(row["completion_json"])),
			ptr(row["created_at"]),
			ptr(jsonPath(row["result_json"], "produced_at")),
		})
	}
	return data
}

func (f *FakeWorkspace) findBy(column, value string) map[string]string {
	for _, row := range f.rows {
		if row[column] == value {
			return row
		}
	}
	return nil
}

func ptr(value string) *string { return &value }

func argText(arg any) string {
	switch typed := arg.(type) {
	case nil:
		return ""
	case string:
		return typed
	case int:
		return strconv.Itoa(typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// FakeSettings returns settings pointed at a fake warehouse.
func FakeSettings() config.Settings {
	return config.Settings{
		RunMode: "fixture", ModelProvider: "none", ModelName: "not-configured",
		EnableDocs: true, Host: "127.0.0.1", Port: 8000,
		DatabricksDSN:              "token:fake-pat@fake.databricks.example:443/sql/1.0/warehouses/abc",
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
