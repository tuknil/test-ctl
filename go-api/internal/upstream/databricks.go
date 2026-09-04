package upstream

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/databricks"
)

// Unity Catalog is read through the SQL Statement Execution REST API. The SQL
// text, the approved-table check, and the row mapping match the Python
// service's; only the transport differs.
//
// NOTE: exercised against a fake HTTP server, not a live Databricks workspace.
// See README.md.

type shapeSpec struct {
	name    string
	columns string
	catalog string
	schema  string
	table   string
}

var shapes = map[string]shapeSpec{
	"defense-generation-result:": {
		name:    "defense",
		columns: "result_id, terminal_state, TO_JSON(request_json), TO_JSON(result_json)",
		catalog: "36889_janus_dev", schema: "defense_generation", table: "defense_generation_results",
	},
	"mitigation-check-result:": {
		name:    "mitigation",
		columns: "result_id, result_json",
		catalog: "36889_janus_dev", schema: "mitigation-check", table: "mitigation_check",
	},
	"bypass-validation-result:": {
		name:    "bypass",
		columns: "result_id, terminal_state, correlation_id, request_json, result_json",
		catalog: "36889_janus_dev", schema: "bypass_validation", table: "bypass_validation_results",
	},
}

// NewResolver returns a Databricks-backed resolver over an existing client.
//
// It returns nil when Databricks is not configured, which makes referenced
// invocations produce a typed insufficient-context result rather than a guess.
// The connection has one source, so that is the only thing to check: the
// client cannot exist without it, and its shape was already validated when the
// DSN was parsed.
func NewResolver(settings config.Settings, client databricks.Querier) Resolver {
	if strings.TrimSpace(settings.DatabricksDSN) == "" || client == nil {
		return nil
	}
	return &DatabricksResolver{client: client}
}

// DatabricksResolver reads exactly one row per caller-authorized reference.
type DatabricksResolver struct {
	client databricks.Querier
}

// Fetch implements Resolver.
func (d *DatabricksResolver) Fetch(reference contracts.DatabricksResultReference) (*Record, error) {
	var spec shapeSpec
	var known bool
	for prefix, candidate := range shapes {
		if strings.HasPrefix(reference.Key, prefix) {
			spec, known = candidate, true
			break
		}
	}
	if !known {
		return nil, resolutionError("unsupported upstream result-reference key")
	}
	if reference.Catalog != spec.catalog || reference.SchemaName != spec.schema ||
		reference.Table != spec.table {
		return nil, resolutionError("%s result reference does not match the approved table", spec.name)
	}
	tableName, err := databricks.QuoteTable(reference.Catalog, reference.SchemaName, reference.Table)
	if err != nil {
		return nil, resolutionError("%v", err)
	}
	statement := fmt.Sprintf("SELECT %s FROM %s WHERE result_id = ? LIMIT 2", spec.columns, tableName)

	started := time.Now()
	slog.Info("upstream Databricks read started",
		"shape", spec.name, "table", tableName, "result_id", reference.Key)
	rows, err := d.client.Query(statement, reference.Key)
	if err != nil {
		slog.Error("upstream Databricks read failed",
			"shape", spec.name, "table", tableName, "result_id", reference.Key,
			"duration_ms", float64(time.Since(started).Microseconds())/1000, "error", err)
		return nil, err
	}
	if len(rows) > 1 {
		return nil, resolutionError("%s result reference resolved to multiple rows", spec.name)
	}
	slog.Info("upstream Databricks read completed",
		"shape", spec.name, "table", tableName, "result_id", reference.Key,
		"found", len(rows) == 1, "duration_ms", float64(time.Since(started).Microseconds())/1000)
	if len(rows) == 0 {
		return nil, nil
	}
	return mapRow(spec.name, rows[0])
}

func mapRow(shape string, row []*string) (*Record, error) {
	var request, result map[string]any
	var terminalState, correlationID, subjectRevision *string
	var err error

	switch shape {
	case "defense":
		if request, err = decodeJSONObject(row[2], "Defense Generation request_json"); err != nil {
			return nil, err
		}
		if result, err = decodeJSONObject(row[3], "Defense Generation result_json"); err != nil {
			return nil, err
		}
		terminalState = row[1]
		correlationID = findOne("correlation_id", result, request)
		subjectRevision = findOne("subject_record_revision_id", result, request)
	case "mitigation":
		request = map[string]any{}
		if result, err = decodeJSONObject(row[1], "Mitigation Check result_json"); err != nil {
			return nil, err
		}
		terminalState = stringField(result["terminal_state"])
		correlationID = stringField(result["correlation_id"])
		subjectRevision = findOne("subject_record_revision_id", result)
	default:
		if request, err = decodeJSONObject(row[3], "Bypass Validation request_json"); err != nil {
			return nil, err
		}
		if result, err = decodeJSONObject(row[4], "Bypass Validation result_json"); err != nil {
			return nil, err
		}
		terminalState = row[1]
		if terminalState == nil || *terminalState == "" {
			terminalState = stringField(result["terminal_state"])
		}
		correlationID = row[2]
		if correlationID == nil || *correlationID == "" {
			correlationID = findOne("correlation_id", result, request)
		}
		subjectRevision = findOne("subject_record_revision_id", result, request)
	}

	resultID := ""
	if row[0] != nil {
		resultID = *row[0]
	}
	state := ""
	if terminalState != nil {
		state = *terminalState
	}
	return &Record{
		ResultID:                resultID,
		TerminalState:           state,
		CorrelationID:           correlationID,
		SubjectRecordRevisionID: subjectRevision,
		Request:                 request,
		Result:                  result,
	}, nil
}

// decodeJSONObject decodes a TO_JSON cell and rejects non-object payloads.
func decodeJSONObject(value *string, label string) (map[string]any, error) {
	if value == nil || *value == "" {
		return map[string]any{}, nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(*value), &decoded); err != nil {
		return nil, resolutionError("%s is not valid JSON", label)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, resolutionError("%s must be a JSON object", label)
	}
	return object, nil
}

func findOne(key string, documents ...map[string]any) *string {
	for _, document := range documents {
		if value := oneValue(document, key); value != nil {
			return value
		}
	}
	return nil
}

func stringField(value any) *string {
	if text, ok := value.(string); ok && text != "" {
		return &text
	}
	return nil
}
