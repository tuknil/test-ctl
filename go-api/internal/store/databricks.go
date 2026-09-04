// Package store persists completed capability runs in Databricks.
//
// Databricks is the only backend. There is no local database, no volume, and
// no migration step: the immutable results table is the system of record, and
// a deployment that cannot reach it fails readiness rather than quietly
// buffering results somewhere they would be lost.
//
// The table shape matches the one the Python service writes
// (src/control_translation/persistence/databricks.py), so both write rows the
// other can read during a cutover.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/databricks"
	"github.com/ATT-CSO/control-translation/go-api/internal/terminal"
)

// ErrPersistence reports that durable storage could not complete an operation.
var ErrPersistence = errors.New("durable result storage is unavailable")

// ErrIdempotencyConflict reports a key reused for different semantic input.
var ErrIdempotencyConflict = errors.New("idempotency key was already used for a different request")

func persistenceError(operation string, cause error) error {
	return fmt.Errorf("%w: %s: %v", ErrPersistence, operation, cause)
}

// IdempotencyRecord is a previously completed invocation bound to a key.
type IdempotencyRecord struct {
	RequestHash string
	Result      contracts.ResultEnvelope
}

// RunSummaryPage is a bounded page of safe run summaries.
type RunSummaryPage struct {
	Items               []contracts.RunSummary
	Total               int
	TerminalStateCounts map[string]int
}

// Repository is the Databricks-backed durable store.
type Repository struct {
	client    *databricks.Client
	tableName string
}

// Open validates the configured coordinates and returns the repository.
func Open(settings config.Settings) (*Repository, error) {
	return New(settings, databricks.New(settings))
}

// New builds a repository over an existing client, so the reader and the store
// share one authenticated connection.
func New(settings config.Settings, client *databricks.Client) (*Repository, error) {
	tableName, err := databricks.QuoteTable(
		settings.DatabricksCatalog, settings.DatabricksSchema, settings.DatabricksResultsTable)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return &Repository{client: client, tableName: tableName}, nil
}

// Healthcheck reports whether the results table is reachable, for GET /ready.
func (r *Repository) Healthcheck() bool {
	if _, err := r.client.Query("SELECT 1 FROM " + r.tableName + " LIMIT 1"); err != nil {
		slog.Error("Databricks healthcheck failed", "error", err)
		return false
	}
	return true
}

// SaveCompletedRun writes one immutable result row.
//
// The write is a MERGE that inserts only when the result_id is absent, so a
// retry can never overwrite a published result. The row is then read back and
// compared: if the stored content differs from what was sent, the mismatch is
// surfaced rather than assumed benign.
func (r *Repository) SaveCompletedRun(
	request contracts.InvokeRequestEnvelope,
	result contracts.ResultEnvelope,
	requestHash string,
	startedAt time.Time,
) error {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return persistenceError("encode-request", err)
	}
	structuredJSON, err := json.Marshal(result.StructuredResult)
	if err != nil {
		return persistenceError("encode-result", err)
	}
	envelopeJSON, err := json.Marshal(result)
	if err != nil {
		return persistenceError("encode-envelope", err)
	}
	canonical, err := canonicalResultBytes(result)
	if err != nil {
		return persistenceError("canonicalize-result", err)
	}
	digest := sha256.Sum256(canonical)
	resultDigest := hex.EncodeToString(digest[:])

	evidence := map[string]bool{}
	for _, binding := range result.StructuredResult.EvidenceBindings {
		for _, reference := range binding.EvidenceRefs {
			evidence[reference] = true
		}
	}
	for _, reference := range result.Provenance {
		evidence[reference] = true
	}
	evidenceRefs := sortedKeys(evidence)
	upstreamRefs := []string{}
	if request.Input.ProvenPattern != nil {
		upstreamRefs = request.Input.ProvenPattern.ProofRecordIDs
	}
	evidenceJSON, _ := json.Marshal(evidenceRefs)
	upstreamJSON, _ := json.Marshal(upstreamRefs)

	statement := fmt.Sprintf(`
		MERGE INTO %s AS target
		USING (SELECT ? AS result_id) AS source
		ON target.result_id = source.result_id
		WHEN NOT MATCHED THEN INSERT (
			result_id, run_id, request_id, correlation_id, capability,
			contract_id, terminal_state, status, subject_record_revision_id,
			request_json, result_json, completion_json, result_sha256,
			result_size_bytes, evidence_refs, upstream_result_refs, created_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			PARSE_JSON(?), PARSE_JSON(?), PARSE_JSON(?), ?, ?,
			PARSE_JSON(?), PARSE_JSON(?), ?
		)`, r.tableName)

	parameters := []databricks.Parameter{
		databricks.String("1", result.ResultID),
		databricks.String("2", result.ResultID),
		databricks.String("3", result.RunID),
		databricks.String("4", derefString(request.RequestID)),
		databricks.String("5", result.CorrelationID),
		databricks.String("6", result.Capability),
		databricks.String("7", result.ContractID),
		databricks.String("8", string(result.TerminalState)),
		databricks.String("9", result.Status),
		databricks.String("10", ""), // subject_record_revision_id: not carried by this build
		databricks.String("11", string(requestJSON)),
		databricks.String("12", string(structuredJSON)),
		databricks.String("13", string(envelopeJSON)),
		databricks.String("14", resultDigest),
		databricks.Int("15", len(canonical)),
		databricks.String("16", string(evidenceJSON)),
		databricks.String("17", string(upstreamJSON)),
		databricks.Timestamp("18", startedAt.UTC().Format("2006-01-02T15:04:05.000000Z")),
	}
	if _, err := r.client.Query(statement, parameters...); err != nil {
		return persistenceError("insert-result", err)
	}

	rows, err := r.client.Query(fmt.Sprintf(
		"SELECT run_id, result_sha256, result_size_bytes FROM %s WHERE result_id = ? LIMIT 1", r.tableName),
		databricks.String("1", result.ResultID))
	if err != nil {
		return persistenceError("verify-result", err)
	}
	if len(rows) == 0 {
		return persistenceError("verify-result", errors.New("the row was not stored"))
	}
	storedSize, _ := strconv.Atoi(databricks.Text(rows[0][2]))
	if databricks.Text(rows[0][0]) != result.RunID || databricks.Text(rows[0][1]) != resultDigest ||
		storedSize != len(canonical) {
		return persistenceError("verify-result",
			errors.New("immutable result identity conflicts with stored content"))
	}
	return nil
}

// canonicalResultBytes serializes the content covered by the integrity
// metadata: sorted keys, compact separators, and the self-describing
// integrity fields excluded.
func canonicalResultBytes(result contracts.ResultEnvelope) ([]byte, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, err
	}
	delete(document, "content_sha256")
	delete(document, "size_bytes")
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// GetByIdempotencyKey returns a previously completed run for a key.
//
// The key is the caller's request_id, which is stored on the row, so a retry
// resolves to the row it originally wrote.
func (r *Repository) GetByIdempotencyKey(key string) (*IdempotencyRecord, error) {
	rows, err := r.client.Query(fmt.Sprintf(
		"SELECT TO_JSON(completion_json), TO_JSON(request_json) FROM %s WHERE request_id = ? LIMIT 1",
		r.tableName), databricks.String("1", key))
	if err != nil {
		return nil, persistenceError("get-by-idempotency-key", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var envelope contracts.ResultEnvelope
	if err := json.Unmarshal([]byte(databricks.Text(rows[0][0])), &envelope); err != nil {
		return nil, persistenceError("decode-stored-envelope", err)
	}
	var storedRequest contracts.InvokeRequestEnvelope
	if err := json.Unmarshal([]byte(databricks.Text(rows[0][1])), &storedRequest); err != nil {
		return nil, persistenceError("decode-stored-request", err)
	}
	return &IdempotencyRecord{
		RequestHash: CanonicalRequestHash(storedRequest),
		Result:      envelope,
	}, nil
}

// GetRun returns the durable completion envelope for a run.
func (r *Repository) GetRun(runID string) (*contracts.ResultEnvelope, error) {
	return r.envelopeBy("run_id", runID)
}

// GetResult returns the durable completion envelope for a result id.
func (r *Repository) GetResult(resultID string) (*contracts.ResultEnvelope, error) {
	return r.envelopeBy("result_id", resultID)
}

func (r *Repository) envelopeBy(column, value string) (*contracts.ResultEnvelope, error) {
	rows, err := r.client.Query(fmt.Sprintf(
		"SELECT TO_JSON(completion_json) FROM %s WHERE %s = ? LIMIT 1", r.tableName, column),
		databricks.String("1", value))
	if err != nil {
		return nil, persistenceError("read-envelope", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var envelope contracts.ResultEnvelope
	if err := json.Unmarshal([]byte(databricks.Text(rows[0][0])), &envelope); err != nil {
		return nil, persistenceError("decode-envelope", err)
	}
	return &envelope, nil
}

// ListRuns returns one bounded page of safe run summaries, newest first. The
// projection reads scalar paths out of the stored JSON so no artifact content
// crosses the wire.
func (r *Repository) ListRuns(limit, offset int) (RunSummaryPage, error) {
	page := RunSummaryPage{Items: []contracts.RunSummary{}, TerminalStateCounts: map[string]int{}}

	rows, err := r.client.Query(fmt.Sprintf(`
		SELECT
			run_id,
			result_id,
			correlation_id,
			status,
			terminal_state,
			completion_json:structured_result.outcome_reason.code::STRING,
			completion_json:structured_result.subject.vulnerability_id::STRING,
			completion_json:structured_result.input_bindings.target_technology::STRING,
			completion_json:structured_result.primary_candidate.candidate_artifact.artifact_type::STRING,
			created_at,
			result_json:produced_at::STRING
		FROM %s
		ORDER BY created_at DESC, run_id DESC
		LIMIT ? OFFSET ?`, r.tableName),
		databricks.Int("1", limit), databricks.Int("2", offset))
	if err != nil {
		return page, persistenceError("list-runs", err)
	}
	for _, row := range rows {
		summary := contracts.RunSummary{
			RunID:             databricks.Text(row[0]),
			ResultID:          databricks.Text(row[1]),
			CorrelationID:     databricks.Text(row[2]),
			Status:            databricks.Text(row[3]),
			TerminalState:     terminal.State(databricks.Text(row[4])),
			OutcomeReasonCode: databricks.Text(row[5]),
			VulnerabilityID:   databricks.Text(row[6]),
			TargetTechnology:  databricks.Text(row[7]),
			StartedAt:         parseTime(databricks.Text(row[9])),
			CompletedAt:       parseTime(databricks.Text(row[10])),
			ResultHref:        "/v1/results/" + databricks.Text(row[1]),
		}
		if artifactType := databricks.Text(row[8]); artifactType != "" {
			summary.ArtifactType = &artifactType
		}
		page.Items = append(page.Items, summary)
	}

	totals, err := r.client.Query("SELECT COUNT(*) FROM " + r.tableName)
	if err != nil {
		return page, persistenceError("count-runs", err)
	}
	if len(totals) > 0 {
		page.Total, _ = strconv.Atoi(databricks.Text(totals[0][0]))
	}
	counts, err := r.client.Query(
		"SELECT terminal_state, COUNT(*) FROM " + r.tableName + " GROUP BY terminal_state")
	if err != nil {
		return page, persistenceError("count-terminal-states", err)
	}
	for _, row := range counts {
		count, _ := strconv.Atoi(databricks.Text(row[1]))
		page.TerminalStateCounts[databricks.Text(row[0])] = count
	}
	return page, nil
}

// CanonicalRequestHash hashes semantic request data, excluding transport and
// retry identifiers, so an idempotent retry is recognized and a changed body
// under the same key is refused.
func CanonicalRequestHash(envelope contracts.InvokeRequestEnvelope) string {
	encoded, err := json.Marshal(map[string]any{"input": envelope.Input})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func parseTime(value string) contracts.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000Z", time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05.999999", "2006-01-02T15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return contracts.Time{Time: parsed.UTC()}
		}
	}
	return contracts.Time{Time: time.Time{}}
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
