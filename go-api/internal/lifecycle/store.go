package lifecycle

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
)

// LifecycleRun is a durable worker record with its validated request.
type LifecycleRun struct {
	RunID           string
	RequestID       string
	CorrelationID   string
	IdempotencyKey  string
	RequestDigest   string
	Request         contracts.InvokeRequestEnvelope
	Status          string
	Attempt         int
	CancelRequested bool
	CreatedAt       time.Time
	AcceptedAt      time.Time
	StartedAt       *time.Time
	UpdatedAt       time.Time
	CompletedAt     *time.Time
	TerminalState   *string
	ResultID        *string
	Completion      *contracts.CanonicalCompletion
	Failure         *contracts.RunFailure
	Progress        contracts.RunProgress
}

// CreateLifecycleRun persists a queued run, or returns the existing one when
// the idempotency key repeats with the same normalized request digest.
func (s *Store) CreateLifecycleRun(
	runID string,
	envelope contracts.InvokeRequestEnvelope,
	requestDigest string,
) (*LifecycleRun, bool, error) {
	existing, err := s.GetLifecycleRunByKey(*envelope.IdempotencyKey)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if existing.RequestDigest != requestDigest {
			return nil, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}

	requestJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, storeError("encode-lifecycle-request", err)
	}
	now := nowText()
	_, err = s.db.Exec(`
		INSERT INTO capability_run_lifecycle(
			run_id, request_id, correlation_id, idempotency_key, request_digest,
			request_json, status, progress_phase, progress_percent, progress_message,
			cancel_requested, attempt_number, created_at, accepted_at, updated_at)
		VALUES (?,?,?,?,?,?,'queued','queued',0,?,0,0,?,?,?)`,
		runID, *envelope.RequestID, *envelope.CorrelationID, *envelope.IdempotencyKey,
		requestDigest, string(requestJSON),
		"Run accepted and queued for durable processing.", now, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			// A concurrent retry committed the same key first.
			existing, lookupErr := s.GetLifecycleRunByKey(*envelope.IdempotencyKey)
			if lookupErr != nil {
				return nil, false, lookupErr
			}
			if existing != nil && existing.RequestDigest == requestDigest {
				return existing, false, nil
			}
			return nil, false, ErrIdempotencyConflict
		}
		return nil, false, storeError("insert-lifecycle-run", err)
	}
	created, err := s.GetLifecycleRun(runID)
	return created, true, err
}

// GetLifecycleRun reads one lifecycle run by run id.
func (s *Store) GetLifecycleRun(runID string) (*LifecycleRun, error) {
	return s.scanLifecycle(s.db.QueryRow(lifecycleSelect+" WHERE run_id = ?", runID))
}

// GetLifecycleRunByKey reads one lifecycle run by idempotency key.
func (s *Store) GetLifecycleRunByKey(key string) (*LifecycleRun, error) {
	return s.scanLifecycle(s.db.QueryRow(lifecycleSelect+" WHERE idempotency_key = ?", key))
}

const lifecycleSelect = `
	SELECT run_id, request_id, correlation_id, idempotency_key, request_digest,
	       request_json, status, terminal_state, result_id, completion_json, failure_json,
	       progress_phase, progress_percent, progress_message, cancel_requested,
	       attempt_number, created_at, accepted_at, started_at, updated_at, completed_at
	FROM capability_run_lifecycle`

func (s *Store) scanLifecycle(row *sql.Row) (*LifecycleRun, error) {
	var (
		run                              LifecycleRun
		requestJSON                      string
		terminalState, resultID          sql.NullString
		resultJSON, failureJSON          sql.NullString
		progressPercent                  sql.NullInt64
		cancelRequested                  int
		createdAt, acceptedAt, updatedAt string
		startedAt, completedAt           sql.NullString
	)
	err := row.Scan(&run.RunID, &run.RequestID, &run.CorrelationID, &run.IdempotencyKey,
		&run.RequestDigest, &requestJSON, &run.Status, &terminalState, &resultID,
		&resultJSON, &failureJSON, &run.Progress.Phase, &progressPercent,
		&run.Progress.Message, &cancelRequested, &run.Attempt,
		&createdAt, &acceptedAt, &startedAt, &updatedAt, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeError("read-lifecycle-run", err)
	}
	if err := json.Unmarshal([]byte(requestJSON), &run.Request); err != nil {
		return nil, storeError("decode-lifecycle-request", err)
	}
	run.CancelRequested = cancelRequested == 1
	run.CreatedAt = parseTimeValue(createdAt).Time
	run.AcceptedAt = parseTimeValue(acceptedAt).Time
	run.UpdatedAt = parseTimeValue(updatedAt).Time
	if startedAt.Valid {
		value := parseTimeValue(startedAt.String).Time
		run.StartedAt = &value
	}
	if completedAt.Valid {
		value := parseTimeValue(completedAt.String).Time
		run.CompletedAt = &value
	}
	if terminalState.Valid {
		run.TerminalState = &terminalState.String
	}
	if resultID.Valid {
		run.ResultID = &resultID.String
	}
	if progressPercent.Valid {
		percent := int(progressPercent.Int64)
		run.Progress.Percent = &percent
	}
	if resultJSON.Valid {
		var completion contracts.CanonicalCompletion
		if err := json.Unmarshal([]byte(resultJSON.String), &completion); err != nil {
			return nil, storeError("decode-lifecycle-completion", err)
		}
		run.Completion = &completion
	}
	if failureJSON.Valid {
		var failure contracts.RunFailure
		if err := json.Unmarshal([]byte(failureJSON.String), &failure); err != nil {
			return nil, storeError("decode-lifecycle-failure", err)
		}
		run.Failure = &failure
	}
	return &run, nil
}

// ClaimNextQueuedRun leases one queued run to a worker, or returns nil when
// the queue is empty. Expired leases are reclaimed by the same statement, so a
// crashed worker's run is picked up on the next poll.
func (s *Store) ClaimNextQueuedRun(workerID string, leaseSeconds int, maxAttempts int) (*LifecycleRun, error) {
	now := time.Now().UTC()
	nowValue := now.Format(timeLayout)
	leaseExpiry := now.Add(time.Duration(leaseSeconds) * time.Second).Format(timeLayout)

	result, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET status = 'running', worker_id = ?, lease_expires_at = ?, last_heartbeat_at = ?,
		    attempt_number = attempt_number + 1, started_at = COALESCE(started_at, ?),
		    updated_at = ?, progress_phase = 'running',
		    progress_message = 'Translation in progress.'
		WHERE run_id = (
			SELECT run_id FROM capability_run_lifecycle
			WHERE (status = 'queued' OR (status = 'running' AND lease_expires_at < ?))
			  AND attempt_number < ?
			ORDER BY created_at ASC LIMIT 1
		)`, workerID, leaseExpiry, nowValue, nowValue, nowValue, nowValue, maxAttempts)
	if err != nil {
		return nil, storeError("claim-lifecycle-run", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, nil
	}
	return s.scanLifecycle(s.db.QueryRow(lifecycleSelect + " WHERE worker_id = '" + escape(workerID) +
		"' AND status = 'running' ORDER BY updated_at DESC LIMIT 1"))
}

func escape(value string) string {
	out := make([]rune, 0, len(value))
	for _, char := range value {
		if char == '\'' {
			out = append(out, '\'')
		}
		out = append(out, char)
	}
	return string(out)
}

// Heartbeat extends a worker's lease while translation is still running.
func (s *Store) Heartbeat(runID, workerID string, leaseSeconds int) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET lease_expires_at = ?, last_heartbeat_at = ?, updated_at = ?
		WHERE run_id = ? AND worker_id = ? AND status = 'running'`,
		now.Add(time.Duration(leaseSeconds)*time.Second).Format(timeLayout),
		now.Format(timeLayout), now.Format(timeLayout), runID, workerID)
	if err != nil {
		return storeError("heartbeat-lifecycle-run", err)
	}
	return nil
}

// CompleteLifecycleRun finishes a run whose immutable result is already stored
// in Databricks. Only the pointer and the compact completion are kept here.
//
// The update is guarded by worker_id so a worker that lost its lease to a
// recovery attempt cannot complete a run another attempt now owns.
func (s *Store) CompleteLifecycleRun(
	runID, workerID, terminalState, resultID string,
	completion contracts.CanonicalCompletion,
) error {
	completionJSON, err := json.Marshal(completion)
	if err != nil {
		return storeError("encode-lifecycle-completion", err)
	}
	now := nowText()
	if _, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET status = 'completed', terminal_state = ?, result_id = ?,
		    completion_json = ?, progress_phase = 'completed', progress_percent = 100,
		    progress_message = 'Translation completed.', worker_id = NULL,
		    lease_expires_at = NULL, updated_at = ?, completed_at = ?
		WHERE run_id = ? AND worker_id = ?`,
		terminalState, resultID, string(completionJSON), now, now, runID, workerID,
	); err != nil {
		return storeError("complete-lifecycle-run", err)
	}
	return nil
}

// FailLifecycleRun records a failure. A retryable one returns the run to the
// queue for another bounded attempt; a terminal one completes it.
func (s *Store) FailLifecycleRun(runID string, failure contracts.RunFailure, requeue bool) error {
	failureJSON, err := json.Marshal(failure)
	if err != nil {
		return storeError("encode-lifecycle-failure", err)
	}
	status, phase := "failed", "failed"
	if requeue {
		status, phase = "queued", "queued"
	}
	now := nowText()
	var completedAt any
	if !requeue {
		completedAt = now
	}
	_, err = s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET status = ?, failure_json = ?, progress_phase = ?, progress_message = ?,
		    worker_id = NULL, lease_expires_at = NULL, updated_at = ?, completed_at = ?
		WHERE run_id = ?`,
		status, string(failureJSON), phase, failure.Detail, now, completedAt, runID)
	if err != nil {
		return storeError("fail-lifecycle-run", err)
	}
	return nil
}

// RequestCancellation marks a run for idempotent cancellation. A run that has
// already completed keeps its completion: the result may already be published.
func (s *Store) RequestCancellation(runID string) (*LifecycleRun, error) {
	run, err := s.GetLifecycleRun(runID)
	if err != nil || run == nil {
		return run, err
	}
	if run.Status == "completed" || run.Status == "failed" || run.Status == "canceled" {
		return run, nil
	}
	now := nowText()
	if _, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET cancel_requested = 1, status = 'canceled', progress_phase = 'canceled',
		    progress_message = 'Run canceled before completion.', worker_id = NULL,
		    lease_expires_at = NULL, updated_at = ?, completed_at = ?
		WHERE run_id = ? AND status IN ('queued', 'running')`, now, now, runID); err != nil {
		return nil, storeError("cancel-lifecycle-run", err)
	}
	return s.GetLifecycleRun(runID)
}

// NormalizedRequestDigest is a stable digest over the semantic request body,
// excluding the idempotency key, so an identical retry is recognized and
// changed input under the same key is refused.
func NormalizedRequestDigest(envelope contracts.InvokeRequestEnvelope) string {
	copied := envelope
	copied.IdempotencyKey = nil
	return store.CanonicalRequestHash(copied)
}

func parseTimeValue(text string) contracts.Time {
	for _, layout := range []string{timeLayout, time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return contracts.Time{Time: parsed.UTC()}
		}
	}
	return contracts.Time{Time: time.Time{}}
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
