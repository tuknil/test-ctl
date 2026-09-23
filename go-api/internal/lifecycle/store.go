package lifecycle

import (
	"database/sql"
	"encoding/json"
	"errors"
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

func now() time.Time { return time.Now().UTC() }

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
	timestamp := now()
	_, err = s.db.Exec(`
		INSERT INTO capability_run_lifecycle(
			run_id, request_id, correlation_id, idempotency_key, request_digest,
			request_json, status, progress_phase, progress_percent, progress_message,
			cancel_requested, attempt_number, created_at, accepted_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,'queued','queued',0,$7,FALSE,0,$8,$8,$8)`,
		runID, *envelope.RequestID, *envelope.CorrelationID, *envelope.IdempotencyKey,
		requestDigest, string(requestJSON),
		"Run accepted and queued for durable processing.", timestamp)
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
	return s.scanLifecycle(s.db.QueryRow(
		"SELECT "+lifecycleColumns+" FROM capability_run_lifecycle WHERE run_id = $1", runID))
}

// GetLifecycleRunByKey reads one lifecycle run by idempotency key.
func (s *Store) GetLifecycleRunByKey(key string) (*LifecycleRun, error) {
	return s.scanLifecycle(s.db.QueryRow(
		"SELECT "+lifecycleColumns+" FROM capability_run_lifecycle WHERE idempotency_key = $1", key))
}

// The column list is shared between the reads and the claim's RETURNING, so
// the two cannot drift into scanning different shapes.
const lifecycleColumns = `
	run_id, request_id, correlation_id, idempotency_key, request_digest,
	request_json, status, terminal_state, result_id, completion_json, failure_json,
	progress_phase, progress_percent, progress_message, cancel_requested,
	attempt_number, created_at, accepted_at, started_at, updated_at, completed_at`

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanLifecycle(row rowScanner) (*LifecycleRun, error) {
	var (
		run                     LifecycleRun
		requestJSON             []byte
		terminalState, resultID sql.NullString
		completionJSON          []byte
		failureJSON             []byte
		progressPercent         sql.NullInt64
		startedAt, completedAt  sql.NullTime
	)
	err := row.Scan(&run.RunID, &run.RequestID, &run.CorrelationID, &run.IdempotencyKey,
		&run.RequestDigest, &requestJSON, &run.Status, &terminalState, &resultID,
		&completionJSON, &failureJSON, &run.Progress.Phase, &progressPercent,
		&run.Progress.Message, &run.CancelRequested, &run.Attempt,
		&run.CreatedAt, &run.AcceptedAt, &startedAt, &run.UpdatedAt, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeError("read-lifecycle-run", err)
	}
	if err := json.Unmarshal(requestJSON, &run.Request); err != nil {
		return nil, storeError("decode-lifecycle-request", err)
	}
	// timestamptz comes back in the session time zone; the contract is UTC.
	run.CreatedAt = run.CreatedAt.UTC()
	run.AcceptedAt = run.AcceptedAt.UTC()
	run.UpdatedAt = run.UpdatedAt.UTC()
	if startedAt.Valid {
		value := startedAt.Time.UTC()
		run.StartedAt = &value
	}
	if completedAt.Valid {
		value := completedAt.Time.UTC()
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
	if len(completionJSON) > 0 {
		var completion contracts.CanonicalCompletion
		if err := json.Unmarshal(completionJSON, &completion); err != nil {
			return nil, storeError("decode-lifecycle-completion", err)
		}
		run.Completion = &completion
	}
	if len(failureJSON) > 0 {
		var failure contracts.RunFailure
		if err := json.Unmarshal(failureJSON, &failure); err != nil {
			return nil, storeError("decode-lifecycle-failure", err)
		}
		run.Failure = &failure
	}
	return &run, nil
}

// ClaimNextQueuedRun leases one queued run to a worker, or returns nil when
// the queue is empty. Expired leases are reclaimed by the same statement, so a
// crashed worker's run is picked up on the next poll.
//
// The claim is one statement. FOR UPDATE SKIP LOCKED makes concurrent pollers
// step over a row another transaction already holds instead of blocking on it
// or claiming it twice, and RETURNING hands back the row that was actually
// claimed -- so the worker never has to ask "which run did I just take?", a
// question with no safe answer once more than one replica is running.
func (s *Store) ClaimNextQueuedRun(workerID string, leaseSeconds int, maxAttempts int) (*LifecycleRun, error) {
	timestamp := now()
	leaseExpiry := timestamp.Add(time.Duration(leaseSeconds) * time.Second)

	row := s.db.QueryRow(`
		WITH claimed AS (
			-- Aliased so the RETURNING list below, which names the queue's own
			-- columns, cannot collide with the CTE's run_id.
			SELECT run_id AS claimed_run_id FROM capability_run_lifecycle
			WHERE (status = 'queued' OR (status = 'running' AND lease_expires_at < $3))
			  AND attempt_number < $4
			ORDER BY created_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE capability_run_lifecycle AS lifecycle
		SET status = 'running', worker_id = $1, lease_expires_at = $2,
		    last_heartbeat_at = $3, attempt_number = lifecycle.attempt_number + 1,
		    started_at = COALESCE(lifecycle.started_at, $3), updated_at = $3,
		    progress_phase = 'running', progress_message = 'Translation in progress.'
		FROM claimed
		WHERE lifecycle.run_id = claimed.claimed_run_id
		RETURNING `+lifecycleColumns,
		workerID, leaseExpiry, timestamp, maxAttempts)

	// scanLifecycle reports an empty queue as (nil, nil): no row was claimed.
	return s.scanLifecycle(row)
}

// Heartbeat extends a worker's lease while translation is still running.
func (s *Store) Heartbeat(runID, workerID string, leaseSeconds int) error {
	timestamp := now()
	_, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET lease_expires_at = $1, last_heartbeat_at = $2, updated_at = $2
		WHERE run_id = $3 AND worker_id = $4 AND status = 'running'`,
		timestamp.Add(time.Duration(leaseSeconds)*time.Second), timestamp, runID, workerID)
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
	timestamp := now()
	if _, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET status = 'completed', terminal_state = $1, result_id = $2,
		    completion_json = $3::jsonb, progress_phase = 'completed', progress_percent = 100,
		    progress_message = 'Translation completed.', worker_id = NULL,
		    lease_expires_at = NULL, updated_at = $4, completed_at = $4
		WHERE run_id = $5 AND worker_id = $6`,
		terminalState, resultID, string(completionJSON), timestamp, runID, workerID,
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
	timestamp := now()
	var completedAt any
	if !requeue {
		completedAt = timestamp
	}
	_, err = s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET status = $1, failure_json = $2::jsonb, progress_phase = $3, progress_message = $4,
		    worker_id = NULL, lease_expires_at = NULL, updated_at = $5, completed_at = $6
		WHERE run_id = $7`,
		status, string(failureJSON), phase, failure.Detail, timestamp, completedAt, runID)
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
	timestamp := now()
	if _, err := s.db.Exec(`
		UPDATE capability_run_lifecycle
		SET cancel_requested = TRUE, status = 'canceled', progress_phase = 'canceled',
		    progress_message = 'Run canceled before completion.', worker_id = NULL,
		    lease_expires_at = NULL, updated_at = $1, completed_at = $1
		WHERE run_id = $2 AND status IN ('queued', 'running')`, timestamp, runID); err != nil {
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
