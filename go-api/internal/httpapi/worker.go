package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ATT-CSO/control-translation/go-api/internal/capability"
	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

// Worker drains queued lifecycle runs.
//
// It claims work under a durable lease, heartbeats while translation is
// active, and reclaims leases that expired because a previous process died.
// WORKER_MAX_ATTEMPTS bounds that recovery so a run that fails repeatedly ends
// as a terminal failure rather than cycling forever.
//
// Order matters on completion: the immutable result is written to Databricks
// first, and only then is the queue row marked complete. A crash between the
// two leaves the run claimable again, and the results write is a MERGE keyed
// on result_id, so the retry cannot produce a duplicate row.
//
// One writer only: the service is pinned to a single replica while the queue
// is a local SQLite file.
type Worker struct {
	settings   config.Settings
	repository *store.Repository
	resolver   upstream.Resolver
	queue      *lifecycle.Store
	workerID   string

	signal chan struct{}
	done   chan struct{}
	stop   chan struct{}
	once   sync.Once
}

// NewWorker builds the background lifecycle worker.
func NewWorker(
	settings config.Settings,
	repository *store.Repository,
	resolver upstream.Resolver,
	queue *lifecycle.Store,
) *Worker {
	return &Worker{
		settings:   settings,
		repository: repository,
		resolver:   resolver,
		queue:      queue,
		workerID:   "go-api:" + uuid.NewString(),
		signal:     make(chan struct{}, 1),
		done:       make(chan struct{}),
		stop:       make(chan struct{}),
	}
}

// Start begins the polling loop.
func (w *Worker) Start() { go w.run() }

// Signal wakes the worker after a submission, so a queued run is not left
// waiting for the next poll tick.
func (w *Worker) Signal() {
	select {
	case w.signal <- struct{}{}:
	default:
	}
}

// Stop asks the worker to finish within the configured grace period.
func (w *Worker) Stop() {
	w.once.Do(func() { close(w.stop) })
	select {
	case <-w.done:
	case <-time.After(time.Duration(w.settings.WorkerShutdownGraceSeconds * float64(time.Second))):
		slog.Warn("lifecycle worker did not drain within the shutdown grace period")
	}
}

func (w *Worker) run() {
	defer close(w.done)
	interval := time.Duration(w.settings.WorkerPollSeconds * float64(time.Second))
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for w.processOne() {
			select {
			case <-w.stop:
				return
			default:
			}
		}
		select {
		case <-w.stop:
			return
		case <-w.signal:
		case <-ticker.C:
		}
	}
}

// processOne claims and settles at most one run. It reports whether work was
// found, so the loop drains a backlog before sleeping again.
func (w *Worker) processOne() bool {
	run, err := w.queue.ClaimNextQueuedRun(
		w.workerID, w.settings.WorkerLeaseSeconds, w.settings.WorkerMaxAttempts)
	if err != nil {
		slog.Error("failed to claim a queued run", "error", err)
		return false
	}
	if run == nil {
		return false
	}
	slog.Info("lifecycle run claimed",
		"run_id", run.RunID, "correlation_id", run.CorrelationID, "attempt", run.Attempt)

	heartbeatDone := make(chan struct{})
	go w.heartbeat(run.RunID, heartbeatDone)
	result := capability.InvokeEnvelope(run.Request, w.resolver,
		capability.Options{Settings: w.settings})
	close(heartbeatDone)

	// A cancellation requested while the translation ran still wins here: no
	// result has been published anywhere yet.
	if current, err := w.queue.GetLifecycleRun(run.RunID); err == nil &&
		current != nil && current.CancelRequested {
		slog.Info("lifecycle run canceled before publication", "run_id", run.RunID)
		return true
	}

	// Databricks first, queue second. A crash between them re-runs the
	// translation; the MERGE on result_id keeps that idempotent.
	if err := w.repository.SaveCompletedRun(
		run.Request, result, store.CanonicalRequestHash(run.Request), run.CreatedAt,
	); err != nil {
		slog.Error("failed to publish the immutable result",
			"run_id", run.RunID, "error", err)
		retryable := run.Attempt < w.settings.WorkerMaxAttempts
		if failErr := w.queue.FailLifecycleRun(run.RunID, contracts.RunFailure{
			Code:      "storage_unavailable",
			Detail:    "Durable result storage is unavailable.",
			Retryable: retryable,
		}, retryable); failErr != nil {
			slog.Error("failed to record the lifecycle failure",
				"run_id", run.RunID, "error", failErr)
		}
		return true
	}

	if err := w.queue.CompleteLifecycleRun(run.RunID, w.workerID,
		string(result.TerminalState), result.ResultID,
		canonicalCompletion(*run, result)); err != nil {
		// The result is already durable; the queue row will be reclaimed and
		// the republish is idempotent.
		slog.Error("result published but the queue row was not finalized",
			"run_id", run.RunID, "result_id", result.ResultID, "error", err)
		return true
	}
	slog.Info("lifecycle run completed",
		"run_id", run.RunID, "result_id", result.ResultID,
		"terminal_state", string(result.TerminalState))
	return true
}

// canonicalCompletion is the compact completion orchestration consumes: where
// the immutable result is, its digest, and its size, rather than the result.
func canonicalCompletion(
	run lifecycle.LifecycleRun, result contracts.ResultEnvelope,
) contracts.CanonicalCompletion {
	canonical, _ := json.Marshal(result.StructuredResult)
	digest := sha256.Sum256(canonical)
	evidence := []string{}
	for _, binding := range result.StructuredResult.EvidenceBindings {
		evidence = append(evidence, binding.EvidenceRefs...)
	}
	return contracts.CanonicalCompletion{
		Capability:    "control-translation",
		ContractID:    "capability-completion@1.0",
		RequestID:     run.RequestID,
		CorrelationID: run.CorrelationID,
		RunID:         run.RunID,
		ResultID:      result.ResultID,
		Status:        "completed",
		TerminalState: string(result.TerminalState),
		ResultRef:     resultReference(result),
		EvidenceRefs:  evidence,
		ContentSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		SizeBytes:     len(canonical),
		CreatedAt:     contracts.Now(),
	}
}

// resultReference points at the row the result was written to.
func resultReference(result contracts.ResultEnvelope) contracts.DatabricksResultReference {
	reference := contracts.DatabricksResultReference{
		System: "control-translation", Catalog: "-", SchemaName: "-",
		Table: "-", Key: result.ResultID,
	}
	if result.UpstreamResultRefs != nil {
		reference.System = "databricks"
		reference.Catalog = result.UpstreamResultRefs.DefenseGeneration.Catalog
		reference.SchemaName = "control_translation"
		reference.Table = "control_translation_results"
	}
	return reference
}

func (w *Worker) heartbeat(runID string, done <-chan struct{}) {
	interval := time.Duration(w.settings.WorkerHeartbeatSeconds * float64(time.Second))
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := w.queue.Heartbeat(runID, w.workerID, w.settings.WorkerLeaseSeconds); err != nil {
				slog.Warn("lifecycle heartbeat failed", "run_id", runID, "error", err)
			}
		}
	}
}
