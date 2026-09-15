package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
)

// submitRun persists and queues one asynchronous translation.
//
// Submission requires Idempotency-Key and X-Correlation-ID. The body
// request_id must equal the idempotency header and body correlation_id must
// equal the correlation header. An identical retry returns the same run;
// reusing the key with changed semantic input returns 409.
func (s *Server) submitRun(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	correlationID := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
	if idempotencyKey == "" || correlationID == "" {
		lifecycleError(w, http.StatusBadRequest, "missing_required_header",
			"Idempotency-Key and X-Correlation-ID headers are required.")
		return
	}
	if hasAnyHeader(r, "X-Janus-Callback-URL", "X-Janus-Callback-Workflow-ID", "X-Janus-Callback-Signal") &&
		!hasAllHeaders(r, "X-Janus-Callback-URL", "X-Janus-Callback-Workflow-ID", "X-Janus-Callback-Signal") {
		lifecycleError(w, http.StatusBadRequest, "invalid_callback_headers",
			"The callback header group must be supplied in full or not at all.")
		return
	}

	envelope, err := decodeEnvelope(r)
	if err != nil {
		lifecycleError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}
	if envelope.RequestID == nil || *envelope.RequestID != idempotencyKey {
		lifecycleError(w, http.StatusBadRequest, "request_id_mismatch",
			"Body request_id must equal the Idempotency-Key header.")
		return
	}
	if envelope.CorrelationID == nil || *envelope.CorrelationID != correlationID {
		lifecycleError(w, http.StatusBadRequest, "correlation_id_mismatch",
			"Body correlation_id must equal the X-Correlation-ID header.")
		return
	}
	if envelope.IdempotencyKey == nil {
		key := idempotencyKey
		envelope.IdempotencyKey = &key
	}
	if *envelope.IdempotencyKey != idempotencyKey {
		lifecycleError(w, http.StatusBadRequest, "idempotency_key_mismatch",
			"Body idempotency_key must equal the Idempotency-Key header.")
		return
	}

	digest := lifecycle.NormalizedRequestDigest(envelope)
	run, created, err := s.lifecycle.CreateLifecycleRun(uuid.NewString(), envelope, digest)
	if err != nil {
		if errors.Is(err, lifecycle.ErrIdempotencyConflict) {
			lifecycleError(w, http.StatusConflict, "idempotency_conflict",
				"The idempotency key was already used for different request input.")
			return
		}
		s.storageDiagnostic(w, "create-lifecycle-run", err, nil)
		return
	}
	// Status polling never starts work; the worker is signaled here instead.
	s.worker.Signal()

	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeJSON(w, status, contracts.CapabilityRunSubmission{
		Capability:    "control-translation",
		ContractID:    "control-translation-run-submission@1.0",
		RequestID:     run.RequestID,
		CorrelationID: run.CorrelationID,
		RunID:         run.RunID,
		Status:        run.Status,
		StatusURL:     "/v1/control-translation-runs/" + run.RunID,
		ResultURL:     "/v1/control-translation-runs/" + run.RunID + "/result",
		AcceptedAt:    contracts.Time{Time: run.AcceptedAt},
	})
}

func hasAnyHeader(r *http.Request, names ...string) bool {
	for _, name := range names {
		if r.Header.Get(name) != "" {
			return true
		}
	}
	return false
}

func hasAllHeaders(r *http.Request, names ...string) bool {
	for _, name := range names {
		if r.Header.Get(name) == "" {
			return false
		}
	}
	return true
}

func (s *Server) getRunStatus(w http.ResponseWriter, r *http.Request) {
	run, err := s.lifecycle.GetLifecycleRun(r.PathValue("run_id"))
	if err != nil {
		s.storageDiagnostic(w, "get-lifecycle-run", err, nil)
		return
	}
	if run == nil {
		lifecycleError(w, http.StatusNotFound, "run_not_found", "The requested run does not exist.")
		return
	}
	writeJSON(w, http.StatusOK, runStatus(*run))
}

func (s *Server) getRunResult(w http.ResponseWriter, r *http.Request) {
	run, err := s.lifecycle.GetLifecycleRun(r.PathValue("run_id"))
	if err != nil {
		s.storageDiagnostic(w, "get-lifecycle-run-result", err, nil)
		return
	}
	if run == nil {
		lifecycleError(w, http.StatusNotFound, "run_not_found", "The requested run does not exist.")
		return
	}
	if run.ResultID == nil {
		lifecycleError(w, http.StatusConflict, "result_not_ready",
			"The run has not produced an immutable result yet.")
		return
	}
	// The immutable result lives in Databricks; the queue only points at it.
	envelope, err := s.repository.GetResult(*run.ResultID)
	if err != nil {
		s.storageDiagnostic(w, "get-lifecycle-result", err, nil)
		return
	}
	if envelope == nil {
		lifecycleError(w, http.StatusConflict, "result_not_ready",
			"The run completed but its immutable result is not readable yet.")
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

// cancelRun requests idempotent cancellation. Cancellation wins before a
// result exists; afterwards the completion wins, because the result may
// already have been published downstream.
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.lifecycle.RequestCancellation(r.PathValue("run_id"))
	if err != nil {
		s.storageDiagnostic(w, "cancel-lifecycle-run", err, nil)
		return
	}
	if run == nil {
		lifecycleError(w, http.StatusNotFound, "run_not_found", "The requested run does not exist.")
		return
	}
	writeJSON(w, http.StatusAccepted, runStatus(*run))
}

func runStatus(run lifecycle.LifecycleRun) contracts.CapabilityRunStatus {
	status := contracts.CapabilityRunStatus{
		Capability:    "control-translation",
		ContractID:    "capability-run-status@1.0",
		RequestID:     run.RequestID,
		CorrelationID: run.CorrelationID,
		RunID:         run.RunID,
		Status:        run.Status,
		TerminalState: run.TerminalState,
		ResultID:      run.ResultID,
		CreatedAt:     contracts.Time{Time: run.CreatedAt},
		UpdatedAt:     contracts.Time{Time: run.UpdatedAt},
		Progress:      run.Progress,
		Failure:       run.Failure,
		Completion:    run.Completion,
	}
	if run.StartedAt != nil {
		status.StartedAt = &contracts.Time{Time: *run.StartedAt}
	}
	if run.CompletedAt != nil {
		status.CompletedAt = &contracts.Time{Time: *run.CompletedAt}
	}
	if status.Progress.Phase == "" {
		status.Progress = contracts.RunProgress{Phase: run.Status, Message: run.Status}
	}
	return status
}
