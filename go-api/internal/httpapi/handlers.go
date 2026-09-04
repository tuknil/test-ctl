package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ATT-CSO/control-translation/go-api/internal/adapters"
	"github.com/ATT-CSO/control-translation/go-api/internal/capability"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/terminal"
)

func (s *Server) serviceDescriptor(w http.ResponseWriter, _ *http.Request) {
	var docs any
	if s.settings.EnableDocs {
		docs = "/docs"
	}
	writeJSON(w, http.StatusOK, jsonx.Obj{}.
		Set("service", "control-translation").
		Set("contract_id", "control-translation@1.0").
		Set("role", "api").
		Set("docs", docs).
		Set("endpoints", []string{
			"/health", "/ready", "/inference", "/schema", "/invoke",
			"/v1/control-translation-runs",
		}))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readiness(w http.ResponseWriter, _ *http.Request) {
	if errs := s.settings.ConfigurationErrors(); len(errs) > 0 {
		writeDetail(w, http.StatusServiceUnavailable, map[string]any{
			"status":               "not-ready",
			"configuration_errors": errs,
		})
		return
	}
	if !s.repository.Healthcheck() {
		slog.Error("readiness storage healthcheck failed",
			"backend", "databricks")
		writeDetail(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not-ready", "storage": "unavailable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// inferenceStatus is safe and browser-consumable: it never returns secrets.
func (s *Server) inferencePayload() jsonx.Obj {
	mode := "fixture"
	if s.settings.IsLive() {
		mode = "live"
	}
	return jsonx.Obj{}.
		Set("execution_mode", mode).
		Set("provider", s.settings.ModelProvider).
		Set("model", s.settings.ModelName).
		Set("credentials_configured", s.settings.CredentialsConfigured()).
		Set("switching_requires_restart", true)
}

func (s *Server) inferenceStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.inferencePayload())
}

func (s *Server) schema(w http.ResponseWriter, _ *http.Request) {
	supported := jsonx.Obj{}
	for _, adapter := range adapters.Registry() {
		supported = supported.Set(adapter.TargetTechnology(), jsonx.Obj{}.
			Set("artifact_type", adapter.ArtifactType()).
			Set("mode", "fixture-backed (no live policy/API integration yet)"))
	}
	states := make([]string, 0, len(terminal.DeclaredStates))
	for _, state := range terminal.DeclaredStates {
		states = append(states, string(state))
	}
	writeJSON(w, http.StatusOK, jsonx.Obj{}.
		Set("capability", "control-translation").
		// The advertised fields are the fields this build actually accepts;
		// anything else is a 422, so the document must not overstate them.
		Set("request_model_fields", []string{
			"contract_id", "input", "subject", "upstream_inputs", "routing_context",
			"upstream_result_refs", "routing_metadata", "request_id", "correlation_id",
			"idempotency_key", "subject_record_revision_id", "provenance",
		}).
		Set("response_model_fields", []string{
			"capability", "contract_id", "run_id", "result_id", "status", "terminal_state",
			"request_id", "correlation_id", "result_ref", "upstream_result_refs",
			"structured_result", "prose", "reference_bundle", "provenance", "confidence",
			"warnings", "trace", "inference",
		}).
		Set("terminal_states", states).
		Set("run_mode", s.settings.RunMode).
		Set("persistence", "databricks").
		Set("lifecycle_coordination", "sqlite").
		Set("inference", s.inferencePayload()).
		Set("supported_adapters", supported).
		Set("execution_paths", []string{"deterministic-modsec-rule"}).
		Set("schema_files", jsonx.Obj{}.
			Set("request", "schemas/request.schema.json").
			Set("result", "schemas/result.schema.json")))
}

// decodeEnvelope reads and validates the request body. Unknown fields are
// rejected, matching the Python models' extra="forbid".
func decodeEnvelope(r *http.Request) (contracts.InvokeRequestEnvelope, error) {
	var envelope contracts.InvokeRequestEnvelope
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, err
	}
	if err := envelope.Validate(); err != nil {
		return envelope, err
	}
	return envelope, nil
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request) {
	envelope, err := decodeEnvelope(r)
	if err != nil {
		writeDetail(w, http.StatusUnprocessableEntity, []map[string]any{{
			"loc": []string{"body"}, "msg": err.Error(), "type": "value_error",
		}})
		return
	}
	if envelope.RequestID == nil {
		generated := uuid.NewString()
		envelope.RequestID = &generated
	}
	if envelope.CorrelationID == nil {
		generated := uuid.NewString()
		envelope.CorrelationID = &generated
	}
	requestHash := store.CanonicalRequestHash(envelope)
	slog.Info("invocation accepted",
		"request_id", *envelope.RequestID, "correlation_id", *envelope.CorrelationID,
		"idempotency_key_present", envelope.IdempotencyKey != nil, "request_hash", requestHash)

	if envelope.IdempotencyKey != nil {
		existing, err := s.repository.GetByIdempotencyKey(*envelope.IdempotencyKey)
		if err != nil {
			s.storageUnavailable(w, "get-by-idempotency-key", err, envelope)
			return
		}
		if existing != nil {
			if existing.RequestHash != requestHash {
				slog.Warn("invocation idempotency conflict",
					"request_id", *envelope.RequestID, "correlation_id", *envelope.CorrelationID)
				writeDetail(w, http.StatusConflict,
					"Idempotency key was already used for a different request.")
				return
			}
			writeJSON(w, http.StatusOK, existing.Result)
			return
		}
	}

	startedAt := time.Now().UTC()
	result := capability.InvokeEnvelope(envelope, s.resolver, capability.Options{Settings: s.settings})
	if err := s.repository.SaveCompletedRun(envelope, result, requestHash, startedAt); err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) && envelope.IdempotencyKey != nil {
			// A simultaneous retry committed the same key first.
			if existing, lookupErr := s.repository.GetByIdempotencyKey(*envelope.IdempotencyKey); lookupErr == nil &&
				existing != nil && existing.RequestHash == requestHash {
				writeJSON(w, http.StatusOK, existing.Result)
				return
			}
		}
		s.storageUnavailable(w, "save-completed-run", err, envelope)
		return
	}
	slog.Info("invocation durably persisted",
		"request_id", *envelope.RequestID, "correlation_id", result.CorrelationID,
		"run_id", result.RunID, "result_id", result.ResultID,
		"backend", "databricks")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	envelope, err := s.repository.GetRun(runID)
	if err != nil {
		s.storageDiagnostic(w, "get-run", err, map[string]any{"run_id": runID})
		return
	}
	if envelope == nil {
		writeDetail(w, http.StatusNotFound, "Run '"+runID+"' not found.")
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

func (s *Server) getResult(w http.ResponseWriter, r *http.Request) {
	resultID := r.PathValue("result_id")
	envelope, err := s.repository.GetResult(resultID)
	if err != nil {
		s.storageDiagnostic(w, "get-result", err, map[string]any{"result_id": resultID})
		return
	}
	if envelope == nil {
		writeDetail(w, http.StatusNotFound, "Result '"+resultID+"' not found.")
		return
	}
	writeJSON(w, http.StatusOK, envelope.StructuredResult)
}

// listRuns returns safe run metadata for the dashboard using bounded pagination.
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedQuery(r, "limit", 25, 1, 100)
	if err != nil {
		writeDetail(w, http.StatusUnprocessableEntity, []map[string]any{{
			"loc": []string{"query", "limit"}, "msg": err.Error(), "type": "value_error",
		}})
		return
	}
	offset, err := boundedQuery(r, "offset", 0, 0, 1<<31-1)
	if err != nil {
		writeDetail(w, http.StatusUnprocessableEntity, []map[string]any{{
			"loc": []string{"query", "offset"}, "msg": err.Error(), "type": "value_error",
		}})
		return
	}
	page, err := s.repository.ListRuns(limit, offset)
	if err != nil {
		s.storageDiagnostic(w, "list-runs", err, nil)
		return
	}
	writeJSON(w, http.StatusOK, contracts.RunListResponse{
		Items:               page.Items,
		Total:               page.Total,
		Limit:               limit,
		Offset:              offset,
		HasMore:             offset+len(page.Items) < page.Total,
		TerminalStateCounts: page.TerminalStateCounts,
	})
}

func boundedQuery(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("Input should be a valid integer")
	}
	if value < minimum {
		return 0, errors.New("Input should be greater than or equal to " + strconv.Itoa(minimum))
	}
	if value > maximum {
		return 0, errors.New("Input should be less than or equal to " + strconv.Itoa(maximum))
	}
	return value, nil
}

// storageUnavailable logs the cause and returns sanitized diagnostics: full
// error detail stays in server logs, never in the response.
func (s *Server) storageUnavailable(
	w http.ResponseWriter, operation string, err error, envelope contracts.InvokeRequestEnvelope,
) {
	diagnostic := map[string]any{}
	if envelope.RequestID != nil {
		diagnostic["request_id"] = *envelope.RequestID
	}
	if envelope.CorrelationID != nil {
		diagnostic["correlation_id"] = *envelope.CorrelationID
	}
	s.storageDiagnostic(w, operation, err, diagnostic)
}

func (s *Server) storageDiagnostic(
	w http.ResponseWriter, operation string, err error, extra map[string]any,
) {
	slog.Error("durable storage operation failed", "operation", operation, "error", err)
	diagnostic := map[string]any{
		"operation":      operation,
		"backend":        "databricks",
		"request_id":     nil,
		"correlation_id": nil,
		"run_id":         nil,
		"result_id":      nil,
		"error_type":     "RuntimeError",
		"error":          "Root-cause details are available only in server logs.",
	}
	for key, value := range extra {
		diagnostic[key] = value
	}
	writeDetail(w, http.StatusServiceUnavailable, map[string]any{
		"code":       "storage_unavailable",
		"detail":     "Durable result storage is unavailable.",
		"message":    "Durable result storage is unavailable.",
		"retryable":  true,
		"diagnostic": diagnostic,
	})
}
