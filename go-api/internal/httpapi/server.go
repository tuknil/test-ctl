// Package httpapi is the HTTP surface for the control-translation capability.
//
// Endpoint paths, status codes, and response bodies mirror the Python
// service's, so the same UI can be pointed at either one.
//
// This service is API-only: the demo UI is a separate deployable that calls it
// cross-origin, so browser access requires CORS_ALLOWED_ORIGINS.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

// Server holds the process-wide dependencies for the HTTP surface.
type Server struct {
	settings   config.Settings
	repository *store.Repository
	// resolver reads the upstream rows a referenced request names. A nil
	// resolver makes those requests a typed decline, never a guess.
	resolver upstream.Resolver
	// lifecycle is the durable queue behind the asynchronous routes.
	lifecycle *lifecycle.Store
	worker    *Worker
}

// New builds the server and its background lifecycle worker.
func New(
	settings config.Settings,
	repository *store.Repository,
	resolver upstream.Resolver,
	queue *lifecycle.Store,
) *Server {
	server := &Server{
		settings: settings, repository: repository, resolver: resolver, lifecycle: queue,
	}
	server.worker = NewWorker(settings, repository, resolver, queue)
	return server
}

// Start begins background processing of queued runs.
func (s *Server) Start() { s.worker.Start() }

// Stop drains the background worker within the configured grace period.
func (s *Server) Stop() { s.worker.Stop() }

// Handler builds the router with logging and CORS applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.serviceDescriptor)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /ready", s.readiness)
	mux.HandleFunc("GET /inference", s.inferenceStatus)
	mux.HandleFunc("GET /schema", s.schema)
	mux.HandleFunc("POST /invoke", s.invoke)
	mux.HandleFunc("POST /v1/control-translation-runs", s.submitRun)
	mux.HandleFunc("GET /v1/control-translation-runs/{run_id}", s.getRunStatus)
	mux.HandleFunc("GET /v1/control-translation-runs/{run_id}/result", s.getRunResult)
	mux.HandleFunc("POST /v1/control-translation-runs/{run_id}/cancel", s.cancelRun)
	mux.HandleFunc("GET /runs/{run_id}", s.getRun)
	mux.HandleFunc("GET /v1/runs", s.listRuns)
	mux.HandleFunc("GET /v1/results/{result_id}", s.getResult)
	return s.logRequests(s.withCORS(mux))
}

// withCORS allows only the configured browser origins. Nothing here is
// credentialed: the API takes no cookies or browser auth, so credentials stay
// disallowed.
func (s *Server) withCORS(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, origin := range s.settings.CORSAllowedOrigins {
		allowed[origin] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		permitted := origin != "" && allowed[strings.TrimRight(origin, "/")]
		if permitted {
			header := w.Header()
			header.Set("Access-Control-Allow-Origin", origin)
			header.Add("Vary", "Origin")
			header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			header.Set("Access-Control-Allow-Headers", "content-type")
			header.Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			if !permitted {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs every request outcome without logging headers or query
// values.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		queryNames := make([]string, 0, len(r.URL.Query()))
		for name := range r.URL.Query() {
			queryNames = append(queryNames, name)
		}
		slog.Info("HTTP request started",
			"method", r.Method, "path", r.URL.Path, "query_names", queryNames)

		// The async submit route requires a JSON content type before anything
		// else is read, so a malformed submission never reaches the queue.
		if r.Method == http.MethodPost && r.URL.Path == "/v1/control-translation-runs" {
			mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
			if !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
				lifecycleError(w, http.StatusBadRequest, "invalid_content_type",
					"Content-Type must be application/json.")
				return
			}
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		slog.Info("HTTP request completed",
			"method", r.Method, "path", r.URL.Path, "status_code", recorder.status,
			"duration_ms", float64(time.Since(started).Microseconds())/1000)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// writeDetail matches FastAPI's HTTPException body shape.
func writeDetail(w http.ResponseWriter, status int, detail any) {
	writeJSON(w, status, map[string]any{"detail": detail})
}

// lifecycleError is the error envelope the asynchronous routes return.
func lifecycleError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{
		"code":      code,
		"detail":    detail,
		"message":   detail,
		"retryable": status == http.StatusTooManyRequests || status >= http.StatusInternalServerError,
	})
}
