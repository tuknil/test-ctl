// Command api runs the control-translation capability API.
//
// One execution path: read the proven ModSecurity rule from the Defense
// Generation row named in the request, compile it into an Akamai custom WAF
// rule, gate it, and persist the result in Databricks. Requests arrive
// synchronously on /invoke or through the durable asynchronous lifecycle,
// whose queue is the single local SQLite file. The demo UI is a separate
// deployable; this process serves the API only.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/databricks"
	"github.com/ATT-CSO/control-translation/go-api/internal/httpapi"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	settings := config.Load()
	for _, problem := range settings.ConfigurationErrors() {
		// Readiness still fails, but an operator should see the cause at boot
		// rather than only on the first /ready probe.
		slog.Warn("configuration error", "detail", problem)
	}

	// One connection pool serves both the upstream reader and the store.
	client, err := databricks.New(settings)
	if err != nil {
		// Readiness reports the same thing, but an operator should see the
		// cause at boot rather than only on the first probe.
		slog.Error("unable to open the Databricks connection", "error", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	repository, err := store.New(settings, client)
	if err != nil {
		slog.Error("unable to initialize durable result storage", "error", err)
		os.Exit(1)
	}
	resolver := upstream.NewResolver(settings, client)
	if resolver == nil {
		slog.Warn("Databricks is not configured; referenced invocations will decline")
	}

	// The only local state: the durable queue behind the asynchronous routes.
	queue, err := lifecycle.Open(settings.DatabasePath)
	if err != nil {
		slog.Error("unable to initialize the durable lifecycle queue", "error", err)
		os.Exit(1)
	}
	defer func() { _ = queue.Close() }()

	server := httpapi.New(settings, repository, resolver, queue)
	server.Start()
	defer server.Stop()

	address := net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port))
	httpServer := &http.Server{
		Addr:              address,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("control-translation API listening",
			"address", address, "run_mode", settings.RunMode, "persistence", "databricks")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdown
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(settings.WorkerShutdownGraceSeconds*float64(time.Second))+5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
}
