package lifecycle_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle/lifecycletest"
)

// The queue coordinates asynchronous runs: which one is claimed, by whom, and
// how many attempts it has had. These run against a real Postgres, because the
// behaviour under test is the database's -- SKIP LOCKED, unique violations,
// and what a guarded UPDATE does when it matches nothing.

func text(value string) *string { return &value }

func envelope(requestID, correlationID, key string) contracts.InvokeRequestEnvelope {
	return contracts.InvokeRequestEnvelope{
		ContractID:     text("control-translation@1.0"),
		RequestID:      text(requestID),
		CorrelationID:  text(correlationID),
		IdempotencyKey: text(key),
	}
}

func queued(t *testing.T, queue *lifecycle.Store, suffix string) *lifecycle.LifecycleRun {
	t.Helper()
	request := envelope("req-"+suffix, "corr-"+suffix, "key-"+suffix)
	run, created, err := queue.CreateLifecycleRun(
		"run-"+suffix, request, lifecycle.NormalizedRequestDigest(request))
	if err != nil {
		t.Fatalf("unable to queue a run: %v", err)
	}
	if !created {
		t.Fatalf("run-%s already existed", suffix)
	}
	return run
}

func TestAQueuedRunIsClaimedAndCompleted(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	claimed, err := queue.ClaimNextQueuedRun("worker-a", 30, 3)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if claimed == nil {
		t.Fatal("a queued run was not claimed")
	}
	if claimed.RunID != "run-1" || claimed.Status != "running" || claimed.Attempt != 1 {
		t.Fatalf("unexpected claim: %+v", claimed)
	}
	// RETURNING hands back the row the statement updated, so the request it
	// carries is the one that was stored -- not a second read that could have
	// landed on a different row.
	if claimed.Request.RequestID == nil || *claimed.Request.RequestID != "req-1" {
		t.Errorf("the claim did not carry its request: %+v", claimed.Request)
	}
	if claimed.StartedAt == nil {
		t.Error("a claimed run should have a start time")
	}

	completion := contracts.CanonicalCompletion{TerminalState: "translated"}
	if err := queue.CompleteLifecycleRun(
		"run-1", "worker-a", "translated", "result:1", completion); err != nil {
		t.Fatalf("complete failed: %v", err)
	}

	final, err := queue.GetLifecycleRun("run-1")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if final.Status != "completed" || final.ResultID == nil || *final.ResultID != "result:1" {
		t.Fatalf("unexpected final run: %+v", final)
	}
	if final.Completion == nil || final.Completion.TerminalState != "translated" {
		t.Errorf("the completion did not round-trip: %+v", final.Completion)
	}
	if final.CompletedAt == nil {
		t.Error("a completed run should have a completion time")
	}
}

// An empty queue is not an error.
func TestAnEmptyQueueClaimsNothing(t *testing.T) {
	queue := lifecycletest.Queue(t)

	claimed, err := queue.ClaimNextQueuedRun("worker-a", 30, 3)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if claimed != nil {
		t.Errorf("an empty queue claimed %+v", claimed)
	}
}

// This is the property the single-replica limit used to buy. Several workers
// polling at once must never be handed the same run: FOR UPDATE SKIP LOCKED
// makes a concurrent poller step over a row another transaction holds.
func TestConcurrentWorkersNeverClaimTheSameRun(t *testing.T) {
	queue := lifecycletest.Queue(t)

	const runs = 12
	for index := 0; index < runs; index++ {
		queued(t, queue, fmt.Sprintf("%02d", index))
	}

	var (
		mutex   sync.Mutex
		claimed []string
		failed  []error
		group   sync.WaitGroup
	)
	// More workers than runs, so some come back empty-handed rather than
	// waiting -- which is the "skip" half of SKIP LOCKED.
	for worker := 0; worker < runs+4; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			run, err := queue.ClaimNextQueuedRun(fmt.Sprintf("worker-%02d", worker), 30, 3)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				failed = append(failed, err)
				return
			}
			if run != nil {
				claimed = append(claimed, run.RunID)
			}
		}(worker)
	}
	group.Wait()

	for _, err := range failed {
		t.Errorf("a concurrent claim failed: %v", err)
	}
	seen := map[string]bool{}
	for _, runID := range claimed {
		if seen[runID] {
			t.Errorf("%s was claimed twice", runID)
		}
		seen[runID] = true
	}
	if len(claimed) != runs {
		t.Errorf("claimed %d of %d runs; every queued run should be claimed exactly once",
			len(claimed), runs)
	}
}

// A worker that died holds a lease that expires. The next poll takes the run
// back rather than leaving it claimed forever.
func TestAnExpiredLeaseIsReclaimed(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	// A lease that has already expired by the time the next poll runs.
	if _, err := queue.ClaimNextQueuedRun("worker-dead", -1, 5); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}

	reclaimed, err := queue.ClaimNextQueuedRun("worker-live", 30, 5)
	if err != nil {
		t.Fatalf("reclaim failed: %v", err)
	}
	if reclaimed == nil {
		t.Fatal("an expired lease was not reclaimed")
	}
	if reclaimed.Attempt != 2 {
		t.Errorf("attempt = %d, want 2: a reclaim is another attempt", reclaimed.Attempt)
	}
}

// Recovery is bounded. A run that has burned its attempts stops coming back,
// so a poison request cannot spin forever.
func TestReclaimingStopsAtTheAttemptLimit(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	const maxAttempts = 2
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		run, err := queue.ClaimNextQueuedRun("worker-dead", -1, maxAttempts)
		if err != nil {
			t.Fatalf("claim %d failed: %v", attempt, err)
		}
		if run == nil {
			t.Fatalf("attempt %d of %d was not claimable", attempt, maxAttempts)
		}
	}

	exhausted, err := queue.ClaimNextQueuedRun("worker-live", 30, maxAttempts)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if exhausted != nil {
		t.Errorf("a run past its attempt limit was claimed again: %+v", exhausted)
	}
}

// The oldest queued run goes first.
func TestRunsAreClaimedInTheOrderTheyWereQueued(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "first")
	time.Sleep(5 * time.Millisecond)
	queued(t, queue, "second")

	claimed, err := queue.ClaimNextQueuedRun("worker-a", 30, 3)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if claimed.RunID != "run-first" {
		t.Errorf("claimed %s, want run-first", claimed.RunID)
	}
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

func TestARepeatedKeyReturnsTheExistingRun(t *testing.T) {
	queue := lifecycletest.Queue(t)
	request := envelope("req-1", "corr-1", "key-1")
	digest := lifecycle.NormalizedRequestDigest(request)

	if _, _, err := queue.CreateLifecycleRun("run-1", request, digest); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	existing, created, err := queue.CreateLifecycleRun("run-2", request, digest)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if created {
		t.Error("a repeated key created a second run")
	}
	if existing.RunID != "run-1" {
		t.Errorf("retry returned %s, want the original run-1", existing.RunID)
	}
}

// The same key with different input is a caller bug, not a retry. The digest
// covers the semantic input, so it is the request body that has to differ --
// a retry that merely carries a new request_id is still the same request.
func TestARepeatedKeyWithDifferentInputIsRefused(t *testing.T) {
	queue := lifecycletest.Queue(t)
	first := envelope("req-1", "corr-1", "key-1")
	first.Input.CurrentPolicySnapshotID = "snapshot:a"
	if _, _, err := queue.CreateLifecycleRun(
		"run-1", first, lifecycle.NormalizedRequestDigest(first)); err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	second := envelope("req-2", "corr-2", "key-1")
	second.Input.CurrentPolicySnapshotID = "snapshot:b"
	_, _, err := queue.CreateLifecycleRun("run-2", second, lifecycle.NormalizedRequestDigest(second))

	if !errors.Is(err, lifecycle.ErrIdempotencyConflict) {
		t.Errorf("err = %v, want ErrIdempotencyConflict", err)
	}
}

// The mirror of the case above: a retry whose only difference is the
// request_id is the same semantic request, and returns the original run.
func TestARetryWithANewRequestIDIsStillTheSameRun(t *testing.T) {
	queue := lifecycletest.Queue(t)
	first := envelope("req-1", "corr-1", "key-1")
	if _, _, err := queue.CreateLifecycleRun(
		"run-1", first, lifecycle.NormalizedRequestDigest(first)); err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	second := envelope("req-2", "corr-1", "key-1")
	run, created, err := queue.CreateLifecycleRun(
		"run-2", second, lifecycle.NormalizedRequestDigest(second))
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if created || run.RunID != "run-1" {
		t.Errorf("created=%v run=%s, want the original run-1", created, run.RunID)
	}
}

// The idempotency key is unique in the database, not just checked first, so
// two requests racing on the same key cannot both insert.
func TestARacingRepeatedKeyIsResolvedByTheDatabase(t *testing.T) {
	queue := lifecycletest.Queue(t)
	request := envelope("req-1", "corr-1", "key-race")
	digest := lifecycle.NormalizedRequestDigest(request)

	var (
		mutex    sync.Mutex
		creates  int
		returned = map[string]bool{}
		group    sync.WaitGroup
	)
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			run, created, err := queue.CreateLifecycleRun(
				fmt.Sprintf("run-%d", index), request, digest)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				t.Errorf("concurrent create failed: %v", err)
				return
			}
			if created {
				creates++
			}
			returned[run.RunID] = true
		}(index)
	}
	group.Wait()

	if creates != 1 {
		t.Errorf("%d creations for one idempotency key, want exactly 1", creates)
	}
	if len(returned) != 1 {
		t.Errorf("callers were given %d different runs for one key: %v", len(returned), returned)
	}
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

// A worker whose lease was reclaimed must not be able to complete the run the
// new attempt now owns -- its result is for a run that moved on.
func TestAWorkerThatLostItsLeaseCannotComplete(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	if _, err := queue.ClaimNextQueuedRun("worker-dead", -1, 5); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	if _, err := queue.ClaimNextQueuedRun("worker-live", 30, 5); err != nil {
		t.Fatalf("reclaim failed: %v", err)
	}

	err := queue.CompleteLifecycleRun("run-1", "worker-dead", "translated", "result:stale",
		contracts.CanonicalCompletion{TerminalState: "translated"})
	if err != nil {
		t.Fatalf("the guarded update should not error: %v", err)
	}

	run, err := queue.GetLifecycleRun("run-1")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if run.Status == "completed" {
		t.Error("a worker that lost its lease completed the run")
	}
	if run.ResultID != nil {
		t.Errorf("a stale worker wrote a result id: %v", *run.ResultID)
	}
}

// A heartbeat keeps a lease alive; one from a worker that does not hold the
// run changes nothing.
func TestOnlyTheHoldingWorkerCanExtendALease(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")
	if _, err := queue.ClaimNextQueuedRun("worker-a", 1, 5); err != nil {
		t.Fatalf("claim failed: %v", err)
	}

	if err := queue.Heartbeat("run-1", "worker-b", 3600); err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	// worker-b's heartbeat must not have extended worker-a's lease: the run is
	// still reclaimable once that short lease expires.
	time.Sleep(1100 * time.Millisecond)

	reclaimed, err := queue.ClaimNextQueuedRun("worker-c", 30, 5)
	if err != nil {
		t.Fatalf("reclaim failed: %v", err)
	}
	if reclaimed == nil {
		t.Error("a foreign heartbeat extended the lease")
	}
}

// ---------------------------------------------------------------------------
// Failure and cancellation
// ---------------------------------------------------------------------------

func TestARetryableFailureReturnsTheRunToTheQueue(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")
	if _, err := queue.ClaimNextQueuedRun("worker-a", 30, 5); err != nil {
		t.Fatalf("claim failed: %v", err)
	}

	failure := contracts.RunFailure{Detail: "transient upstream error"}
	if err := queue.FailLifecycleRun("run-1", failure, true); err != nil {
		t.Fatalf("fail failed: %v", err)
	}

	run, err := queue.GetLifecycleRun("run-1")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if run.Status != "queued" {
		t.Errorf("status = %s, want queued", run.Status)
	}
	if run.Failure == nil || run.Failure.Detail != "transient upstream error" {
		t.Errorf("the failure did not round-trip: %+v", run.Failure)
	}
	if run.CompletedAt != nil {
		t.Error("a requeued run is not completed")
	}
}

func TestATerminalFailureCompletesTheRun(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	if err := queue.FailLifecycleRun(
		"run-1", contracts.RunFailure{Detail: "permanent"}, false); err != nil {
		t.Fatalf("fail failed: %v", err)
	}

	run, _ := queue.GetLifecycleRun("run-1")
	if run.Status != "failed" || run.CompletedAt == nil {
		t.Errorf("unexpected run: status=%s completed_at=%v", run.Status, run.CompletedAt)
	}
}

func TestCancellationIsIdempotent(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")

	first, err := queue.RequestCancellation("run-1")
	if err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	if first.Status != "canceled" || !first.CancelRequested {
		t.Fatalf("unexpected cancel: %+v", first)
	}

	second, err := queue.RequestCancellation("run-1")
	if err != nil {
		t.Fatalf("second cancel failed: %v", err)
	}
	if second.Status != "canceled" {
		t.Errorf("a repeated cancel changed the status to %s", second.Status)
	}
}

// The result may already be published, so a late cancel does not take it back.
func TestCancellingACompletedRunKeepsItsCompletion(t *testing.T) {
	queue := lifecycletest.Queue(t)
	queued(t, queue, "1")
	if _, err := queue.ClaimNextQueuedRun("worker-a", 30, 5); err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if err := queue.CompleteLifecycleRun("run-1", "worker-a", "translated", "result:1",
		contracts.CanonicalCompletion{TerminalState: "translated"}); err != nil {
		t.Fatalf("complete failed: %v", err)
	}

	run, err := queue.RequestCancellation("run-1")
	if err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	if run.Status != "completed" || run.ResultID == nil {
		t.Errorf("a completed run was canceled: %+v", run)
	}
}

func TestAnUnknownRunIsNotAnError(t *testing.T) {
	queue := lifecycletest.Queue(t)

	run, err := queue.GetLifecycleRun("run-missing")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if run != nil {
		t.Errorf("an unknown run returned %+v", run)
	}
}

// ---------------------------------------------------------------------------
// Schema handling
// ---------------------------------------------------------------------------

// The deployed posture: a separate process owns the schema, and the service's
// principal may not hold DDL rights. A missing table has to be a clear startup
// failure rather than a permission error on CREATE TABLE.
func TestExternalMigrationModeRefusesToStartWithoutTheSchema(t *testing.T) {
	url := lifecycletest.EmptySchemaURL(t)

	_, err := lifecycle.OpenConnectionString(url, config.MigrationModeExternal)

	if !errors.Is(err, lifecycle.ErrSchemaMissing) {
		t.Fatalf("err = %v, want ErrSchemaMissing", err)
	}
	if !strings.Contains(err.Error(), "DATABASE_MIGRATION_MODE") {
		t.Errorf("the failure should name the setting that explains it: %v", err)
	}
}

// Managed mode is what a local database wants, and running it twice is safe.
func TestManagedMigrationModeCreatesTheSchemaAndIsRepeatable(t *testing.T) {
	url := lifecycletest.EmptySchemaURL(t)

	first, err := lifecycle.OpenConnectionString(url, config.MigrationModeManaged)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	_ = first.Close()

	second, err := lifecycle.OpenConnectionString(url, config.MigrationModeManaged)
	if err != nil {
		t.Fatalf("reopening an already-migrated database failed: %v", err)
	}
	defer func() { _ = second.Close() }()

	// External mode now finds what managed mode created.
	third, err := lifecycle.OpenConnectionString(url, config.MigrationModeExternal)
	if err != nil {
		t.Fatalf("external mode rejected a schema that exists: %v", err)
	}
	_ = third.Close()
}

func TestHealthcheckReportsAReachableQueue(t *testing.T) {
	queue := lifecycletest.Queue(t)

	if !queue.Healthcheck() {
		t.Error("a reachable queue reported unhealthy")
	}
}
