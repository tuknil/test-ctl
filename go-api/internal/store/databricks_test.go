package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/store/storetest"
	"github.com/ATT-CSO/control-translation/go-api/internal/terminal"
)

// The results table is the system of record. These mirror the properties
// tests/test_databricks_persistence.py holds the Python writer to: the write
// is an insert-if-absent that cannot overwrite, it is verified after the fact,
// its identifiers are validated, and nothing leaks a credential.

func newRepository(t *testing.T) (*store.Repository, *storetest.FakeWorkspace) {
	t.Helper()
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	repository, err := store.New(settings, fake.DB(t))
	if err != nil {
		t.Fatalf("unable to open the store: %v", err)
	}
	return repository, fake
}

func envelope(resultID string) (contracts.InvokeRequestEnvelope, contracts.ResultEnvelope) {
	requestID := "request-1"
	request := contracts.InvokeRequestEnvelope{
		Input: contracts.ControlTranslationRequest{
			ProvenPattern: &contracts.ProvenMitigationPattern{
				ProvenPatternID: "p", VulnerabilityID: "CVE-2026-77392",
				SelectedControlClass: "waf", DiscriminatorID: "d",
				DiscriminatorDescription: "x", PatternSummary: "y",
				ProofRecordIDs: []string{"mitigation-check-result:a", "bypass-validation-result:b"},
			},
		},
		RequestID: &requestID,
	}
	result := contracts.ResultEnvelope{
		Capability: "control-translation", ContractID: "control-translation@1.0",
		RunID: "run-1", ResultID: resultID, Status: "succeeded",
		TerminalState: terminal.Translated, CorrelationID: "corr-1",
		StructuredResult: contracts.ControlTranslationResult{
			ResultID: resultID, TerminalState: terminal.Translated,
			ProducedAt: contracts.Now(),
		},
	}
	return request, result
}

// The write is a MERGE that inserts only when absent, so a retry after a crash
// cannot overwrite a result something downstream may already have consumed.
func TestSaveInsertsOnlyWhenAbsentAndVerifiesTheStoredRow(t *testing.T) {
	repository, fake := newRepository(t)
	request, result := envelope("control-translation-result:1")

	if err := repository.SaveCompletedRun(request, result, "hash-1", time.Now()); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	statement, found := fake.LastStatementMatching("MERGE INTO")
	if !found {
		t.Fatal("the write was not a MERGE")
	}
	if !strings.Contains(statement.SQL, "WHEN NOT MATCHED THEN INSERT") {
		t.Errorf("the write must be insert-if-absent: %s", statement.SQL)
	}
	if statement.Args[0] != result.ResultID {
		t.Errorf("the result id was not bound: %v", statement.Args)
	}
	if strings.Contains(statement.SQL, result.ResultID) {
		t.Errorf("the result id was concatenated into the statement: %s", statement.SQL)
	}
	// The row is read back and compared, so a silent no-op write is caught.
	if _, verified := fake.LastStatementMatching("SELECT run_id, result_sha256"); !verified {
		t.Error("the write was not verified by reading the row back")
	}

	// A repeat writes nothing new.
	if err := repository.SaveCompletedRun(request, result, "hash-1", time.Now()); err != nil {
		t.Fatalf("the idempotent repeat failed: %v", err)
	}
	if len(fake.Rows()) != 1 {
		t.Errorf("a repeat must not add a row, got %d", len(fake.Rows()))
	}
}

// A stored row whose identity does not match what was sent is surfaced, not
// assumed benign: it means something else owns that result_id.
func TestSaveRejectsAStoredRowThatDoesNotMatch(t *testing.T) {
	repository, fake := newRepository(t)
	request, result := envelope("control-translation-result:2")
	if err := repository.SaveCompletedRun(request, result, "hash-1", time.Now()); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Something else already holds this result_id with different content, so
	// the MERGE no-ops and the read-back disagrees.
	fake.OverwriteRow(result.ResultID, map[string]string{"run_id": "a-different-run"})
	_, other := envelope(result.ResultID)
	other.RunID = "run-2"

	err := repository.SaveCompletedRun(request, other, "hash-1", time.Now())

	if err == nil || !strings.Contains(err.Error(), "conflicts with stored content") {
		t.Fatalf("err = %v, want an identity conflict", err)
	}
}

// The values covered by result_sha256 and result_size_bytes are written
// alongside the row, so a later reader can detect tampering.
func TestSaveWritesIntegrityMetadata(t *testing.T) {
	repository, fake := newRepository(t)
	request, result := envelope("control-translation-result:3")

	if err := repository.SaveCompletedRun(request, result, "hash-1", time.Now()); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	row := fake.Rows()[0]
	if len(row["result_sha256"]) != 64 {
		t.Errorf("result_sha256 = %q, want a hex digest", row["result_sha256"])
	}
	if row["result_size_bytes"] == "" || row["result_size_bytes"] == "0" {
		t.Errorf("result_size_bytes = %q", row["result_size_bytes"])
	}
}

// Table coordinates become part of the statement text, so anything that is not
// a plain word is refused when the repository is built, not at query time.
func TestIdentifiersAreValidatedWhenTheRepositoryIsBuilt(t *testing.T) {
	for name, mutate := range map[string]func(*storetest.FakeWorkspace, *string){
		"catalog": func(_ *storetest.FakeWorkspace, value *string) { *value = "cat`;DROP TABLE x;--" },
	} {
		t.Run(name, func(t *testing.T) {
			fake := storetest.NewFakeWorkspace(t)
			settings := storetest.FakeSettings()
			mutate(fake, &settings.DatabricksCatalog)

			if _, err := store.New(settings, fake.DB(t)); err == nil {
				t.Fatal("a non-word identifier must be refused")
			}
		})
	}
}

// A workspace failure reaches the caller as a sanitized error. The statement
// may quote the artifact and the client holds the token; neither belongs in a
// message that surfaces over HTTP.
func TestStorageErrorsCarryNeitherCredentialNorStatement(t *testing.T) {
	repository, fake := newRepository(t)
	fake.Fail = true
	request, result := envelope("control-translation-result:4")

	err := repository.SaveCompletedRun(request, result, "hash-1", time.Now())

	if err == nil {
		t.Fatal("a failing workspace should error")
	}
	for _, forbidden := range []string{"fake-pat", "MERGE INTO", "PARSE_JSON"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("the error carried %q: %v", forbidden, err)
		}
	}
}

// The dashboard projection reads scalar paths out of the stored JSON, so
// artifact content never crosses the wire for a list.
func TestListRunsProjectsScalarsAndNeverArtifactContent(t *testing.T) {
	repository, fake := newRepository(t)
	request, result := envelope("control-translation-result:5")
	if err := repository.SaveCompletedRun(request, result, "hash-1", time.Now()); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if _, err := repository.ListRuns(25, 0); err != nil {
		t.Fatalf("list failed: %v", err)
	}

	statement, found := fake.LastStatementMatching("ORDER BY created_at DESC")
	if !found {
		t.Fatal("the list did not run")
	}
	if strings.Contains(statement.SQL, "content_ref") || strings.Contains(statement.SQL, "request_json") {
		t.Errorf("the projection selects content it should not: %s", statement.SQL)
	}
	if !strings.Contains(statement.SQL, "LIMIT ? OFFSET ?") {
		t.Errorf("the page bounds must be bound parameters: %s", statement.SQL)
	}
}

// Reads are addressed by a bound key too, not by interpolation.
func TestReadsBindTheirKey(t *testing.T) {
	repository, fake := newRepository(t)
	const hostile = "control-translation-result:1' OR '1'='1"

	if _, err := repository.GetResult(hostile); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	statement, _ := fake.LastStatementMatching("TO_JSON(completion_json)")
	if strings.Contains(statement.SQL, "OR '1'='1") {
		t.Fatalf("a hostile key reached the statement text: %s", statement.SQL)
	}
	if statement.Args[0] != hostile {
		t.Errorf("the key should be bound verbatim: %v", statement.Args)
	}
}
