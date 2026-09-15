package upstream_test

import (
	"strings"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/store/storetest"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

// The resolver reads exactly one named row from one approved table. These
// mirror the properties tests/test_upstream_databricks.py holds the Python
// reader to, at the level this service actually operates: the statement it
// sends and the parameters it binds.

func reference(key string, overrides ...func(*contracts.DatabricksResultReference)) contracts.DatabricksResultReference {
	ref := contracts.DatabricksResultReference{
		System: "databricks", Catalog: "36889_janus_dev",
		SchemaName: "bypass_validation", Table: "bypass_validation_results", Key: key,
	}
	for _, override := range overrides {
		override(&ref)
	}
	return ref
}

func newResolver(t *testing.T) (upstream.Resolver, *storetest.FakeWorkspace) {
	t.Helper()
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	return upstream.NewResolver(settings, fake.DB(t)), fake
}

// The row key is bound out of band. If it were concatenated into the statement
// a caller-supplied result_id could rewrite the query.
func TestResolverBindsTheRowKeyRatherThanConcatenatingIt(t *testing.T) {
	resolver, fake := newResolver(t)
	const key = "bypass-validation-result:1"
	fake.UpstreamRow(key, key, "no-bypass-found", "corr-1", "{}", `{"terminal_state":"no-bypass-found"}`)

	record, err := resolver.Fetch(reference(key))
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if record == nil || record.ResultID != key {
		t.Fatalf("unexpected record: %+v", record)
	}

	statement, found := fake.LastStatementMatching("bypass_validation_results")
	if !found {
		t.Fatal("the resolver sent no statement for the bypass table")
	}
	if statement.Args[0] != key {
		t.Errorf("the row key was not bound as a parameter: %v", statement.Args)
	}
	if strings.Contains(statement.SQL, key) {
		t.Errorf("the row key was concatenated into the statement: %s", statement.SQL)
	}
	// LIMIT 2 is what makes "exactly one row" detectable rather than assumed.
	if !strings.Contains(statement.SQL, "LIMIT 2") {
		t.Errorf("the statement should fetch two rows to detect ambiguity: %s", statement.SQL)
	}
}

// A key carrying SQL metacharacters must be data, not syntax.
func TestResolverIsUnaffectedByMetacharactersInTheRowKey(t *testing.T) {
	resolver, fake := newResolver(t)
	const hostile = "bypass-validation-result:1' OR '1'='1"

	if _, err := resolver.Fetch(reference(hostile)); err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	statement, _ := fake.LastStatementMatching("bypass_validation_results")
	if strings.Contains(statement.SQL, "OR '1'='1") {
		t.Fatalf("a hostile key reached the statement text: %s", statement.SQL)
	}
	if statement.Args[0] != hostile {
		t.Errorf("the key should be bound verbatim as data: %v", statement.Args)
	}
}

// The approved-table check runs before any row is read, so a reference cannot
// point the reader at a table the deployment was never authorized for.
func TestResolverRefusesUnapprovedCoordinates(t *testing.T) {
	cases := map[string]func(*contracts.DatabricksResultReference){
		"schema":  func(r *contracts.DatabricksResultReference) { r.SchemaName = "other_schema" },
		"catalog": func(r *contracts.DatabricksResultReference) { r.Catalog = "other_catalog" },
		"table":   func(r *contracts.DatabricksResultReference) { r.Table = "other_table" },
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			resolver, fake := newResolver(t)

			_, err := resolver.Fetch(reference("bypass-validation-result:1", override))

			if err == nil || !strings.Contains(err.Error(), "approved table") {
				t.Fatalf("err = %v, want an approved-table refusal", err)
			}
			if len(fake.Statements()) != 0 {
				t.Errorf("nothing should be queried before the check: %v", fake.Statements())
			}
		})
	}
}

// An identifier that is not a plain word is refused, so a reference can never
// inject SQL through the table name.
func TestResolverRefusesIdentifiersThatAreNotPlainWords(t *testing.T) {
	resolver, _ := newResolver(t)
	hostile := reference("bypass-validation-result:1", func(r *contracts.DatabricksResultReference) {
		r.Catalog = "36889_janus_dev`;DROP TABLE x;--"
	})

	if _, err := resolver.Fetch(hostile); err == nil {
		t.Fatal("a non-word identifier must be refused")
	}
}

// More than one row for a supposedly unique result_id is ambiguity, and
// ambiguity is an error rather than a pick-the-first.
func TestResolverRefusesAnAmbiguousResult(t *testing.T) {
	resolver, fake := newResolver(t)
	const key = "bypass-validation-result:1"
	fake.UpstreamRowsFor(key,
		[]string{key, "no-bypass-found", "corr-1", "{}", "{}"},
		[]string{key, "no-bypass-found", "corr-1", "{}", "{}"})

	_, err := resolver.Fetch(reference(key))

	if err == nil || !strings.Contains(err.Error(), "multiple rows") {
		t.Fatalf("err = %v, want a multiple-rows refusal", err)
	}
}

// A reference that matches nothing is not found, not an error: orchestration
// may legitimately name a row that has not landed yet.
func TestResolverReportsAMissingRowAsNotFound(t *testing.T) {
	resolver, _ := newResolver(t)

	record, err := resolver.Fetch(reference("bypass-validation-result:absent"))

	if err != nil || record != nil {
		t.Errorf("record = %v, err = %v; want (nil, nil)", record, err)
	}
}

// A row whose JSON columns are malformed is a resolution error naming the
// column, not a panic and not a silently empty record.
func TestResolverRejectsMalformedStoredJSON(t *testing.T) {
	resolver, fake := newResolver(t)
	const key = "bypass-validation-result:1"
	fake.UpstreamRow(key, key, "no-bypass-found", "corr-1", "{}", "{not json")

	_, err := resolver.Fetch(reference(key))

	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("err = %v, want a JSON refusal", err)
	}
}

// Errors reach the caller as a typed decline. They must not carry the
// workspace credential.
func TestResolverErrorsDoNotCarryTheCredential(t *testing.T) {
	resolver, _ := newResolver(t)

	_, err := resolver.Fetch(reference("bypass-validation-result:1", func(r *contracts.DatabricksResultReference) {
		r.SchemaName = "other_schema"
	}))

	if err != nil && strings.Contains(err.Error(), "fake-pat") {
		t.Errorf("the error carried the token: %v", err)
	}
}
