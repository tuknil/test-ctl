package storetest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

// The fake warehouse is registered as a database/sql driver rather than
// standing in for an interface of ours. Tests therefore exercise the real
// database/sql path -- argument conversion, row scanning, NULL handling -- and
// the code under test holds a plain *sql.DB, exactly as it does in production.

const driverName = "storetest-databricks"

var (
	registerOnce sync.Once
	registryMu   sync.Mutex
	registry     = map[string]*FakeWorkspace{}
	nextID       int
)

func register(workspace *FakeWorkspace) string {
	registerOnce.Do(func() { sql.Register(driverName, fakeDriver{}) })
	registryMu.Lock()
	defer registryMu.Unlock()
	nextID++
	name := fmt.Sprintf("workspace-%d", nextID)
	registry[name] = workspace
	return name
}

// DB opens a *sql.DB backed by this workspace.
func (f *FakeWorkspace) DB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, f.name)
	if err != nil {
		t.Fatalf("unable to open the fake warehouse: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type fakeDriver struct{}

func (fakeDriver) Open(name string) (driver.Conn, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	workspace, ok := registry[name]
	if !ok {
		return nil, errors.New("storetest: unknown workspace " + name)
	}
	return &fakeConn{workspace: workspace}, nil
}

type fakeConn struct{ workspace *FakeWorkspace }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	// Everything goes through QueryContext/ExecContext.
	return nil, errors.New("storetest: prepared statements are not used")
}

func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("storetest: no transactions") }

// Ping backs db.PingContext, which is the readiness probe.
func (c *fakeConn) Ping(context.Context) error { return c.workspace.ping() }

func (c *fakeConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	if _, err := c.workspace.execute(query, values(args)); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

func (c *fakeConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	rows, err := c.workspace.execute(query, values(args))
	if err != nil {
		return nil, err
	}
	return &fakeRows{rows: rows}, nil
}

// values flattens driver arguments into the strings the workspace records.
// The driver has already converted them, so this is where an int bound as a
// page bound and a string bound as a row key look the same.
func values(args []driver.NamedValue) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg.Value == nil {
			out = append(out, "")
			continue
		}
		out = append(out, fmt.Sprintf("%v", arg.Value))
	}
	return out
}

type fakeRows struct {
	rows  [][]*string
	index int
}

// Columns are positional: the code under test scans by position, and naming
// them here would assert nothing the statements do not already fix.
func (r *fakeRows) Columns() []string {
	width := 0
	for _, row := range r.rows {
		if len(row) > width {
			width = len(row)
		}
	}
	names := make([]string, width)
	for index := range names {
		names[index] = fmt.Sprintf("c%d", index)
	}
	return names
}

func (r *fakeRows) Close() error { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.index]
	r.index++
	for index := range dest {
		if index < len(row) && row[index] != nil {
			dest[index] = *row[index]
			continue
		}
		// A NULL column, which the caller must be able to tell from "".
		dest[index] = nil
	}
	return nil
}
