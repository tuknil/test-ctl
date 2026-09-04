// Package databricks talks to Unity Catalog through the vendor SQL driver.
//
// This mirrors the mitigation-check service (claude_mitigate/api/databricks.go),
// which opens database/sql with github.com/databricks/databricks-sql-go and a
// DSN. Using the same driver as the sibling service means protocol, auth and
// result decoding are code that already runs against a real workspace, rather
// than a bespoke client of ours that does not.
//
// Both the upstream reader and the result store share one client, so
// connection handling and parameter binding are implemented once.
package databricks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/databricks/databricks-sql-go"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// Querier is the SQL boundary. The driver-backed client satisfies it, and
// tests substitute a recorder so they can assert the statement and the bound
// arguments rather than only the behavior.
type Querier interface {
	// Query runs a statement and returns its rows. A NULL column is a nil
	// element, so callers can tell it from an empty string.
	Query(statement string, args ...any) ([][]*string, error)
	// Exec runs a statement that returns no rows.
	Exec(statement string, args ...any) error
	// Ping reports whether the warehouse is reachable.
	Ping() error
}

const (
	queryTimeout = 120 * time.Second
	pingTimeout  = 30 * time.Second
)

// Client is a driver-backed Querier.
type Client struct {
	db *sql.DB
}

// New opens the warehouse named by the DSN.
func New(settings config.Settings) (*Client, error) {
	dsn := strings.TrimSpace(settings.DatabricksDSN)
	if dsn == "" {
		return nil, errors.New("DATABRICKS_DSN is not set")
	}
	db, err := sql.Open("databricks", NormalizeDSN(dsn))
	if err != nil {
		// The driver echoes the DSN in its errors, and the DSN carries a
		// credential, so the cause is not propagated.
		return nil, errors.New("the Databricks connection could not be opened")
	}
	db.SetMaxOpenConns(4)
	return &Client{db: db}, nil
}

// Close releases the pool.
func (c *Client) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Ping implements Querier.
func (c *Client) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := c.db.PingContext(ctx); err != nil {
		return errors.New("the Databricks warehouse is unreachable")
	}
	return nil
}

// Exec implements Querier.
func (c *Client) Exec(statement string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	if _, err := c.db.ExecContext(ctx, statement, args...); err != nil {
		return sanitize(err)
	}
	return nil
}

// Query implements Querier.
func (c *Client) Query(statement string, args ...any) ([][]*string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	rows, err := c.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, sanitize(err)
	}
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		return nil, sanitize(err)
	}
	var out [][]*string
	for rows.Next() {
		cells := make([]sql.NullString, len(columns))
		targets := make([]any, len(columns))
		for index := range cells {
			targets[index] = &cells[index]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, sanitize(err)
		}
		row := make([]*string, len(cells))
		for index, cell := range cells {
			if cell.Valid {
				value := cell.String
				row[index] = &value
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, sanitize(err)
	}
	return out, nil
}

// sanitize keeps the driver's message out of anything that surfaces over HTTP.
// Driver errors quote the statement, which quotes the candidate artifact, and
// connection errors can quote the DSN, which carries the credential.
func sanitize(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("the Databricks statement timed out")
	}
	return errors.New("the Databricks statement failed")
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// QuoteTable renders a fully qualified table name.
//
// mitigation-check backticks whatever it is given. This service also validates,
// because here a catalog, schema and table can arrive from a request -- the
// upstream references -- and not only from configuration, so an identifier that
// is not a plain word is refused rather than escaped into the statement.
func QuoteTable(catalog, schema, table string) (string, error) {
	parts := []struct{ value, label string }{
		{catalog, "catalog"}, {schema, "schema"}, {table, "table"},
	}
	quoted := make([]string, 0, len(parts))
	for _, part := range parts {
		if !identifierPattern.MatchString(part.value) {
			return "", fmt.Errorf("%s is not a valid Databricks identifier", part.label)
		}
		quoted = append(quoted, backtick(part.value))
	}
	return strings.Join(quoted, "."), nil
}

// backtick quotes an identifier, doubling any backtick inside it. Validation
// already rejects those, so this is the second of two guards rather than the
// only one.
func backtick(identifier string) string {
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

// NormalizeDSN inserts :443 when the host carries no explicit port, which the
// driver requires. Taken from the mitigation-check service so one
// operator-written DSN works for both.
func NormalizeDSN(dsn string) string {
	dsn = strings.TrimPrefix(strings.TrimSpace(dsn), "databricks://")
	at := strings.Index(dsn, "@")
	if at < 0 {
		return dsn
	}
	credentials, rest := dsn[:at+1], dsn[at+1:]
	host, path := rest, ""
	if slash := strings.Index(rest, "/"); slash >= 0 {
		host, path = rest[:slash], rest[slash:]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	return credentials + host + path
}

// Text safely dereferences a nullable column value.
func Text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
