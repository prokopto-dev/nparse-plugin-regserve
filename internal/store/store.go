// Package store is the only holder of *sql.DB in this repository. Gate SQL001 enforces that.
//
// The rule is not tidiness. Once a second package can open a connection, "does this run in a
// transaction" stops being answerable by reading one file and becomes a search — and the answer
// matters here, because the rows in this database are the only thing standing between a plugin's
// users and somebody else shipping them an update.
//
// Two pools, per ADR-0001:
//
//   - The WRITER is a single connection with _txlock=immediate. SQLite has exactly one writer, and
//     pretending otherwise produces SQLITE_BUSY under load rather than throughput. Taking the
//     write lock at BEGIN rather than at the first write means a busy database blocks at a point
//     where the busy timeout applies, instead of failing mid-transaction with "database is locked"
//     — which is the deferred-transaction upgrade deadlock, and it is not retryable in place.
//   - The READER is sized max(4, NumCPU) and is opened query_only, so a read path physically
//     cannot write. In WAL mode readers never block the writer and the writer never blocks them.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strings"

	// The driver is registered as "sqlite". Pure Go and CGO-free, which is what makes the
	// FROM scratch image and one-builder cross-compilation possible (ADR-0001).
	_ "modernc.org/sqlite"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Queries is the typed query set. Callers get one of these and never a *sql.Tx or a *sql.DB:
// handing out a transaction handle would let a caller commit, roll back, or start a nested one,
// and none of those are decisions that belong outside this package.
type Queries = sqlitegen.Queries

// ErrNoRows is what a :one query returns when nothing matched.
//
// It is database/sql's own sentinel, re-exported so a caller can test for it without importing
// database/sql — which gate SQL001 forbids outside this package, and rightly: "there is no such
// row" is a fact about the data, and a package that has to import the driver stack to ask it will
// end up importing the driver stack for other reasons too.
var ErrNoRows = sql.ErrNoRows

// ErrNoPath is returned by Open when no database path was configured. It is a distinct error
// because "the operator did not configure a database" and "the database is broken" call for
// different responses from the operator and read identically in a log otherwise.
var ErrNoPath = errors.New("no database path configured")

// FileMode is the permission the database file is held at.
//
// It is the entire credential corpus: PAT hashes, OAuth subjects, session records and every
// publisher's identity. 0600 is what ADR-0001 commits to, and Open enforces it rather than hoping
// for a umask.
const FileMode fs.FileMode = 0o600

// minReaderConns is the floor under max(4, NumCPU). A one-core VPS still serves several concurrent
// index reads, and four idle SQLite connections cost a few kilobytes.
const minReaderConns = 4

// busyTimeoutMillis is how long a statement waits for a lock before giving up.
//
// Five seconds is far longer than any transaction here should take. It exists for the one case
// that is not about contention: a WAL checkpoint or a backup holding the file briefly. A shorter
// value turns that into a failed publish; a longer one turns a genuine deadlock into a hung
// request.
const busyTimeoutMillis = 5000

// DB is an open database. It is safe for concurrent use.
type DB struct {
	writer *sql.DB
	reader *sql.DB
	path   string
}

// Config is the only argument to Open.
type Config struct {
	// Path is the database file. It is created if it does not exist.
	Path string

	// ReaderConns overrides the reader pool size. Zero means max(4, NumCPU).
	ReaderConns int
}

// Open opens both pools and verifies each one answers.
//
// It does NOT migrate: applying a schema change is a separate, louder decision than opening a file,
// and the caller has to be able to tell an unopenable database (log it, serve anyway, report it on
// /readyz) from a failed migration (fatal — canonical §11).
func Open(ctx context.Context, cfg Config) (*DB, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, ErrNoPath
	}
	if err := ensureFile(ctx, cfg.Path); err != nil {
		return nil, err
	}

	readers := cfg.ReaderConns
	if readers <= 0 {
		readers = max(minReaderConns, runtime.NumCPU())
	}

	writer, err := sql.Open("sqlite", writerDSN(cfg.Path))
	if err != nil {
		return nil, fmt.Errorf("open writer pool for %s: %w", cfg.Path, err)
	}
	// Exactly one connection, and it never expires. Two writers to one SQLite file is the
	// situation the whole design assumes cannot happen; the pool is where that is enforced.
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	writer.SetConnMaxLifetime(0)

	if err := writer.PingContext(ctx); err != nil {
		_ = writer.Close() // the pool is already unusable; the ping error is the one worth reporting
		return nil, fmt.Errorf("open writer pool for %s: %w", cfg.Path, err)
	}

	reader, err := sql.Open("sqlite", readerDSN(cfg.Path))
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("open reader pool for %s: %w", cfg.Path, err)
	}
	reader.SetMaxOpenConns(readers)
	reader.SetMaxIdleConns(readers)
	reader.SetConnMaxLifetime(0)

	if err := reader.PingContext(ctx); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, fmt.Errorf("open reader pool for %s: %w", cfg.Path, err)
	}

	slog.DebugContext(ctx, "database opened", "path", cfg.Path, "reader_conns", readers)
	return &DB{writer: writer, reader: reader, path: cfg.Path}, nil
}

// Path returns the file this database was opened from. It is for logs and for the migrate command,
// never for a response body: an unauthenticated caller has no business learning the container's
// filesystem layout.
func (d *DB) Path() string { return d.path }

// Close closes both pools.
func (d *DB) Close() error {
	// Both are closed even if the first fails, and both errors are reported. Returning early would
	// leak the second pool's connections on the path where something is already wrong.
	return errors.Join(d.reader.Close(), d.writer.Close())
}

// Read returns a query set bound to the reader pool.
//
// The connections behind it are query_only, so a write reaching this path fails with a SQLite
// error rather than silently taking the write lock the writer pool is supposed to own.
func (d *DB) Read() *Queries { return sqlitegen.New(d.reader) }

// Tx runs fn inside one immediate transaction on the writer, and commits only if fn returns nil.
//
// The callback gets a *Queries, never the transaction: a caller holding a *sql.Tx can commit half
// a change, and every mutation in this service is a set of rows that are only correct together — a
// release row and the audit row that records who put it there, for one.
func (d *DB) Tx(ctx context.Context, fn func(q *Queries) error) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// A waiver, not an oversight: after a successful Commit this returns sql.ErrTxDone, and on
	// every other path the rollback error is less informative than the error that caused it.
	defer func() { _ = tx.Rollback() }()

	if err := fn(sqlitegen.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// Ping checks that both pools still answer.
//
// Both, not one: a reader that answers while the writer is gone is a service that serves the
// catalogue and cannot accept a publish, and reporting that as ready would hide it until somebody
// tried to release a plugin.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.reader.PingContext(ctx); err != nil {
		return fmt.Errorf("ping the reader pool: %w", err)
	}
	if err := d.writer.PingContext(ctx); err != nil {
		return fmt.Errorf("ping the writer pool: %w", err)
	}
	return nil
}

// ensureFile creates the database file at FileMode if it is absent, and tightens it if it is
// present and too permissive.
//
// SQLite would create the file itself on first use, at 0666 minus the umask — which on a default
// umask is world-readable. The file holds every PAT hash in the system, so the permission is not
// left to the environment. An existing file that is loose is fixed and the fix is logged: silently
// widening is a vulnerability, and silently narrowing is a surprise, so it says so out loud.
func ensureFile(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		f, cerr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, FileMode) // #nosec G304 -- operator-supplied path
		if cerr != nil {
			return fmt.Errorf("create database file %s: %w", path, cerr)
		}
		if cerr := f.Close(); cerr != nil {
			return fmt.Errorf("create database file %s: %w", path, cerr)
		}
		return nil
	case err != nil:
		return fmt.Errorf("stat database file %s: %w", path, err)
	}

	if perm := info.Mode().Perm(); perm != FileMode {
		slog.WarnContext(ctx, "database file permissions tightened",
			"path", path, "was", perm.String(), "now", FileMode.String())
		if err := os.Chmod(path, FileMode); err != nil {
			return fmt.Errorf("tighten permissions on %s: %w", path, err)
		}
	}
	return nil
}

// writerDSN builds the writer connection string.
func writerDSN(path string) string {
	q := url.Values{}
	// Applied before anything else by the driver, so a statement that meets a lock waits rather
	// than failing instantly.
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMillis))
	// WAL is what lets readers run while a publish is in flight. It is a persistent property of
	// the file; setting it here means a database restored from a backup taken in another mode is
	// converted on the first open rather than serving slowly for a week before anybody notices.
	q.Add("_pragma", "journal_mode(WAL)")
	// NORMAL is the documented companion to WAL: a commit is durable across a process crash, and
	// only a power loss can cost the last transactions. FULL fsyncs every commit for a workload
	// that publishes a few times a week.
	q.Add("_pragma", "synchronous(NORMAL)")
	// Foreign keys are OFF by default in SQLite — per connection, every connection, forever. Every
	// reference in db/schema.hcl is unenforced without this.
	q.Add("_pragma", "foreign_keys(ON)")
	// BEGIN IMMEDIATE. See the package comment: the alternative fails mid-transaction under
	// contention, at a point where retrying means redoing work the caller has already done.
	q.Set("_txlock", "immediate")
	return "file:" + path + "?" + q.Encode()
}

// readerDSN builds the reader connection string.
func readerDSN(path string) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMillis))
	q.Add("_pragma", "foreign_keys(ON)")
	// A read connection that cannot write. This is belt and braces over the type system: Read()
	// hands back a *Queries whose write methods would still compile, and this is what makes such a
	// call an error instead of a second writer.
	q.Add("_pragma", "query_only(1)")
	// journal_mode is deliberately NOT set here. Setting it is a write to the database header, and
	// a reader that has to write before it can read is a reader that fails on a read-only replica
	// or against a database another process is checkpointing. The writer owns the file's mode.
	return "file:" + path + "?" + q.Encode()
}
