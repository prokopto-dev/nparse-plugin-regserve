package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/pressly/goose/v3"

	"github.com/prokopto-dev/nparse-plugin-regserve/db"
)

// ErrSchemaAhead is returned when the database has migrations this binary does not carry.
//
// It is fatal at boot, and it is the one database condition that is (canonical §11). An older
// binary against a newer schema is a rollback that skipped the snapshot restore: the columns it
// expects may be gone, the constraints it does not know about will reject its writes, and the
// failures land one request at a time rather than all at once. Refusing to start is the only
// answer that produces a legible incident.
var ErrSchemaAhead = errors.New("the database schema is newer than this binary")

// ErrNoMigrations is returned when the embedded migration set is empty, which can only mean the
// binary was built with a broken embed. It is separated from a migration failure because the fix
// is a rebuild, not a database.
var ErrNoMigrations = errors.New("no migrations are embedded in this binary")

// Migration reports one applied migration.
type Migration struct {
	Version int64
	Path    string
}

// MigrationOutcome is what Migrate did.
type MigrationOutcome struct {
	// Applied is what this call ran, in order. Empty on a database that was already current, which
	// is the normal case for a restart.
	Applied []Migration

	// Version is the schema version afterwards.
	Version int64
}

// Migrate applies every pending migration, in order, on the writer connection.
//
// Forward-only (ADR-0006): there is no Down path, and each migration's Down block aborts. Recovery
// from a bad migration is restoring the snapshot the deploy takes immediately before this runs.
func (d *DB) Migrate(ctx context.Context) (MigrationOutcome, error) {
	fsys, err := fs.Sub(db.MigrationsSQLite, db.MigrationsSQLiteDir)
	if err != nil {
		return MigrationOutcome{}, fmt.Errorf("open the embedded migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, d.writer, fsys,
		// goose logs through slog, like everything else here, so a migration at boot lands in the
		// same JSON stream an operator is already reading.
		goose.WithSlog(slog.Default()),
		// goose keeps a package-level registry that any imported package can add Go migrations to.
		// This service has none, and a migration that arrives by import is one nobody reviewed
		// against db/schema.hcl.
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return MigrationOutcome{}, fmt.Errorf("prepare migrations: %w", err)
	}

	sources := provider.ListSources()
	if len(sources) == 0 {
		return MigrationOutcome{}, ErrNoMigrations
	}
	newest := sources[len(sources)-1].Version // ListSources is sorted ascending

	current, err := provider.GetDBVersion(ctx)
	if err != nil {
		return MigrationOutcome{}, fmt.Errorf("read the schema version: %w", err)
	}
	if current > newest {
		return MigrationOutcome{}, fmt.Errorf("%w: database is at %d, this binary carries up to %d",
			ErrSchemaAhead, current, newest)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return MigrationOutcome{}, fmt.Errorf("apply migrations to %s: %w", d.path, err)
	}

	out := MigrationOutcome{Version: newest, Applied: make([]Migration, 0, len(results))}
	for _, r := range results {
		if r.Source == nil {
			continue
		}
		out.Applied = append(out.Applied, Migration{Version: r.Source.Version, Path: r.Source.Path})
	}
	return out, nil
}
