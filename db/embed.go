// Package db carries the schema and the migrations that produce it.
//
// It holds no logic and imports nothing but embed: it exists so the migrations travel inside the
// binary. The deployment target is a container built FROM scratch with no shell, no migration CLI
// and no way to copy a .sql file in, so a migration that is not embedded is a migration that
// cannot be applied (ADR-0006).
//
// db/schema.hcl is the declarative truth and is NOT embedded — nothing at runtime reads it. Atlas
// diffs it to author the files below; that is a developer's tool, not the server's.
package db

import "embed"

// MigrationsSQLite holds every SQLite migration, in the order goose applies them.
//
// Embedded by pattern rather than by name: a migration added to the directory and forgotten here
// would be a schema change that ships in the source and never runs on the database.
//
//go:embed migrations-sqlite/*.sql
var MigrationsSQLite embed.FS

// MigrationsSQLiteDir is the directory inside MigrationsSQLite. goose is handed a sub-filesystem
// rooted here, so the version numbers it reads are the file names and nothing else.
const MigrationsSQLiteDir = "migrations-sqlite"
