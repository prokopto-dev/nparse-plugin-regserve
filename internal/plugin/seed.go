package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// A seed import is how the catalogue that is live TODAY reaches the database that replaces the
// file it currently lives in.
//
// Until this release the deployed server read /opt/regserve/seed.json at boot and served it
// directly. The store-backed catalogue reads the database instead — so without an import, the
// first container running this code would come up with an empty schema and serve an index with no
// plugins to every installed client. Nothing else in the roadmap put the catalogue in the
// database: the `make seed` target is a Phase 2 tool for a developer's laptop, not a deployment
// step, and a deployment step that a human has to remember on the day is not a transition plan.
//
// The rule that makes it safe to leave the seed mounted forever: A NON-EMPTY DATABASE IS NEVER
// TOUCHED. The import runs only when there are no plugin rows at all. After the first boot the
// database is the catalogue, publishing writes to it, and the file on disk is inert.

// importReviewNote is recorded on every imported release row.
//
// It is the honest provenance of a hash this server did not compute. The static registry's hashes
// were reviewed by a human in a pull request against prokopto-dev/nparseplus-plugins, and CI
// re-downloaded and re-hashed the artifact there — which is a real check, and is not the check
// ADR-0008 describes. `source = 'import'` is the machine-readable half of the same statement.
const importReviewNote = "imported from the static registry: the hash was published and reviewed " +
	"there, not computed by this server"

// Seed is a parsed seed document and the file it came from.
type Seed struct {
	// Path is kept for the log and the audit row. It is never served.
	Path  string
	Index registry.Index
}

// ImportSkip says why an import wrote nothing. The empty value means it wrote.
type ImportSkip string

const (
	// SkipCatalogueExists is the normal case for every boot after the first.
	SkipCatalogueExists ImportSkip = "the database already holds a catalogue"

	// SkipAlreadyImported is the same statement made by the audit log rather than by the plugin
	// table. Both are checked: see the comment on ImportSeed.
	SkipAlreadyImported ImportSkip = "a seed has already been imported into this database"

	// SkipSeedEmpty is a seed that parses and lists no plugins.
	//
	// Nothing is written for one — NOT even the import marker. An empty index is a valid document,
	// so this is reachable by mistake (a truncated upstream fetch, a hand-edited file), and
	// claiming the marker would mean the operator's corrected seed silently did nothing on the
	// next boot. An import that imported nothing has not happened.
	SkipSeedEmpty ImportSkip = "the seed file lists no plugins"
)

// ImportOutcome is what ImportSeed did.
type ImportOutcome struct {
	// Plugins is how many plugins were written. Zero on every skip.
	Plugins int

	// Skip is empty when Plugins were written, and otherwise says why none were.
	Skip ImportSkip

	// Existing is how many plugins the database already held, for the log line.
	Existing int64
}

// LoadSeed reads and validates a schema-v1 index document.
//
// It validates through the same path the server serves with, so a seed that would not render is
// rejected here rather than at the first client request. The document is the same shape the
// service emits, which is what lets the live catalogue be captured with curl and replayed.
func LoadSeed(path string) (Seed, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path is an operator-supplied CLI flag
	if err != nil {
		return Seed{}, fmt.Errorf("read seed file %s: %w", path, err)
	}
	idx, err := registry.ParseIndex(raw)
	if err != nil {
		return Seed{}, fmt.Errorf("parse seed file %s: %w", path, err)
	}
	return Seed{Path: path, Index: idx}, nil
}

// ImportSeed writes seed into an EMPTY database, in one transaction.
//
// It writes nothing at all unless three things are true: the database holds no plugins, no import
// has been recorded in the audit log before, and the seed actually lists a plugin. All of it —
// the checks and the writes — shares one transaction on the single writer connection, so "empty"
// cannot become "not empty" between the check and the insert.
//
// TWO CONDITIONS FOR ONE RULE, on purpose. The plugin count answers "is there a catalogue"; the
// audit marker answers "did we already do this". They are equivalent only because nothing can
// delete a plugin row today — a BEFORE DELETE trigger sees to that — and the rule this protects is
// the one whose failure mode is a restart reverting every publish since the cutover. It should not
// rest on a trigger in another file staying where it is.
//
// Every imported release lands as approved, because it is what the live registry is serving right
// now and this is a transition, not a re-review. It lands with source = 'import' and no
// verified_at, because this server did not fetch those bytes.
func ImportSeed(ctx context.Context, db *store.DB, clk clock.Clock, seed Seed) (ImportOutcome, error) {
	// Sorting and re-validating: the file is trusted no further than any other input, and a
	// deterministic order makes the audit row and the log line reproducible.
	idx, err := registry.NewIndex(seed.Index.Plugins)
	if err != nil {
		return ImportOutcome{}, fmt.Errorf("validate seed file %s: %w", seed.Path, err)
	}

	now := core.MicrosFromTime(clk.Now())
	out := ImportOutcome{}

	err = db.Tx(ctx, func(q *store.Queries) error {
		existing, err := q.CountPlugins(ctx)
		if err != nil {
			return fmt.Errorf("count the plugins already in the database: %w", err)
		}
		imports, err := q.CountCatalogueImports(ctx)
		if err != nil {
			return fmt.Errorf("count the imports already recorded: %w", err)
		}

		// None of these is an error. Two of them are every boot after the first, and skipping
		// quietly is the property that makes leaving the seed file mounted harmless.
		out.Existing = existing
		switch {
		case existing > 0:
			out.Skip = SkipCatalogueExists
			return nil
		case imports > 0:
			out.Skip = SkipAlreadyImported
			return nil
		case len(idx.Plugins) == 0:
			out.Skip = SkipSeedEmpty
			return nil
		}

		for _, p := range idx.Plugins {
			if err := insertImported(ctx, q, clk, now, p); err != nil {
				return err
			}
		}
		out.Plugins = len(idx.Plugins)

		return recordImport(ctx, q, clk, now, seed.Path, out.Plugins)
	})
	if err != nil {
		return ImportOutcome{}, fmt.Errorf("import seed file %s: %w", seed.Path, err)
	}
	return out, nil
}

func insertImported(
	ctx context.Context, q *store.Queries, clk clock.Clock, now core.Micros, p registry.Plugin,
) error {
	if err := q.InsertPlugin(ctx, sqlitegen.InsertPluginParams{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Author:      p.Author,
		Homepage:    p.Homepage,
		ClaimedAt:   now.Int64(),
		UpdatedAt:   now.Int64(),
	}); err != nil {
		return fmt.Errorf("claim plugin id %s: %w", p.ID, err)
	}

	id, err := core.NewULID(clk.Now())
	if err != nil {
		return fmt.Errorf("mint a release id for %s: %w", p.ID, err)
	}

	sha := p.Latest.SHA256
	note := importReviewNote
	if err := q.InsertRelease(ctx, sqlitegen.InsertReleaseParams{
		ID:                id.String(),
		PluginID:          p.ID,
		Version:           p.Latest.Version,
		State:             "approved",
		Source:            "import",
		ArtifactUrl:       p.Latest.URL,
		ArtifactSha256:    &sha,
		SdkSpecifier:      p.Latest.RequiresSDK,
		MinimumAppVersion: p.Latest.MinAppVersion,
		SubmittedAt:       now.Int64(),
		ReviewNote:        &note,
	}); err != nil {
		return fmt.Errorf("record the imported release of %s: %w", p.ID, err)
	}
	return nil
}

// recordImport writes the audit row for the import.
//
// The import is a privileged, unattended write of the entire catalogue, performed by no account.
// If it is ever the wrong catalogue, this row is what says when it happened and from which file.
func recordImport(
	ctx context.Context, q *store.Queries, clk clock.Clock, now core.Micros, path string, plugins int,
) error {
	id, err := core.NewULID(clk.Now())
	if err != nil {
		return fmt.Errorf("mint an audit id: %w", err)
	}

	detail, err := json.Marshal(map[string]any{"plugins": plugins, "path": path})
	if err != nil {
		return fmt.Errorf("render the audit detail: %w", err)
	}
	detailText := string(detail)

	if err := q.InsertAuditLog(ctx, sqlitegen.InsertAuditLogParams{
		ID:          id.String(),
		RecordedAt:  now.Int64(),
		ActorKind:   "system",
		Action:      "catalogue.import",
		SubjectKind: "catalogue",
		Detail:      &detailText,
	}); err != nil {
		return fmt.Errorf("record the import in the audit log: %w", err)
	}
	return nil
}
