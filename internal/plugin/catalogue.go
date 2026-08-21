// Package plugin holds the plugin and release domain services.
//
// The catalogue here is what the index endpoints read. It satisfies an interface declared by its
// consumer (internal/api.Catalogue), which is why the store-backed implementation could replace
// the file-backed one without a handler moving.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Catalogue serves the listings from the database.
//
// It reads through the store's reader pool, which is query_only: rendering the index cannot take a
// write lock, so a burst of client polls can never delay a publish.
type Catalogue struct {
	db *store.DB
}

// NewCatalogue wraps an open database.
func NewCatalogue(db *store.DB) *Catalogue { return &Catalogue{db: db} }

// Listings returns every plugin with a live release, ordered by id.
//
// "Live" is one approved, non-superseded release — a single row, guaranteed by the partial unique
// index rather than by this query picking one (ADR-0010). A claimed plugin awaiting review has no
// such row and is therefore not in the index: it was never listed, rather than dropped from a
// listing.
func (c *Catalogue) Listings(ctx context.Context) ([]registry.Plugin, error) {
	rows, err := c.db.Read().ListListings(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the catalogue: %w", err)
	}

	out := make([]registry.Plugin, 0, len(rows))
	for _, row := range rows {
		p, err := listingFrom(row)
		if err != nil {
			// The whole request fails rather than the one row being dropped. A short index is
			// indistinguishable from "those plugins were delisted", so a client would show users a
			// catalogue that had quietly lost entries, with nothing anywhere saying so. A 500 is
			// visible in a log, on /readyz and in the deploy's own verification.
			slog.ErrorContext(ctx, "the catalogue cannot be rendered", "plugin_id", row.ID, "error", err)
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Listing returns one plugin, or api.ErrListingNotFound.
//
// Unknown and delisted are the same answer on purpose: a client cannot tell a delisted plugin from
// one that never existed, and neither can somebody enumerating ids.
func (c *Catalogue) Listing(ctx context.Context, id core.PluginID) (registry.Plugin, error) {
	row, err := c.db.Read().GetListing(ctx, id.String())
	switch {
	case errors.Is(err, store.ErrNoRows):
		return registry.Plugin{}, api.ErrListingNotFound
	case err != nil:
		return registry.Plugin{}, fmt.Errorf("read the listing for %s: %w", id, err)
	}

	p, err := listingFrom(sqlitegen.ListListingsRow(row))
	if err != nil {
		// Reporting "not found" for a row that exists would be a confident mistake: the id is
		// claimed, and the truth is that we cannot serve it.
		slog.ErrorContext(ctx, "the listing cannot be rendered", "plugin_id", id.String(), "error", err)
		return registry.Plugin{}, err
	}
	return p, nil
}

// Ready reports whether the catalogue can be served, and says why when it cannot.
//
// It re-reads and re-renders rather than answering from a flag set at boot. A readiness probe that
// remembers what was true at startup cannot notice a database that has since gone away, and it
// would keep answering 200 while /index.json returned 500 to every client.
//
// The error reaches an unauthenticated caller verbatim through /readyz, so it must stay a
// statement about the catalogue: no paths, no driver internals.
func (c *Catalogue) Ready(ctx context.Context) error {
	if err := c.db.Ping(ctx); err != nil {
		// The ping error names the pool and nothing else; the path is in the boot log.
		return errors.New("the database is not answering")
	}

	listings, err := c.Listings(ctx)
	if err != nil {
		return errors.New("the catalogue could not be read")
	}
	if _, err := registry.NewIndex(listings); err != nil {
		return fmt.Errorf("render the catalogue: %w", err)
	}

	// Claimed ids with nothing approved behind them are not an error — a plugin awaiting review is
	// the normal state of a new submission — but they are the difference between "we have twelve
	// plugins" and "we serve nine", and that difference should never have to be discovered.
	if waiting, err := c.db.Read().ListPluginsWithNoApprovedRelease(ctx); err == nil && len(waiting) > 0 {
		slog.InfoContext(ctx, "plugins claimed with no approved release",
			"count", len(waiting), "plugin_ids", waiting)
	}
	return nil
}

// ErrUnservableListing is returned when a row exists but cannot be rendered into a listing.
//
// The only case the schema permits is an approved release whose hash is NULL, which the
// release_approved_has_a_hash CHECK forbids — so this is the row that got there by a route nobody
// has thought of yet. Serving it with an empty hash would hand every client an artifact it must
// refuse to install, so the request fails instead and says which plugin did it.
var ErrUnservableListing = errors.New("listing has no usable artifact hash")

// listingFrom maps a row onto the wire type.
func listingFrom(row sqlitegen.ListListingsRow) (registry.Plugin, error) {
	if row.ArtifactSha256 == nil || *row.ArtifactSha256 == "" {
		return registry.Plugin{}, fmt.Errorf("%w: %s", ErrUnservableListing, row.ID)
	}
	return registry.Plugin{
		ID:          row.ID,
		Name:        row.Name,
		Description: row.Description,
		Author:      row.Author,
		Homepage:    row.Homepage,
		Latest: registry.Release{
			Version:     row.Version,
			URL:         row.ArtifactUrl,
			SHA256:      *row.ArtifactSha256,
			RequiresSDK: row.SdkSpecifier,
			// Nil stays nil: the field is string-or-null on the wire, and an absent constraint is
			// not the same statement as an empty one.
			MinAppVersion: row.MinimumAppVersion,
			// NULL becomes the empty string, which the renderer omits from the document entirely.
			// The opposite of MinimumAppVersion above, and for the opposite reason: nobody can
			// tell "no notes" from "empty notes", so a key saying so on every listing without one
			// would be a change to every document we already serve in exchange for nothing.
			ReleaseNotes: deref(row.Notes),
		},
	}, nil
}

// deref reads an optional column as a string, treating NULL and empty alike.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var (
	_ api.Catalogue    = (*Catalogue)(nil)
	_ api.ReadyChecker = (*Catalogue)(nil)
)
