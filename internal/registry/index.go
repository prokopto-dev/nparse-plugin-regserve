// Package registry renders the plugin index document.
//
// This package is the ONLY place that knows the wire format. Gate SCHEMA002 enforces that, and the
// reason is that the format is not ours: a released nParse+ desktop client parses it with the
// pydantic models in nparseplus.core.plugins.registry. Two packages that both "know" the shape will
// eventually disagree, and the thing that breaks is somebody's plugin browser, on a version we
// cannot patch.
//
// See docs/design/00-canonical-conventions.md §1 and ADR-0009.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// SchemaVersion is the wire format version, and it is 1.
//
// A client that reads a higher number refuses the entire index and tells the user to update
// nParse+. Every release in the field does this, so bumping this constant strands all of them at
// once. It is not a version we increment when we add a field — unknown fields are ignored by the
// client's parser, which is what makes additive change safe. See ADR-0009.
const SchemaVersion = 1

// MaxIndexBytes mirrors MAX_INDEX_BYTES in the client's registry.py.
//
// The client streams the response and aborts past this budget, so an index that grows beyond it
// does not degrade — it stops working, for everyone, at once. Gate SIZE001 fails well before here.
const MaxIndexBytes = 5 * 1024 * 1024

// DefaultRequiresSDK mirrors the default on the client's RegistryRelease model. It is written out
// explicitly rather than omitted, so a reader of the JSON sees the constraint that applies.
const DefaultRequiresSDK = ">=1.0,<2"

// sha256Re mirrors _SHA256_RE in the client's registry.py: 64 LOWERCASE hex characters.
//
// The client lower-cases before matching and so tolerates uppercase; the CI job this server
// replaces does not. We emit lowercase and reject anything else, because being the stricter end of
// a tolerant protocol is the only position that cannot produce a listing some parsers reject.
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Errors returned by Validate. They are sentinels so callers can map them onto problem codes
// without string matching.
var (
	ErrNoName          = errors.New("plugin name is empty")
	ErrNotHTTPS        = errors.New("artifact url is not https")
	ErrBadSHA256       = errors.New("sha256 is not 64 lowercase hex characters")
	ErrNoVersion       = errors.New("release version is empty")
	ErrDuplicatePlugin = errors.New("duplicate plugin id")
)

// Release is one reviewed, downloadable release of a plugin.
//
// Field names and JSON tags are the client's, not ours. Do not rename them.
type Release struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`

	// RequiresSDK is a PEP 440 specifier. The client evaluates it; we only carry it.
	RequiresSDK string `json:"requires_sdk"`

	// MinAppVersion is string-or-null on the wire. A pointer rather than a string with omitempty,
	// because the client's model declares the field nullable and an absent key and an explicit
	// null are different things to a reader even where pydantic treats them alike.
	MinAppVersion *string `json:"min_app_version"`
}

// Plugin is one listing in the index.
//
// Description, Author and Homepage carry no omitempty: the client defaults them to "", and emitting
// the keys keeps the document self-describing for the humans who read it far more often than any
// parser does. Homepage is deliberately NOT URL-validated — the client does not validate it either,
// and rejecting a listing here that the static registry would have accepted is a regression.
type Plugin struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Author      string  `json:"author"`
	Homepage    string  `json:"homepage"`
	Latest      Release `json:"latest"`
}

// Index is the whole document.
type Index struct {
	SchemaVersion int      `json:"schema_version"`
	Plugins       []Plugin `json:"plugins"`
}

// NewIndex builds an Index from listings, sorted by id, and validates it.
//
// Sorting is not cosmetic. The client renders plugins in array order, and a document whose order
// depends on a map iteration produces a browse list that reshuffles on every refresh — which reads
// as a bug and makes any diff of two fetches useless for debugging.
func NewIndex(plugins []Plugin) (Index, error) {
	out := make([]Plugin, len(plugins))
	copy(out, plugins)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	idx := Index{SchemaVersion: SchemaVersion, Plugins: out}
	if err := idx.Validate(); err != nil {
		return Index{}, err
	}
	return idx, nil
}

// Validate applies every rule the client and the replaced CI job apply, and returns the first
// failure. It is called by NewIndex; call it directly only when checking a hand-built document.
func (idx Index) Validate() error {
	seen := make(map[string]struct{}, len(idx.Plugins))
	for _, p := range idx.Plugins {
		if _, err := core.ParsePluginID(p.ID); err != nil {
			return err
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("%w: %s", ErrDuplicatePlugin, p.ID)
		}
		seen[p.ID] = struct{}{}

		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("%s: %w", p.ID, ErrNoName)
		}
		if err := p.Latest.validate(); err != nil {
			return fmt.Errorf("%s: %w", p.ID, err)
		}
	}
	return nil
}

func (r Release) validate() error {
	if strings.TrimSpace(r.Version) == "" {
		return ErrNoVersion
	}
	// Lower-cased before the prefix test because the client does the same: it accepts "HTTPS://".
	// Matching that tolerance costs nothing and avoids rejecting a listing the old registry took.
	if !strings.HasPrefix(strings.ToLower(r.URL), "https://") {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, r.URL)
	}
	if !sha256Re.MatchString(r.SHA256) {
		return fmt.Errorf("%w: %q", ErrBadSHA256, r.SHA256)
	}
	return nil
}

// ParseIndex decodes a schema-v1 index document and validates it.
//
// This is the reader half of the format, used to load seed data and to verify our own output in
// tests. It rejects a schema_version we do not understand for the same reason the client does: a
// document from the future is one whose meaning we would be guessing at.
func ParseIndex(raw []byte) (Index, error) {
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return Index{}, fmt.Errorf("parse index: %w", err)
	}
	if idx.SchemaVersion > SchemaVersion {
		return Index{}, fmt.Errorf("registry schema %d is newer than this server understands (%d)",
			idx.SchemaVersion, SchemaVersion)
	}
	// A document written before schema_version existed, or one that omits it, is version 1.
	if idx.SchemaVersion == 0 {
		idx.SchemaVersion = SchemaVersion
	}
	if idx.Plugins == nil {
		idx.Plugins = []Plugin{}
	}
	if err := idx.Validate(); err != nil {
		return Index{}, err
	}
	return idx, nil
}
