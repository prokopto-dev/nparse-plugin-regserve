// Package plugin holds the plugin and release domain services.
//
// At this stage it provides the catalogue the index endpoints read from. The store-backed
// implementation replaces Static in Phase 2; the interface it satisfies is declared by the consumer
// (internal/api.Catalogue), so that swap touches no handler.
package plugin

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// Static is an in-memory catalogue.
//
// It exists so the service can be run and pointed at by a real nParse+ client before the database
// lands — which matters more than it sounds, because the wire format is the one contract this
// project cannot unilaterally fix, and exercising it against the actual parser early is the whole
// point of ADR-0009.
type Static struct {
	mu      sync.RWMutex
	byID    map[core.PluginID]registry.Plugin
	ordered []registry.Plugin
}

// NewStatic builds a catalogue from listings. The listings are validated as a set, so a Static that
// constructs successfully cannot render an invalid index.
func NewStatic(listings []registry.Plugin) (*Static, error) {
	idx, err := registry.NewIndex(listings)
	if err != nil {
		return nil, err
	}

	byID := make(map[core.PluginID]registry.Plugin, len(idx.Plugins))
	for _, p := range idx.Plugins {
		id, perr := core.ParsePluginID(p.ID)
		if perr != nil {
			return nil, perr
		}
		byID[id] = p
	}
	return &Static{byID: byID, ordered: idx.Plugins}, nil
}

// LoadStatic reads a schema-v1 index document from disk and builds a catalogue from it.
//
// The seed file is the same shape the service serves, so the live catalogue can be captured with
// curl and replayed locally without a conversion step.
func LoadStatic(path string) (*Static, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path is an operator-supplied CLI flag
	if err != nil {
		return nil, fmt.Errorf("read seed file %s: %w", path, err)
	}
	idx, err := registry.ParseIndex(raw)
	if err != nil {
		return nil, fmt.Errorf("parse seed file %s: %w", path, err)
	}
	return NewStatic(idx.Plugins)
}

// Listings returns every visible plugin.
func (s *Static) Listings(_ context.Context) ([]registry.Plugin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]registry.Plugin, len(s.ordered))
	copy(out, s.ordered)
	return out, nil
}

// Listing returns one plugin, or api.ErrListingNotFound.
func (s *Static) Listing(_ context.Context, id core.PluginID) (registry.Plugin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.byID[id]
	if !ok {
		return registry.Plugin{}, api.ErrListingNotFound
	}
	return p, nil
}

var _ api.Catalogue = (*Static)(nil)
