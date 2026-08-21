package registry_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// Release notes on the wire (ADR-0013).
//
// The field is ADDITIVE to a format that installs already in the field parse with pydantic models
// nobody can patch, so the question these tests answer is not "does the new field render" — that
// is the easy half — but "did adding it change anything for a listing that has none". The answer
// has to be no, byte for byte, and that is asserted against the literal document the live registry
// serves rather than against a shape this file made up.

// liveIndexBeforeNotes is the EXACT body of https://nparseplugins.prokopto.dev/index.json,
// captured on 2026-08-20, before this field existed.
//
// It is a literal rather than a fixture built from the values below, because a fixture built from
// the same struct the renderer marshals proves only that the renderer agrees with itself. These
// are somebody else's bytes: every key, every escape (`\u003e` for `>`, because encoding/json
// HTML-escapes by default and the client has been reading that spelling since the static registry
// produced it), and the order they arrive in.
//
// If this constant ever has to be edited to make the test pass, the change under review altered
// the document every installed client is parsing today. That is the finding, not the fix.
const liveIndexBeforeNotes = `{"schema_version":1,"plugins":[{"id":"merchant-mode","name":"Merchant Mode","description":"Turn your inventory into linkable WTS auction macros, find which mule is holding what, look up what anything is worth, and see how its price is actually moving — one server at a time, since that is the only place any of it can be sold.","author":"prokopto-dev","homepage":"https://github.com/prokopto-dev/nparseplus-merchantmode","latest":{"version":"0.5.0","url":"https://github.com/prokopto-dev/nparseplus-merchantmode/releases/download/v0.5.0/merchant_mode.zip","sha256":"87478a4fa3463cd831e5157a5b3f6e3c8fe6e6ff321f777162f6ab06cfccc742","requires_sdk":"\u003e=1.0,\u003c2","min_app_version":"2.1.0"}}]}`

// liveListing is the one plugin the production registry lists, with no notes — which is the state
// every listing in production is in on the day this lands.
func liveListing() registry.Plugin {
	min := "2.1.0"
	return registry.Plugin{
		ID:   "merchant-mode",
		Name: "Merchant Mode",
		Description: "Turn your inventory into linkable WTS auction macros, find which mule is " +
			"holding what, look up what anything is worth, and see how its price is actually " +
			"moving — one server at a time, since that is the only place any of it can be sold.",
		Author:   "prokopto-dev",
		Homepage: "https://github.com/prokopto-dev/nparseplus-merchantmode",
		Latest: registry.Release{
			Version:       "0.5.0",
			URL:           "https://github.com/prokopto-dev/nparseplus-merchantmode/releases/download/v0.5.0/merchant_mode.zip",
			SHA256:        "87478a4fa3463cd831e5157a5b3f6e3c8fe6e6ff321f777162f6ab06cfccc742",
			RequiresSDK:   registry.DefaultRequiresSDK,
			MinAppVersion: &min,
		},
	}
}

// TestMarshal_AListingWithNoNotes_IsByteIdenticalToTheLiveIndex is the measurement, not the claim.
//
// Adding a field to this document is only safe if it is invisible to every listing that does not
// use it. `require.Equal` on the whole string is what makes that a measurement: a reordered key, a
// `"release_notes":""`, a `null`, or a changed escape all fail here with a diff, where a
// `NotContains` assertion would pass while the bytes moved.
func TestMarshal_AListingWithNoNotes_IsByteIdenticalToTheLiveIndex(t *testing.T) {
	t.Parallel()

	idx, err := registry.NewIndex([]registry.Plugin{liveListing()})
	require.NoError(t, err)

	raw, err := idx.Marshal()
	require.NoError(t, err)

	require.Equal(t, liveIndexBeforeNotes, string(raw),
		"a listing with no notes must render to the bytes production serves today; if this "+
			"fails, the change under review altered the document installed clients are parsing")
	require.Len(t, raw, len(liveIndexBeforeNotes),
		"same length, stated separately so a failure says how many bytes moved")
}

// TestMarshal_NoNotes_OmitsTheKeyEntirely is the same property said the other way round, over the
// shapes a listing can be in rather than over one captured document.
func TestMarshal_NoNotes_OmitsTheKeyEntirely(t *testing.T) {
	t.Parallel()

	p := samplePlugin()
	p.Latest.ReleaseNotes = ""

	idx, err := registry.NewIndex([]registry.Plugin{p})
	require.NoError(t, err)
	raw, err := idx.Marshal()
	require.NoError(t, err)

	require.NotContains(t, string(raw), "release_notes",
		"an empty value must produce no key: an added key on every listing is a change to every "+
			"document we already serve, in exchange for saying nothing")
}

// TestMarshal_Notes_RenderOnLatestAfterTheExistingFields — where the key goes, and that it goes
// only where it belongs.
//
// The position matters because encoding/json emits struct fields in declaration order: a field
// inserted anywhere but last would reorder the keys of every listing, which is a diff on the wire
// for plugins that have no notes at all.
func TestMarshal_Notes_RenderOnLatestAfterTheExistingFields(t *testing.T) {
	t.Parallel()

	p := samplePlugin()
	p.Latest.ReleaseNotes = "Fixed the price graph on servers with no recent sales."

	idx, err := registry.NewIndex([]registry.Plugin{p})
	require.NoError(t, err)
	raw, err := idx.Marshal()
	require.NoError(t, err)

	require.Contains(t, string(raw),
		`"min_app_version":"2.1.0","release_notes":"Fixed the price graph on servers with no recent sales."}`,
		"notes are the last member of the latest object; anywhere else reorders every listing")
	require.NotContains(t, strings.Split(string(raw), `"latest":`)[0], "release_notes",
		"the field belongs to the release, not to the plugin")
}

// TestParseIndex_RoundTrips_Notes — the reader half.
//
// ParseIndex loads seed documents, and the seed document is the index document: the live
// catalogue reaches a fresh database by being captured with curl and replayed. A field the
// renderer writes and the parser drops would make that replay silently lossy.
func TestParseIndex_RoundTrips_Notes(t *testing.T) {
	t.Parallel()

	const notes = "Two lines,\nand a tab\there."

	p := samplePlugin()
	p.Latest.ReleaseNotes = notes

	idx, err := registry.NewIndex([]registry.Plugin{p})
	require.NoError(t, err)
	raw, err := idx.Marshal()
	require.NoError(t, err)

	back, err := registry.ParseIndex(raw)
	require.NoError(t, err)
	require.Equal(t, notes, back.Plugins[0].Latest.ReleaseNotes)

	again, err := back.Marshal()
	require.NoError(t, err)
	require.Equal(t, string(raw), string(again), "a parse and a re-render must be the same bytes")
}

// TestParseIndex_ADocumentWithoutNotes_LeavesThemEmpty — a document written before the field
// existed, which is every seed file and every mirror of the old static registry.
func TestParseIndex_ADocumentWithoutNotes_LeavesThemEmpty(t *testing.T) {
	t.Parallel()

	idx, err := registry.ParseIndex([]byte(liveIndexBeforeNotes))
	require.NoError(t, err)
	require.Empty(t, idx.Plugins[0].Latest.ReleaseNotes)

	raw, err := idx.Marshal()
	require.NoError(t, err)
	require.Equal(t, liveIndexBeforeNotes, string(raw),
		"parsing and re-rendering the live document must not add a key to it")
}

// TestMarshal_NotesAtTheCap_AreServedIntact — 2048 bytes is a cap, not a truncation point.
//
// The publish path REFUSES notes over the cap rather than shortening them (ADR-0013), so anything
// that reaches this renderer is within budget and must arrive whole. A renderer that trimmed would
// be a second, silent, cap.
func TestMarshal_NotesAtTheCap_AreServedIntact(t *testing.T) {
	t.Parallel()

	// The cap's own constant lives in internal/release, next to the validator and the column's
	// CHECK. It is not imported here: this package must not gain a second copy of a number whose
	// whole point is that there is one.
	notes := strings.Repeat("a", 2048)

	p := samplePlugin()
	p.Latest.ReleaseNotes = notes

	idx, err := registry.NewIndex([]registry.Plugin{p})
	require.NoError(t, err)
	raw, err := idx.Marshal()
	require.NoError(t, err)

	var back registry.Index
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Len(t, back.Plugins[0].Latest.ReleaseNotes, 2048)
}
