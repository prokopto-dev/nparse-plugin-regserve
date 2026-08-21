package plugin_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The seed importer is a door into release.notes, and these are the tests that keep it as narrow
// as the other one.
//
// ADR-0013's promise is that the field is not markup, so a client can render it in a text widget
// with no sanitiser. That promise is worth exactly as much as the widest path into the column —
// and a seed document is a file somebody with shell access wrote, parsed by registry.ParseIndex,
// which validates the WIRE SHAPE and says nothing about the text. The column's CHECK bounds the
// length and says nothing about the content either. So the importer runs the same validator the
// publish path runs, and these tests are what say so.

func TestImportSeed_NotesWithAControlCharacter_IsRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		notes string
		why   string
	}{
		{
			name:  "an ansi escape",
			notes: "clears the pane: \x1b[2J",
			why:   "a terminal-style renderer can be driven by an escape sequence",
		},
		{
			name:  "a bell",
			notes: "ping\x07",
			why:   "no legitimate changelog contains one",
		},
		{
			name:  "a c1 control",
			notes: "a\u0085b",
			why:   "C1 controls are refused as well as C0",
		},
		{
			name:  "over the cap",
			notes: strings.Repeat("n", 2049),
			why:   "the publish path refuses rather than shortening, and so does this",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostile := listing("merchant-mode")
			hostile.Latest.ReleaseNotes = tt.notes

			db := storetest.New(t)
			seed, err := plugin.LoadSeed(seedFile(t, hostile))
			require.NoError(t, err,
				"the document's wire shape is valid; it is the TEXT that is not, which is exactly "+
					"why ParseIndex cannot be the thing that catches this")

			_, err = plugin.ImportSeed(t.Context(), db, fixedClock(), seed)
			require.Error(t, err, "a seed the publish path would refuse must not be imported: %s", tt.why)
			require.Contains(t, err.Error(), "merchant-mode",
				"the refusal must name the plugin; an operator has to know which listing to fix")

			// Nothing at all was written. The import is one transaction, so a refusal partway
			// through must not leave a half-imported catalogue behind — which would then be
			// "non-empty" and stop the corrected seed from ever being imported.
			count, cerr := db.Read().CountPlugins(t.Context())
			require.NoError(t, cerr)
			require.Zero(t, count)
		})
	}
}

// TestImportSeed_NotesAreNormalisedLikeAPublish — the same text, whoever wrote the file.
//
// The validator turns CRLF and a bare CR into LF and trims the outer whitespace. Storing the
// unnormalised value would mean a catalogue captured on one machine and replayed from another
// serves different bytes for the same release, which is a diff on the wire with no change behind
// it.
func TestImportSeed_NotesAreNormalisedLikeAPublish(t *testing.T) {
	t.Parallel()

	windows := listing("merchant-mode")
	windows.Latest.ReleaseNotes = "  Fixed the price graph.\r\nTook the mule list out.\r\n"

	cat := importInto(t, storetest.New(t), windows)

	got, err := cat.Listing(t.Context(), core.PluginID("merchant-mode"))
	require.NoError(t, err)
	require.Equal(t, "Fixed the price graph.\nTook the mule list out.", got.Latest.ReleaseNotes,
		"imported notes are normalised by the same function a publish goes through")
}
