package release_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// Release notes are author-supplied text rendered in a desktop client (ADR-0013). What is asserted
// here is the contract: valid UTF-8, no control characters but newline and tab, within the byte
// cap, and NOT rewritten — a registry that silently stripped markup would be making a different
// promise from the one clients are told to rely on.

func TestValidateReleaseNotes_AcceptsWhatAChangelogLooksLike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "one line", in: "Fixed the merchant scanner.", want: "Fixed the merchant scanner."},
		{
			name: "several lines",
			in:   "Fixed the merchant scanner.\nAdded a setting for the poll interval.",
			want: "Fixed the merchant scanner.\nAdded a setting for the poll interval.",
		},
		{name: "a tab, which changelogs indent with", in: "a\tb", want: "a\tb"},
		{name: "non-ascii text", in: "Corrigé l'analyseur enfin.", want: "Corrigé l'analyseur enfin."},
		{name: "an emoji", in: "Faster now \U0001F680", want: "Faster now \U0001F680"},
		{name: "exactly at the cap", in: strings.Repeat("a", 2048), want: strings.Repeat("a", 2048)},

		// NOT rewritten. An author who writes Markdown gets literal asterisks, which is the cost
		// ADR-0013 accepts on purpose — and a registry that stripped them would be sanitising
		// rather than promising.
		{
			name: "markdown is left alone",
			in:   "**bold** and [a link](https://example.com)",
			want: "**bold** and [a link](https://example.com)",
		},
		{name: "html is left alone as text", in: "<b>not markup</b>", want: "<b>not markup</b>"},

		// Normalised, so the same notes from Windows and from Linux are the same bytes.
		{name: "crlf becomes lf", in: "one\r\ntwo", want: "one\ntwo"},
		{name: "a bare cr becomes lf", in: "one\rtwo", want: "one\ntwo"},
		{name: "surrounding whitespace is trimmed", in: "\n  Fixed it.  \n\n", want: "Fixed it."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := release.ValidateReleaseNotes(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidateReleaseNotes_RefusesWhatIsNotPlainText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want error
	}{
		{
			name: "one byte over the cap",
			in:   strings.Repeat("a", release.MaxReleaseNotesBytes+1),
			want: release.ErrNotesTooLong,
		},
		{
			// The cap is BYTES. Three-byte characters reach it in a third of the characters, which
			// is what a character cap would get wrong in the direction that matters.
			name: "over the cap in multi-byte characters",
			in:   strings.Repeat("\u3042", release.MaxReleaseNotesBytes/3+1),
			want: release.ErrNotesTooLong,
		},
		{name: "invalid utf-8", in: "fine\xff\xfe", want: release.ErrNotesNotUTF8},

		// A terminal-style renderer can be driven by an escape sequence, which is exactly what
		// "the field is not markup" is meant to rule out.
		{name: "an ansi escape", in: "clear\x1b[2Jthis", want: release.ErrNotesControlCharacter},
		{name: "a null byte", in: "a\x00b", want: release.ErrNotesControlCharacter},
		{name: "a bell", in: "a\x07b", want: release.ErrNotesControlCharacter},
		{name: "a c1 control", in: "a\u0085b", want: release.ErrNotesControlCharacter},
		{name: "a delete", in: "a\x7fb", want: release.ErrNotesControlCharacter},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := release.ValidateReleaseNotes(tt.in)
			require.ErrorIs(t, err, tt.want)
			require.Empty(t, got, "a refused value must not come back partially cleaned")
		})
	}
}

// TestValidateReleaseNotes_TheCapMatchesTheIndexBudget — the arithmetic ADR-0013 rests on.
//
// SIZE001 fails as the rendered index approaches 80% of the client's 5 MiB cap. At 2 KiB a
// thousand listings spend 2 MiB on notes alone; a 4 KiB cap would put a thousand plugins over.
// This is what would notice if somebody raised the constant without redoing the sum.
func TestValidateReleaseNotes_TheCapMatchesTheIndexBudget(t *testing.T) {
	t.Parallel()

	const (
		clientCap     = 5 * 1024 * 1024
		gateThreshold = clientCap * 8 / 10
		plausible     = 1000
	)

	require.Less(t, release.MaxReleaseNotesBytes*plausible, gateThreshold,
		"at %d bytes, %d listings spend %d bytes on notes alone, which is past the %d-byte point "+
			"SIZE001 fails at — the cap and the index budget have to be decided together",
		release.MaxReleaseNotesBytes, plausible, release.MaxReleaseNotesBytes*plausible, gateThreshold)
}
