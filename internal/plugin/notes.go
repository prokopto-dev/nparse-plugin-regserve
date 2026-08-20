package plugin

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxReleaseNotesBytes is the hard cap on a release's notes (ADR-0013).
//
// BYTES, not characters, because the budget it protects is bytes on a wire: the client aborts the
// index read past 5 MiB, and `SIZE001` fails as the rendered document approaches 80% of that. At
// 2 KiB a thousand listings spend 2 MiB on notes alone; at 4 KiB a thousand listings put the gate
// over. The same number is a `CHECK` on the column, because a cap living only here is a cap that a
// migration, a later phase, or a hand-run UPDATE during an incident does not go through.
const MaxReleaseNotesBytes = 2048

// Errors ValidateReleaseNotes returns. Sentinels, so the publish path can map each onto a problem
// code without matching strings.
var (
	// ErrNotesTooLong is text over the cap. The publish is REFUSED rather than the text
	// shortened: truncating somebody's changelog silently is a worse answer than telling them.
	ErrNotesTooLong = errors.New("release notes exceed the size cap")

	// ErrNotesNotUTF8 is bytes that are not text. Storing them would put a sequence no client can
	// decode into a document every client parses.
	ErrNotesNotUTF8 = errors.New("release notes are not valid utf-8")

	// ErrNotesControlCharacter is a C0 or C1 control character other than a newline or a tab.
	// There is no legitimate changelog containing one, and a terminal-style renderer can be driven
	// by an escape sequence — which is the whole reason ADR-0013 promises the field is not markup.
	ErrNotesControlCharacter = errors.New("release notes contain a control character")
)

// ValidateReleaseNotes checks author-supplied release notes and returns them normalised.
//
// PLAIN TEXT IS A CONTRACT, NOT A FILTER (ADR-0013). Nothing here strips Markdown or escapes HTML:
// what is submitted is what is stored, minus what is not text at all. The promise a client relies
// on is that the field is never interpreted as markup, so it can be rendered in a text widget with
// no sanitiser — and a registry that quietly rewrote the text would be making a different promise
// while claiming this one.
//
// What it does do is refuse three things and normalise line endings, so that the same notes
// submitted from Windows and from Linux are the same bytes in the index.
func ValidateReleaseNotes(notes string) (string, error) {
	if notes == "" {
		return "", nil
	}
	if !utf8.ValidString(notes) {
		return "", ErrNotesNotUTF8
	}

	// CRLF and a bare CR both become LF. A carriage return is a control character, so this happens
	// before the check below rather than being an exception inside it.
	normalised := strings.ReplaceAll(strings.ReplaceAll(notes, "\r\n", "\n"), "\r", "\n")
	normalised = strings.Trim(normalised, " \t\n")

	for _, r := range normalised {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return "", fmt.Errorf("%w: %q", ErrNotesControlCharacter, r)
		}
	}

	// Measured after normalisation, so the cap is on what would actually be stored and served.
	if len(normalised) > MaxReleaseNotesBytes {
		return "", fmt.Errorf("%w of %d bytes: %d", ErrNotesTooLong, MaxReleaseNotesBytes,
			len(normalised))
	}
	return normalised, nil
}
