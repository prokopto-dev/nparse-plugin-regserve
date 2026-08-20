package release

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// EVERY FIELD OF A PUBLISH REQUEST IS HOSTILE INPUT, including the ones that look structural.
//
// This file is where that is acted on. Nothing below trusts a length, a character set or a scheme
// because the caller is authenticated: a compromised CI token is an authenticated caller, and it
// is the one the whole trust model is built around.
//
// The validation is at the EDGE as well as in the database. The database's CHECKs are what hold
// for a write that never goes through Go; these are what turn a bad request into an answer that
// names the field, before the server spends forty-five seconds downloading fifty megabytes on the
// submitter's behalf.

// Field caps. Each is far above any real value and exists to bound what a stranger can store.
const (
	// MaxVersionBytes bounds a version string. PEP 440's longest sensible form —
	// `1!1.2.3.dev456+local.identifier.1` — is under fifty.
	MaxVersionBytes = 64

	// MaxSDKSpecifierBytes bounds the specifier. This service CARRIES it and never evaluates it;
	// the client is the one that parses it (see db/schema.hcl on why the column is not named after
	// the wire field).
	MaxSDKSpecifierBytes = 128

	// MaxArtifactURLBytes bounds the URL. A signed CDN URL is long; this is longer.
	MaxArtifactURLBytes = 2048
)

// Errors this file returns. Sentinels, so the publish route maps each onto a problem code and a
// message naming the field rather than matching on strings.
var (
	// ErrNoVersion is a missing or malformed version.
	ErrNoVersion = errors.New("version is missing or malformed")

	// ErrNoSDKSpecifier is a missing or malformed SDK specifier.
	ErrNoSDKSpecifier = errors.New("sdk specifier is missing or malformed")

	// ErrBadMinimumAppVersion is a malformed minimum application version.
	ErrBadMinimumAppVersion = errors.New("minimum app version is malformed")
)

// versionRe is what a version may look like: a leading alphanumeric, then the characters PEP 440
// and semver both draw from.
//
// IT IS A FLOOR, NOT A PARSER. This service carries the version and compares it for equality; the
// CLIENT is what evaluates version semantics, and a registry that enforced its own idea of PEP 440
// would start refusing releases the client would have accepted. What it rules out is the thing an
// unbounded string does: control characters, whitespace, path separators, and anything that would
// look like markup wherever this ends up rendered.
var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]*$`)

// Submission is one validated publish request.
//
// It is built only through NewSubmission, so an unvalidated one cannot reach the publisher. The
// digest is a SubmittedDigest and not a string, which is what stops it being stored: see
// internal/artifact.
type Submission struct {
	PluginID core.PluginID
	Version  string

	// ArtifactURL is transport. The hash is the security boundary (ADR-0008).
	ArtifactURL string

	// Submitted is what the caller CLAIMED the artifact hashes to. It is compared against the
	// bytes this server fetches and then discarded.
	Submitted artifact.SubmittedDigest

	SDKSpecifier string

	// MinimumAppVersion is nil when the release states no constraint. Nil and empty are different
	// statements on the wire, so they are different here too.
	MinimumAppVersion *string

	// Notes are the author's plain-text patch notes (ADR-0013), already normalised and capped.
	Notes string
}

// RawSubmission is a publish request as it arrived, before anything has been checked.
//
// It is a separate type from Submission on purpose. A single struct that is "validated once
// someone calls Validate on it" is a struct that reaches the publisher unvalidated the first time
// somebody adds a call site — the compiler cannot tell the two states apart. Two types can.
type RawSubmission struct {
	PluginID          string
	Version           string
	ArtifactURL       string
	ArtifactSHA256    string
	SDKSpecifier      string
	MinimumAppVersion *string
	Notes             string
}

// NewSubmission validates a raw publish request.
//
// Field order is the order a caller would fix them in, and the FIRST failure is returned rather
// than all of them: a publish request comes from a workflow, and a workflow author fixing one
// field at a time is a better outcome than a wall of text where the second error was caused by the
// first.
func NewSubmission(raw RawSubmission) (Submission, error) {
	id, err := core.ParsePluginID(strings.TrimSpace(raw.PluginID))
	if err != nil {
		return Submission{}, err
	}

	version := strings.TrimSpace(raw.Version)
	if err := checkVersion(version, MaxVersionBytes); err != nil {
		return Submission{}, fmt.Errorf("%w: %w", ErrNoVersion, err)
	}

	url := strings.TrimSpace(raw.ArtifactURL)
	if len(url) > MaxArtifactURLBytes {
		return Submission{}, fmt.Errorf("%w: %d bytes, the limit is %d",
			artifact.ErrBadArtifactURL, len(url), MaxArtifactURLBytes)
	}
	if err := artifact.ValidateURL(url); err != nil {
		return Submission{}, err
	}

	submitted, err := artifact.ParseSubmittedDigest(raw.ArtifactSHA256)
	if err != nil {
		return Submission{}, err
	}

	specifier := strings.TrimSpace(raw.SDKSpecifier)
	switch {
	case specifier == "":
		return Submission{}, fmt.Errorf("%w: it is empty", ErrNoSDKSpecifier)
	case len(specifier) > MaxSDKSpecifierBytes:
		return Submission{}, fmt.Errorf("%w: %d bytes, the limit is %d",
			ErrNoSDKSpecifier, len(specifier), MaxSDKSpecifierBytes)
	case !isPlainText(specifier):
		return Submission{}, fmt.Errorf("%w: it contains a control character", ErrNoSDKSpecifier)
	}

	minApp, err := checkMinimumAppVersion(raw.MinimumAppVersion)
	if err != nil {
		return Submission{}, err
	}

	notes, err := ValidateReleaseNotes(raw.Notes)
	if err != nil {
		return Submission{}, err
	}

	return Submission{
		PluginID:          id,
		Version:           version,
		ArtifactURL:       url,
		Submitted:         submitted,
		SDKSpecifier:      specifier,
		MinimumAppVersion: minApp,
		Notes:             notes,
	}, nil
}

// checkMinimumAppVersion validates the optional constraint, keeping nil distinct from empty.
//
// A submitted empty string becomes nil rather than an error: on the wire the field is
// string-or-null, "no constraint" is what null means, and a workflow that interpolated an unset
// variable meant no constraint rather than a constraint of "".
func checkMinimumAppVersion(raw *string) (*string, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil-and-no-error IS the answer: the field is absent
	}
	trimmed := strings.TrimSpace(*raw)
	if trimmed == "" {
		return nil, nil //nolint:nilnil // as above
	}
	if err := checkVersion(trimmed, MaxVersionBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMinimumAppVersion, err)
	}
	return &trimmed, nil
}

// checkVersion applies the shape floor and the byte cap.
func checkVersion(v string, maxBytes int) error {
	switch {
	case v == "":
		return errors.New("it is empty")
	case len(v) > maxBytes:
		return fmt.Errorf("it is %d bytes and the limit is %d", len(v), maxBytes)
	case !versionRe.MatchString(v):
		// The pattern is quoted rather than described, so the answer says what would be accepted.
		return fmt.Errorf("it does not match %s", versionRe.String())
	}
	return nil
}

// isPlainText reports whether s is valid UTF-8 with no control characters.
//
// Tab and newline are NOT allowed here, unlike in release notes: a version or a specifier
// containing a newline is a value that would break every log line and every table it appears in,
// and there is no legitimate one.
func isPlainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}
