// Package artifact fetches a release artifact, hashes it, and throws the bytes away.
//
// It exists because of ADR-0008: a publish request arrives with a URL and a sha256, and the
// submitter is the least trustworthy source of that sha256 available — their CI computed it, and
// their CI is the thing we are worried about being compromised. So the server downloads the
// artifact itself and computes the hash. THE SUBMITTED VALUE IS COMPARED AND THEN DISCARDED.
//
// THE HASH IS THE SECURITY BOUNDARY; THE URL IS ONLY TRANSPORT. The nParse+ installer refuses to
// extract an archive whose bytes do not match the hash this registry published, so that hash is
// the only thing standing between a user and arbitrary code. Publishing an attacker-chosen hash
// for attacker-chosen bytes would make the client verify perfectly against exactly the wrong
// value.
//
// # Two digest types, and why they are not one
//
// [Digest] is a hash THIS SERVER COMPUTED. [SubmittedDigest] is a hash SOMEBODY CLAIMED. They are
// the same 64 characters and they are not the same fact, so they are not the same Go type: a
// SubmittedDigest cannot be assigned where a Digest belongs, and there is no conversion between
// them in either direction. [core.Secret] is the precedent — a type that exists to make a misuse
// hard rather than to hold a value a string could not.
//
// A Digest has an unexported field and NO EXPORTED CONSTRUCTOR. Outside this package the only way
// to obtain a non-zero one is to call [Fetcher.Fetch], which gets it by hashing bytes it read.
// That is not a convention, it is the compiler: a composite literal naming an unexported field
// from another package does not build. Gate HASH001 covers the remaining hole — a caller writing
// a raw string into the column around the side of [StoredHash].
//
// # Artifacts are hashed and discarded
//
// Never extracted, never written to a persistent path, never executed, never imported. The bytes
// stream from the socket into the hasher and are gone. [Result] has nowhere to put them, which is
// what makes that a property of the API rather than a promise in a comment, and
// TestResult_HasNowhereToPutTheBytes is what stops a later field from quietly reintroducing one.
package artifact

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DigestHexLength is the length of a sha256 rendered as lowercase hex. It is also what the
// database CHECKs and what the client's parser accepts, and those three had better agree.
const DigestHexLength = sha256.Size * 2

// ErrInvalidDigest is a submitted sha256 that is not 64 lowercase hex characters.
//
// The shape is checked at the edge as well as by the column's CHECK, because a publish that is
// going to be refused should be refused before the server spends a minute downloading fifty
// megabytes on its behalf.
var ErrInvalidDigest = errors.New("not a sha256 digest")

// Digest is a sha256 THIS SERVER COMPUTED, from bytes THIS SERVER read.
//
// It is the value that reaches release.artifact_sha256 and, from there, every installed client.
// The unexported field is the mechanism: no other package can build one, so no other package can
// present something else as one. See the package comment.
type Digest struct {
	// hex is 64 lowercase hex characters, or empty for the zero value — which is what "we never
	// computed a hash" looks like, and is never storable. StoredHash refuses it.
	hex string
}

// Hex returns the digest as 64 lowercase hex characters, empty for the zero value.
func (d Digest) Hex() string { return d.hex }

// String makes a Digest printable in a log line or an error. It is the same value as Hex: a
// content hash is public — it is served in the index to every client on the internet.
func (d Digest) String() string { return d.hex }

// Computed reports whether this digest came from bytes, rather than being the zero value.
func (d Digest) Computed() bool { return d.hex != "" }

// ErrDigestNotComputed is [StoredHash] refusing the zero Digest.
//
// Reaching it means a publish path is about to record a hash for an artifact it never read, which
// is the exact confident mistake ADR-0008 exists to prevent. It is an error and not a silent NULL
// because "we could not check" and "there was nothing to check" are different rows.
var ErrDigestNotComputed = errors.New("digest was never computed from any bytes")

// StoredHash renders d for the release.artifact_sha256 column.
//
// IT IS THE ONLY DOOR INTO THAT COLUMN ON A PUBLISH PATH, and gate HASH001 is what keeps it that
// way: an assignment to ArtifactSha256 whose right-hand side is not a call to this function is a
// failing test, unless the same literal also declares `Source: "import"` — so the only way to
// store a hash this server did not compute is to say so, in the row, in the same breath.
//
// It returns *string rather than string so that the whole thing is ONE EXPRESSION at the call
// site. That is not a style choice: HASH001 reads the right-hand side of the assignment with
// go/ast and no type information, so a two-step `h, err := StoredHash(d)` followed by `&h` would
// present the gate with a bare `&h` to judge, and a gate that cannot tell what it is looking at is
// a gate that has to guess.
func StoredHash(d Digest) (*string, error) {
	if !d.Computed() {
		return nil, ErrDigestNotComputed
	}
	// Belt and braces over a type that cannot be built wrong: if this ever fails, something in
	// this package has changed and the column's CHECK would have caught it one layer later, in
	// production, on a row somebody has to go and find.
	if err := checkDigestHex(d.hex); err != nil {
		return nil, fmt.Errorf("digest is not storable: %w", err)
	}
	hexCopy := d.hex
	return &hexCopy, nil
}

// SubmittedDigest is the sha256 a publish request CLAIMED for its artifact.
//
// It is COMPARED and then DISCARDED (ADR-0008). It is never stored, never returned to a client as
// though it were the published hash, and there is deliberately no way to turn one into a [Digest]:
// the comparison runs the other way round, through [SubmittedDigest.Matches], which takes the
// computed value and gives back a boolean rather than a hash.
//
// The mismatch is the point. If the two differ, something between the author's build and our fetch
// changed the bytes — a re-uploaded release asset, a compromised token, a hijacked URL — and that
// is precisely the event worth stopping.
type SubmittedDigest struct {
	hex string
}

// ParseSubmittedDigest validates what a request sent.
//
// Uppercase hex is accepted and lowered. The client's parser and the column's CHECK both want
// lowercase, and refusing a spelling that every other tool in the chain accepts would be a
// gratuitous publish failure — where refusing a value that is not a sha256 at all is not.
func ParseSubmittedDigest(s string) (SubmittedDigest, error) {
	lowered := strings.ToLower(strings.TrimSpace(s))
	if err := checkDigestHex(lowered); err != nil {
		return SubmittedDigest{}, err
	}
	return SubmittedDigest{hex: lowered}, nil
}

// String returns the claimed digest, for an error message and for the audit row that records a
// mismatch. A mismatch is unreadable without both halves, and neither half is a secret.
func (s SubmittedDigest) String() string { return s.hex }

// Present reports whether a digest was submitted at all.
func (s SubmittedDigest) Present() bool { return s.hex != "" }

// Matches reports whether the bytes this server hashed are the bytes the submitter claimed.
//
// It takes the computed digest rather than returning the claimed one, which is the whole shape of
// the type: the answer a caller can get out of a SubmittedDigest is a boolean, never a value it
// could go on to store.
//
// Constant time. Not because a content hash is a secret — it is served in the index to anybody who
// asks — but because this is the one comparison in the publish path that decides whether bytes are
// trusted, and a timing-variable compare in that position is the kind of thing that is correct
// today and quoted in a report later. subtle.ConstantTimeCompare costs nothing here.
func (s SubmittedDigest) Matches(computed Digest) bool {
	if s.hex == "" || !computed.Computed() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.hex), []byte(computed.hex)) == 1
}

// checkDigestHex is the shape check both types share: 64 characters, lowercase hex, nothing else.
func checkDigestHex(s string) error {
	if len(s) != DigestHexLength {
		return fmt.Errorf("%w: %d characters, want %d", ErrInvalidDigest, len(s), DigestHexLength)
	}
	// hex.DecodeString accepts uppercase, so the case is checked separately rather than by it.
	if strings.ToLower(s) != s {
		return fmt.Errorf("%w: %q is not lowercase", ErrInvalidDigest, s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("%w: %q is not hex", ErrInvalidDigest, s)
	}
	return nil
}
