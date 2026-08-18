package core

import "encoding/json"

// Secret wraps a value that must never reach a log, an error message, or a response body.
//
// The three OAuth client secrets and the token pepper are this service's entire security model.
// The failure this type prevents is the ordinary one: someone adds %v to a debug line, or a config
// struct gets marshalled into an error, and the secret is in a log file forever. Both String and
// MarshalJSON redact, so the value has to be asked for deliberately via Reveal.
type Secret struct {
	v string
}

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the underlying value. Every call site is a place to ask whether the value is
// about to be logged.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is unset, so config validation can say "this is missing"
// without revealing what a set value looks like.
func (s Secret) IsZero() bool { return s.v == "" }

const redacted = "[REDACTED]"

// String implements fmt.Stringer with a redaction, so %v and %s are safe by default.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, so %#v is safe too — the verb people reach for precisely
// when they are debugging and least want to think about this.
func (s Secret) GoString() string { return redacted }

// MarshalJSON redacts, so a Secret embedded in a config struct cannot be serialised into a
// response or a structured log entry.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
