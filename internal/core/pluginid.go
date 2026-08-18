// Package core holds the types every other package shares: identifiers, secrets, and the small
// value types that would otherwise be redefined slightly differently in three places.
package core

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidPluginID is returned by ParsePluginID for anything the SDK would reject.
var ErrInvalidPluginID = errors.New("invalid plugin id")

// pluginIDPattern mirrors nparseplus_sdk.plugin.PLUGIN_ID_RE exactly.
//
// This is not our regex. It is the SDK's, and the same string appears in the client's pydantic
// model, in the registry's JSON Schema, and in the CI job this server replaces. A plugin id is the
// plugin's identity in every installed copy on every user's machine, so a divergence here does not
// produce a validation error — it produces a listing some clients accept and others silently drop.
//
// If the SDK's pattern ever changes, that is a coordinated release, not a one-line edit.
const pluginIDPattern = `^[a-z][a-z0-9_-]{1,39}$`

var pluginIDRe = regexp.MustCompile(pluginIDPattern)

// PluginID is a validated plugin identifier.
//
// It is a distinct type from string because plugin ids are permanent and never recycled: once
// claimed, an id is that plugin's forever, and an unvalidated string flowing into an ownership
// check is how someone ends up owning an id they never claimed. Construct one only through
// ParsePluginID.
type PluginID string

// ParsePluginID validates s and returns it as a PluginID.
func ParsePluginID(s string) (PluginID, error) {
	if !pluginIDRe.MatchString(s) {
		return "", fmt.Errorf("%w: %q does not match %s", ErrInvalidPluginID, s, pluginIDPattern)
	}
	return PluginID(s), nil
}

// String returns the id as a plain string.
func (p PluginID) String() string { return string(p) }

// PluginIDPattern returns the regex source, for callers that must publish it — the OpenAPI
// document, for one. Returning the constant rather than exporting it keeps the single definition
// above authoritative.
func PluginIDPattern() string { return pluginIDPattern }
