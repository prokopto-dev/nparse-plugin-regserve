// Package authz holds the permission and scope vocabulary.
//
// Canonical §5 makes this package the ONE source for those values. The catalogue in
// `catalogue.go` is that source: docs/reference/permissions.md is generated from it, the
// `x-regserve-permission` metadata in the OpenAPI document names its keys, and the PAT scope enum
// the database CHECKs is derived from it rather than written a second time.
//
// This file holds the two TYPES. They are separate types on purpose — a permission narrows a
// role, a scope narrows a token, and the whole value of the distinction is that one cannot be
// passed where the other is meant. `Valid` pins the spellings so a permission written with a colon
// is caught where it is declared rather than at the comparison that silently never matches.
package authz

import "regexp"

// Permission is `<resource>.<action>`, dot-separated and lowercase: `plugin.publish`,
// `owner.manage`. It narrows a ROLE.
type Permission string

// Scope is `<family>:<verb>`, colon-separated and lowercase: `plugin:publish`, `plugin:read`. It
// narrows a TOKEN.
//
// Scopes are coarser than permissions on purpose, and effective capability is the intersection of
// the two. There is no `admin:*` and no scope that reaches the capability floor — minting tokens,
// changing owners and setting trust are session-only and carry no scope at all.
type Scope string

// The shapes, so a malformed value is caught where it is declared rather than where it is
// compared. They are the spelling rules from canonical §12, not a list of known values: the list
// is the catalogue's job, and it does not exist yet.
var (
	permissionRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	scopeRe      = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)
)

func (p Permission) String() string { return string(p) }

// Valid reports whether p is spelled as a permission.
func (p Permission) Valid() bool { return permissionRe.MatchString(string(p)) }

func (s Scope) String() string { return string(s) }

// Valid reports whether s is spelled as a scope.
func (s Scope) Valid() bool { return scopeRe.MatchString(string(s)) }
