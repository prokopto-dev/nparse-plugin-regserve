// Package authz holds the permission and scope vocabulary.
//
// Canonical §5 makes this package the ONE source for those values: the catalogue in
// `catalogue.go` generates the permission-table seed, the `x-regserve-permission` metadata in the
// OpenAPI document, the PAT scope enum and docs/reference/permissions.md. That catalogue lands
// with identity in Phase 2, and it is deliberately not stubbed here — an empty list that claims to
// be the catalogue is worse than an absent one, because a reader would believe it.
//
// What exists now is the pair of TYPES, because the route registry in internal/api declares the
// access every operation requires and it has to name a type to do it. Declaring that type in
// internal/api instead would mean two types for one concept the moment the catalogue arrives,
// which the house rules ban and which nobody would notice until a permission compared unequal to
// itself across a package boundary.
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
