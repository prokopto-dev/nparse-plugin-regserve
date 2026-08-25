package authz

// THE CATALOGUE. Canonical §5 makes this file the one source for the permission and scope
// vocabulary: docs/reference/permissions.md is generated from it, the route registry in
// internal/api declares against it, and the PAT scope enum the database CHECKs comes from it.
//
// TWO RULES ABOUT HOW THIS FILE IS WRITTEN, and both have a gate:
//
//  1. EVERY KEY IS A WHOLE QUOTED LITERAL. `"plugin.publish"`, never `resource + "." + action`
//     and never a value assembled from fields. Gate AUTHZ001 reads this file as TEXT and requires
//     the exact quoted string to appear, because the point of a catalogue is that grepping for a
//     permission finds the place it is defined — a composed key produces the right runtime value
//     and answers no question anybody asks at 2am.
//
//  2. AN ENTRY SAYS WHETHER A TOKEN MAY REACH IT, and the two ways of saying "no" are different
//     statements. `Floor: true` is a refusal that outlives this phase: no token may ever perform
//     it, because a token that could would be equivalent to the account. An entry with `Floor:
//     false` and no scopes is session-only *by omission* — nobody has minted a scope for it yet.
//     A reader cannot tell those apart from an absence, so the catalogue says which it is.

// Entry is one permission and everything the generated artefacts need to describe it.
type Entry struct {
	// Permission is the key. It is what an operation declares and what the docs page is keyed on.
	Permission Permission

	// Summary is one sentence, present tense, naming what the holder may do. It is rendered into
	// docs/reference/permissions.md verbatim, so it is written for a plugin author reading the
	// published page and not for us.
	Summary string

	// Scopes are the PAT scopes that satisfy this permission. Empty means no token carries it.
	//
	// Effective capability is the INTERSECTION of the scope, the token's plugin pin and the
	// account's ownership at request time (ADR-0005) — a scope widens nothing on its own.
	Scopes []Scope

	// Floor marks a capability-floor permission: session-only, forever, and no scope will ever be
	// minted for it. Canonical §5 lists the members and the reason.
	Floor bool
}

// Catalogue is every permission this service knows, in the order the docs page renders them.
//
// The order is deliberate rather than alphabetical: the reader meets what a token can do before
// what only a browser can, because the first group is the one a CI pipeline is being written
// against and the second is the one that has to be explained.
func Catalogue() []Entry {
	return []Entry{
		{
			Permission: "plugin.read",
			Summary: "Read a plugin's registry state, including releases that are pending " +
				"review and therefore absent from the public index.",
			Scopes: []Scope{"plugin:read"},
		},
		{
			Permission: "plugin.publish",
			Summary: "Submit a release of a plugin. A new plugin id always goes to human " +
				"review; a version bump of an approved plugin may publish automatically.",
			Scopes: []Scope{"plugin:publish"},
		},
		{
			Permission: "plugin.manage",
			Summary: "Change a listing's name, description, author or homepage, and delist it. " +
				"Delisting keeps the id claimed — ids are never recycled.",
			Scopes: []Scope{"plugin:manage"},
		},

		// --- the capability floor (canonical §5) ---------------------------------------------
		//
		// Each of these would let a token become the account: mint another token, hand the plugin
		// to somebody else, or raise its own trust. There is no `admin:*`, and the floor is the
		// reason a leaked publish token stays a leaked publish token.
		{
			Permission: "token.mint",
			Summary:    "Mint a personal access token.",
			Floor:      true,
		},
		{
			Permission: "token.read",
			Summary: "List the account's personal access tokens. Secrets are shown once at " +
				"mint time and never again — this lists prefixes, scopes and dates.",
			Floor: true,
		},
		{
			Permission: "token.revoke",
			Summary:    "Revoke a personal access token.",
			Floor:      true,
		},
		{
			Permission: "plugin.claim",
			Summary: "Register a new plugin id. Ids are first-come, permanent and never " +
				"recycled, and the first release of a new id always goes to human review.",
			Floor: true,
		},
		{
			Permission: "owner.manage",
			Summary:    "Add, remove or transfer a plugin's owners.",
			Floor:      true,
		},
		{
			Permission: "trust.set",
			Summary:    "Set an account's trust level.",
			Floor:      true,
		},
		{
			Permission: "release.review",
			Summary:    "Approve or reject a release that is waiting for review.",
			Floor:      true,
		},
		{
			// MODERATION, NOT OWNERSHIP, and that is why it is not `plugin.manage`.
			//
			// The two acts look alike and are not. `plugin.manage` is what an OWNER holds over
			// their OWN listing, and ADR-0005 makes its effective capability the intersection of
			// the scope, the token's plugin pin and the account's ownership — so it cannot express
			// "somebody with no grant on this plugin removes it from every client's index". To
			// make it express that, the ownership intersection would have to be loosened, and a
			// loosened intersection is a `plugin:manage` token that can delist a stranger's
			// plugin. That is the escalation the capability floor exists to prevent, so the answer
			// is a second permission rather than a wider first one.
			//
			// It is Floor for the same reason `release.review` is: a token that could delist would
			// be a CI credential that can take any plugin out of the index, and moderation must
			// come from control of the deployment. Routes declaring it are
			// `Floor("plugin.moderate").Reviewer()`, and PERM001 fails a reviewer operation that
			// is not also floor.
			Permission: "plugin.moderate",
			Summary: "Delist or relist somebody else's plugin as a moderator. Delisting removes " +
				"the listing and keeps the claim — ids are never recycled — and it is a " +
				"different act from an owner delisting their own plugin, which the audit row says.",
			Floor: true,
		},
		{
			Permission: "session.end",
			Summary:    "End the browser session it is called with.",
			Floor:      true,
		},
	}
}

// Scopes returns every scope any entry names, deduplicated, in catalogue order.
//
// This is the PAT scope enum: the list the mint form offers, the list the database CHECKs, and the
// list the OpenAPI document advertises. Deriving it rather than writing it twice is the whole
// point — a scope that names no permission grants nothing and would be a lie on a consent screen.
func Scopes() []Scope {
	var out []Scope
	seen := map[Scope]bool{}
	for _, e := range Catalogue() {
		for _, s := range e.Scopes {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// Lookup returns the catalogue entry for p.
//
// Callers use it to answer "may this token do that", so a miss is a permission that does not
// exist and must never be treated as one that does: the boolean is second precisely so that
// ignoring it does not compile into an allow.
func Lookup(p Permission) (Entry, bool) {
	for _, e := range Catalogue() {
		if e.Permission == p {
			return e, true
		}
	}
	return Entry{}, false
}

// KnownScope reports whether s is in the catalogue.
//
// A token may only be minted with scopes this returns true for. An unknown scope on a mint request
// is rejected rather than stored and ignored: a token whose stored scope matches nothing would
// look narrow in the account page and be exactly as powerless in practice, which is a difference
// nobody would notice until it mattered.
func KnownScope(s Scope) bool {
	for _, known := range Scopes() {
		if known == s {
			return true
		}
	}
	return false
}

// Satisfies reports whether a token carrying held may exercise p.
//
// A capability-floor permission is never satisfied by any scope, whatever the token carries. That
// is checked here rather than only at the route, because this function is what a later phase will
// reach for when it asks the question somewhere else.
func Satisfies(p Permission, held []Scope) bool {
	e, ok := Lookup(p)
	if !ok || e.Floor || len(e.Scopes) == 0 {
		return false
	}
	for _, want := range e.Scopes {
		for _, have := range held {
			if have == want {
				return true
			}
		}
	}
	return false
}
