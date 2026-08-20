package ownership

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Claiming a plugin id: the act that makes an id yours, for ever.
//
// Canonical §3 and the trust model: a plugin id is FIRST-COME, PERMANENT and NEVER RECYCLED. It is
// the plugin's identity in every installed copy on every user's machine, so an id that became
// available again would be a way to ship an update to somebody else's users. The `plugin` row IS
// the claim, and a BEFORE DELETE trigger makes that permanent in the database rather than in a
// convention.
//
// # Why this is a separate act, and session-only
//
// Publishing to an unclaimed id could have claimed it implicitly, and that would have been fewer
// steps. Two reasons not to:
//
//   - A PUBLISH TOKEN MUST NOT BE ABLE TO CLAIM IDS. A token is a deployment credential for one
//     plugin's pipeline (ADR-0005), and one that could register new ids would be a credential that
//     grows its own reach every time it is used. Claiming is capability-floor: session-only,
//     no scope, no token, ever.
//   - REGISTERING A PLUGIN AND RELEASING IT ARE DIFFERENT DECISIONS, and the static registry this
//     replaces treated them that way too — a human opened a pull request adding the plugin, and a
//     human merged it. Making the claim explicit keeps that shape without keeping the pull request.
//
// What has NOT changed: the first release of a newly claimed id still always goes to human review
// (ADR-0007). Claiming an id gets you a row and an owner grant; it does not get you a listing.

// Errors claiming returns.
var (
	// ErrAlreadyClaimed is an id somebody already holds — including the caller.
	//
	// It is the same answer either way, and deliberately says nothing about WHO holds it. The list
	// of claimed ids is public — the index serves it — but which account holds an unlisted id is
	// not, and answering that would turn this endpoint into a way to map ids to people.
	ErrAlreadyClaimed = errors.New("that plugin id is already claimed")

	// ErrBadListing is metadata a listing cannot carry.
	ErrBadListing = errors.New("the plugin's details are not usable")
)

// Listing caps. Each is far above any real value and bounds what a stranger can store.
const (
	MaxPluginNameBytes        = 120
	MaxPluginDescriptionBytes = 500
	MaxPluginAuthorBytes      = 120
	MaxPluginHomepageBytes    = 500
)

// Claim is a request to register an id.
type Claim struct {
	PluginID core.PluginID

	// Name is what a human sees in the plugin browser. Required: the column CHECKs it is non-empty,
	// and a listing with no name is one nobody can find.
	Name string

	// Description, Author and Homepage are optional and default to empty, which is what the column
	// defaults to and what the index renders.
	Description string
	Author      string

	// Homepage is rendered as a LINK in a desktop application. See validateHomepage.
	Homepage string
}

// ClaimID registers a plugin id to an account, and grants that account the plugin as its owner.
//
// One transaction: the claim and the grant commit together or not at all. A claimed id with no
// owner is a listing nobody can ever update — ids are never recycled, so the only repair would be
// a maintainer writing SQL against production.
func (s *Service) ClaimID(ctx context.Context, c Claim, accountID string) error {
	if err := c.validate(); err != nil {
		return err
	}

	now := core.MicrosFromTime(s.clk.Now()).Int64()

	return s.db.Tx(ctx, func(q *store.Queries) error {
		// FIRST-COME, checked inside the transaction. The insert's primary key would refuse a
		// duplicate anyway; reading first turns "UNIQUE constraint failed" into an answer that
		// says the id is taken, and the transaction is what stops two simultaneous claims both
		// believing they read an empty table.
		if _, err := q.GetPlugin(ctx, c.PluginID.String()); err == nil {
			return ErrAlreadyClaimed
		} else if !errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("check whether %s is claimed: %w", c.PluginID, err)
		}

		if err := q.InsertPlugin(ctx, sqlitegen.InsertPluginParams{
			ID:          c.PluginID.String(),
			Name:        c.Name,
			Description: c.Description,
			Author:      c.Author,
			Homepage:    c.Homepage,
			ClaimedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return fmt.Errorf("claim plugin id %s: %w", c.PluginID, err)
		}

		// The claimant is the OWNER, not a maintainer: they must be able to hand the plugin on,
		// and a plugin whose only holder cannot manage owners is one that can never be
		// transferred.
		if err := q.InsertPluginOwner(ctx, sqlitegen.InsertPluginOwnerParams{
			PluginID:  c.PluginID.String(),
			AccountID: accountID,
			Role:      RoleOwner.String(),
			GrantedAt: now,
			GrantedBy: &accountID,
		}); err != nil {
			return fmt.Errorf("grant %s to its claimant: %w", c.PluginID, err)
		}

		return audit.Record(ctx, q, s.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   accountID,
			Action:      "plugin.claim",
			SubjectKind: subjectPlugin,
			SubjectID:   c.PluginID.String(),
			Detail: map[string]any{
				detailAccount: accountID,
				"name":        c.Name,
			},
		})
	})
}

// validate checks the metadata a claim carries.
func (c *Claim) validate() error {
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	c.Author = strings.TrimSpace(c.Author)
	c.Homepage = strings.TrimSpace(c.Homepage)

	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"name", c.Name, MaxPluginNameBytes},
		{"description", c.Description, MaxPluginDescriptionBytes},
		{"author", c.Author, MaxPluginAuthorBytes},
		{"homepage", c.Homepage, MaxPluginHomepageBytes},
	} {
		if len(field.value) > field.max {
			return fmt.Errorf("%w: the %s is %d bytes and the limit is %d",
				ErrBadListing, field.name, len(field.value), field.max)
		}
		if !isPlainText(field.value) {
			// Every one of these is rendered in a desktop application. A control character in a
			// name is not a name, and an escape sequence in one is a terminal-styling primitive
			// aimed at whatever renders it.
			return fmt.Errorf("%w: the %s contains a control character or is not valid utf-8",
				ErrBadListing, field.name)
		}
	}

	if c.Name == "" {
		return fmt.Errorf("%w: a plugin needs a name", ErrBadListing)
	}
	return validateHomepage(c.Homepage)
}

// validateHomepage refuses a homepage that is not an ordinary https URL.
//
// THIS VALUE IS RENDERED AS A LINK IN A DESKTOP APPLICATION, and served to every client through
// the index. Two things follow:
//
//   - THE SCHEME IS RESTRICTED TO https. `javascript:`, `data:` and `file:` are not homepages; they
//     are instructions to whatever component renders the link, and this registry has no way to know
//     what a given client version does with one. Refusing them here costs an author nothing:
//     GitHub, GitLab, PyPI and every forge are https.
//   - CREDENTIALS ARE REFUSED, for the same reason `artifact_url` refuses them — this string is
//     published to every client, cached, and cannot be recalled.
//
// Empty is fine and means the plugin has no homepage, which is what the column defaults to.
func validateHomepage(raw string) error {
	if raw == "" {
		return nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		// The value is NOT echoed: a parse error's message quotes its input, and this input is
		// about to be refused precisely because nothing here trusts it.
		return fmt.Errorf("%w: the homepage is not a url", ErrBadListing)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: the homepage must be an https url, and %q is not a scheme this "+
			"registry will publish as a link", ErrBadListing, u.Scheme)
	case u.Hostname() == "":
		return fmt.Errorf("%w: the homepage names no host", ErrBadListing)
	case u.User != nil:
		return fmt.Errorf("%w: the homepage carries credentials, and this value is published in "+
			"the index to every client", ErrBadListing)
	}
	return nil
}

// isPlainText reports whether s is valid UTF-8 with no control characters.
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
