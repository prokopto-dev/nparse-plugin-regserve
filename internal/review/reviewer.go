// Package review is the human end of the publishing pipeline.
//
// Everything internal/release accepts lands `pending`. This package is what moves it: a person
// looks at a submission and approves it, rejects it, or asks the server to try fetching the
// artifact again. Without it a publish is durably recorded and goes nowhere, which is a safe state
// and not a finished one.
//
// # Who may review, and why it is not a row
//
// The static registry this service replaces answered this with GitHub: whoever could merge a pull
// request against `prokopto-dev/nparseplus-plugins` decided what got listed. The authority came
// from control of the repository.
//
// Here it comes from control of the DEPLOYMENT. Reviewers are named in the environment
// (`REGSERVE_REVIEWERS`, GitHub handles), so the people who can moderate are the people who can
// change what the droplet runs. That choice is deliberate and the alternatives were worse:
//
//   - A COLUMN ON `account` would be a row somebody can `UPDATE` at 2am. `identity_provider`
//     already refuses to be an operator toggle for exactly this reason, and moderation is a larger
//     power than publishing.
//   - A NEW TRUST LEVEL would conflate two different things. `account_trust` says how much this
//     service trusts somebody's RELEASES; it must never also say who may approve them, or a
//     trusted publisher would be able to approve their own submissions.
//   - GRANTING IT FROM INSIDE THE SYSTEM would create the escalation path canonical §5 exists to
//     prevent. There is no `admin:*` and no token that can become the account; a reviewer flag
//     that could be set through the API would be both.
//
// THE COST, STATED: the grant itself is not auditable — there is no row recording when somebody
// became a reviewer, only the deployment history. What IS auditable is every action they take:
// each approval, rejection and re-verification writes an `audit_log` row naming the account. That
// is the half that matters during an incident, and it is the half a database column would not have
// improved.
//
// A reviewer is also still an ordinary account. Reviewing is capability-floor
// (`Access.Floor("release.review")`), so no personal access token can do it however scoped, and
// `Reviewer()` on top of that is enforced by the same middleware from the same declaration.
package review

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// ErrNotAReviewer is an account that is not named in the configured reviewer set.
//
// It is a 403 and not a 404: unlike a plugin somebody does not own, the existence of a review
// queue is not a secret and refusing to say so would only confuse an operator who has just
// misspelled their own handle.
var ErrNotAReviewer = errors.New("this account is not a reviewer of this registry")

// Reviewers answers whether an account may review.
type Reviewers struct {
	db *store.DB

	// handles is the configured set, lower-cased. GitHub compares handles case-insensitively and
	// so did the static registry's owners.json, so an operator writing `Prokopto-Dev` gets what
	// they meant rather than a queue nobody can reach.
	handles map[string]bool
}

// NewReviewers builds the set from operator-supplied handles.
//
// An EMPTY set is legitimate and means nobody may review — the state every deployment is in before
// an operator has named anybody. It is not an error, and it is not "everybody": a service that
// defaulted to open moderation because a variable was unset would be the worst possible reading of
// a missing value. The caller logs the count at boot so an empty queue with a full backlog is
// visible rather than mysterious.
func NewReviewers(db *store.DB, handles []string) *Reviewers {
	set := make(map[string]bool, len(handles))
	for _, h := range handles {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(h), "@")))
		if h != "" {
			set[h] = true
		}
	}
	return &Reviewers{db: db, handles: set}
}

// ParseHandleList splits an operator-supplied list on commas.
//
// Whitespace and a leading `@` are tolerated because both are what a person writes. An entry that
// is empty after trimming is dropped rather than becoming a handle nobody holds — a trailing comma
// is a typo, not a grant.
func ParseHandleList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Count is how many handles were configured. For the boot log.
func (r *Reviewers) Count() int { return len(r.handles) }

// IsReviewer reports whether the account holds one of the configured handles.
//
// It resolves through `identity`, so the answer is "this account has PROVED it holds that GitHub
// handle" rather than "somebody typed that name". A handle in the configuration that nobody has
// signed in with grants nothing, which is the same rule ownership.Add keeps for the same reason: a
// grant to a name nobody has authenticated as is a grant to whoever registers it next.
//
// It is checked PER REQUEST rather than resolved to account ids at boot. An operator removing a
// handle and redeploying takes effect on the next call, and an account that signs in after boot
// does not need a restart to be recognised.
func (r *Reviewers) IsReviewer(ctx context.Context, accountID string) (bool, error) {
	if len(r.handles) == 0 {
		return false, nil
	}

	rows, err := r.db.Read().ListHandlesForAccount(ctx, accountID)
	if err != nil {
		return false, fmt.Errorf("read the identities of %s: %w", accountID, err)
	}
	for _, row := range rows {
		// Only GitHub identities count, because the configured list is GitHub handles. A second
		// provider would have its own namespace and matching across the two would mean a handle on
		// one provider granting review because somebody holds the same name on another.
		if row.ProviderKind != identity.KindGitHub.String() {
			continue
		}
		if r.handles[strings.ToLower(row.Handle)] {
			return true, nil
		}
	}
	return false, nil
}

// LogConfiguration says at boot what moderation this instance can do.
//
// An instance with a queue and no reviewers is a working service in which nothing will ever be
// published, and that is exactly the kind of state that is discovered a fortnight later by an
// author asking why their release is still pending.
func (r *Reviewers) LogConfiguration(ctx context.Context, pending int64) {
	switch {
	case len(r.handles) == 0 && pending > 0:
		slog.WarnContext(ctx, "releases are waiting for review and no reviewers are configured",
			"pending", pending, "needs", envReviewers)
	case len(r.handles) == 0:
		slog.InfoContext(ctx, "no reviewers are configured; nothing can be approved",
			"needs", envReviewers)
	default:
		// The COUNT and not the handles. A handle is not a secret, but a log line naming who can
		// moderate a registry is a list of people to target, and the count answers the operator's
		// actual question.
		slog.InfoContext(ctx, "reviewers configured",
			"reviewers", len(r.handles), "pending", pending)
	}
}

// envReviewers is named here so the message above and the command that reads it cannot disagree.
const envReviewers = "REGSERVE_REVIEWERS"

// EnvVar returns the environment variable reviewers are configured in.
func EnvVar() string { return envReviewers }
