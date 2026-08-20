package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// FlowTTL is how long an in-flight login may take.
//
// Ten minutes covers reading a consent screen, finding a password manager and answering a second
// factor. Longer would mean an abandoned authorize URL stays redeemable for an afternoon; shorter
// would fail people who get interrupted, and a failed login is indistinguishable from a broken
// service to the person having it.
const FlowTTL = 10 * time.Minute

// ErrAccountDisabled is a login by an account somebody has switched off. It is deliberately NOT
// folded into ErrCredentialRejected: the credential was fine, and telling the person "this account
// is disabled" is the only message that does not send them to reset a password that is not the
// problem.
var ErrAccountDisabled = errors.New("account is disabled")

// ErrFlowUnknown is a callback whose state matches nothing: expired, already redeemed, or never
// issued. All three are one error, because distinguishing them tells a prober which of their
// guesses was close.
var ErrFlowUnknown = errors.New("no such login in progress")

// ErrStateMismatch is a callback whose `state` parameter and `state` cookie disagree.
//
// That is login CSRF: somebody handing a victim's browser an authorization code of their own so
// the victim ends up signed in as the attacker, and then publishing under it. It is a separate
// error because it is the one that is never an accident.
var ErrStateMismatch = errors.New("the login state does not match this browser")

// OAuth runs the authorization-code handshake and turns its result into an account.
type OAuth struct {
	db        *store.DB
	clk       clock.Clock
	pepper    core.Secret
	providers *identity.Registry
}

// NewOAuth builds the handshake service.
func NewOAuth(
	db *store.DB, clk clock.Clock, pepper core.Secret, providers *identity.Registry,
) (*OAuth, error) {
	if err := requirePepper(pepper); err != nil {
		return nil, fmt.Errorf("oauth service: %w", err)
	}
	return &OAuth{db: db, clk: clk, pepper: pepper, providers: providers}, nil
}

// Begun is a started handshake.
type Begun struct {
	// AuthorizeURL is where the browser goes.
	AuthorizeURL string

	// State goes into the OAuthStateCookieName cookie. It is what binds the callback to this
	// browser; the URL alone is a nonce anyone can supply.
	State string

	// ExpiresAt bounds both the row and the cookie.
	ExpiresAt time.Time
}

// Begin mints state and a PKCE verifier, records the flow, and returns where to send the browser.
//
// redirectTo is where to land after a successful login. It is validated as a same-site absolute
// path here AND by a CHECK on the column: an open redirect on a login callback is a phishing
// primitive, and validating it once, at the edge, is how one gets missed.
func (o *OAuth) Begin(ctx context.Context, kind identity.Kind, redirectTo string) (Begun, error) {
	provider, err := o.providers.Get(kind)
	if err != nil {
		return Begun{}, err
	}

	state, err := newSecret()
	if err != nil {
		return Begun{}, err
	}
	verifier, err := newSecret()
	if err != nil {
		return Begun{}, err
	}

	now := o.clk.Now()
	expires := now.Add(FlowTTL)

	err = o.db.Tx(ctx, func(q *store.Queries) error {
		// Swept when a flow starts rather than on a timer: abandoned logins are the only thing
		// this table accumulates, and starting one is when we are certainly writing anyway.
		if err := q.DeleteExpiredOAuthFlows(ctx, core.MicrosFromTime(now).Int64()); err != nil {
			return fmt.Errorf("sweep expired login flows: %w", err)
		}
		return q.InsertOAuthFlow(ctx, sqlitegen.InsertOAuthFlowParams{
			StateHash:    keyedHash(o.pepper, state),
			ProviderKind: kind.String(),
			CodeVerifier: verifier,
			RedirectTo:   SafeRedirect(redirectTo),
			CreatedAt:    core.MicrosFromTime(now).Int64(),
			ExpiresAt:    core.MicrosFromTime(expires).Int64(),
		})
	})
	if err != nil {
		return Begun{}, fmt.Errorf("record the login flow: %w", err)
	}

	return Begun{
		AuthorizeURL: provider.AuthorizeURL(state, pkceChallenge(verifier)),
		State:        state,
		ExpiresAt:    expires,
	}, nil
}

// Completed is a finished handshake.
type Completed struct {
	AccountID   string
	DisplayName string

	// Handle is the provider handle as it was at this login. Decoration, for the page that says
	// who you are signed in as.
	Handle string

	// RedirectTo is the same-site path the flow started with, or "" for the default landing page.
	RedirectTo string

	// NewAccount says whether this login created the account. It is what the callback uses to
	// decide between "welcome back" and a first-run page, and what the audit row records.
	NewAccount bool
}

// Complete redeems a callback: it checks the state against this browser, exchanges the code, and
// resolves the provider identity into an account.
//
// The order matters. The state is checked BEFORE the code is exchanged, so a forged callback never
// causes an outbound request; the flow row is deleted in the same transaction it is read, so a
// replayed callback finds nothing.
func (o *OAuth) Complete(
	ctx context.Context, kind identity.Kind, state, cookieState, code string,
) (Completed, error) {
	switch {
	case state == "" || code == "":
		return Completed{}, ErrFlowUnknown
	case cookieState == "":
		// No cookie at all is the shape of a callback opened in a different browser, or of one
		// somebody constructed. Both are refused; neither is told which it looked like.
		return Completed{}, ErrStateMismatch
	case !equalHash(state, cookieState):
		return Completed{}, ErrStateMismatch
	}

	flow, err := o.takeFlow(ctx, kind, state)
	if err != nil {
		return Completed{}, err
	}

	provider, err := o.providers.Get(kind)
	if err != nil {
		return Completed{}, err
	}

	id, err := provider.Exchange(ctx, code, flow.CodeVerifier)
	if err != nil {
		return Completed{}, err
	}
	if strings.TrimSpace(id.Subject) == "" {
		return Completed{}, identity.ErrNoSubject
	}

	out, err := o.resolveAccount(ctx, id)
	if err != nil {
		return Completed{}, err
	}
	out.RedirectTo = flow.RedirectTo
	return out, nil
}

// takeFlow reads the flow row and deletes it in the same transaction.
//
// Read-then-delete in one transaction on the single writer connection is what makes a flow
// single-use: two callbacks racing with the same state cannot both find the row.
//
// THE REJECTION IS CARRIED OUT OF THE CALLBACK RATHER THAN RETURNED FROM IT. store.Tx commits only
// when the callback returns nil, so returning ErrFlowUnknown from inside would roll the DELETE
// back — and an expired flow that survives its own rejection is one an attacker can keep trying
// against until the clock or the pepper changes. The row is consumed either way; only the answer
// differs.
func (o *OAuth) takeFlow(ctx context.Context, kind identity.Kind, state string) (sqlitegen.OauthFlow, error) {
	var (
		flow   sqlitegen.OauthFlow
		reject error
	)

	err := o.db.Tx(ctx, func(q *store.Queries) error {
		row, err := q.GetOAuthFlow(ctx, keyedHash(o.pepper, state))
		switch {
		case errors.Is(err, store.ErrNoRows):
			reject = ErrFlowUnknown
			return nil
		case err != nil:
			return fmt.Errorf("read the login flow: %w", err)
		}
		if err := q.DeleteOAuthFlow(ctx, row.StateHash); err != nil {
			return fmt.Errorf("consume the login flow: %w", err)
		}
		// Checked after the delete, and recorded rather than returned, so that an expired or
		// mismatched flow is still consumed by the commit.
		if core.Micros(row.ExpiresAt).Time().Before(o.clk.Now()) || row.ProviderKind != kind.String() {
			reject = ErrFlowUnknown
			return nil
		}
		flow = row
		return nil
	})
	switch {
	case err != nil:
		return sqlitegen.OauthFlow{}, err
	case reject != nil:
		return sqlitegen.OauthFlow{}, reject
	}
	return flow, nil
}

// resolveAccount finds or creates the account behind a provider identity.
//
// The lookup is on (provider_kind, subject) and never on the handle: a GitHub rename must be a
// decoration refresh, not a new account holding none of the person's plugins.
func (o *OAuth) resolveAccount(ctx context.Context, id identity.Identity) (Completed, error) {
	display := strings.TrimSpace(id.DisplayName)
	if display == "" {
		// A GitHub account with no profile name is common. Falling back to the handle keeps the
		// account page readable; it is still decoration and still never matched on.
		display = id.Handle
	}

	var out Completed
	err := o.db.Tx(ctx, func(q *store.Queries) error {
		existing, err := q.GetAccountByIdentity(ctx, sqlitegen.GetAccountByIdentityParams{
			ProviderKind: id.Provider.String(),
			Subject:      id.Subject,
		})
		switch {
		case err == nil:
			if existing.DisabledAt != nil {
				return ErrAccountDisabled
			}
			out = Completed{AccountID: existing.ID, DisplayName: display, Handle: id.Handle}
			return o.refresh(ctx, q, existing.IdentityID, existing.ID, id.Handle, display)
		case !errors.Is(err, store.ErrNoRows):
			return fmt.Errorf("look up the identity: %w", err)
		}

		out, err = o.createAccount(ctx, q, id, display)
		return err
	})
	if err != nil {
		return Completed{}, err
	}
	return out, nil
}

// refresh updates the cached decoration: the handle on the identity, the display name on the
// account. Neither is an identifier; both are what a human sees.
func (o *OAuth) refresh(
	ctx context.Context, q *store.Queries, identityID, accountID, handle, display string,
) error {
	now := core.MicrosFromTime(o.clk.Now()).Int64()

	if err := q.RefreshIdentity(ctx, sqlitegen.RefreshIdentityParams{
		Handle:      handle,
		RefreshedAt: now,
		ID:          identityID,
	}); err != nil {
		return fmt.Errorf("refresh the identity: %w", err)
	}
	if err := q.UpdateAccountDisplayName(ctx, sqlitegen.UpdateAccountDisplayNameParams{
		DisplayName: display,
		UpdatedAt:   now,
		ID:          accountID,
	}); err != nil {
		return fmt.Errorf("refresh the account display name: %w", err)
	}
	return nil
}

// createAccount mints the account and the identity that proves it, in the caller's transaction.
func (o *OAuth) createAccount(
	ctx context.Context, q *store.Queries, id identity.Identity, display string,
) (Completed, error) {
	now := o.clk.Now()
	micros := core.MicrosFromTime(now).Int64()

	accountID, err := core.NewULID(now)
	if err != nil {
		return Completed{}, fmt.Errorf("mint an account id: %w", err)
	}
	identityID, err := core.NewULID(now)
	if err != nil {
		return Completed{}, fmt.Errorf("mint an identity id: %w", err)
	}

	if err := q.InsertAccount(ctx, sqlitegen.InsertAccountParams{
		ID:          accountID.String(),
		DisplayName: display,
		CreatedAt:   micros,
		UpdatedAt:   micros,
	}); err != nil {
		return Completed{}, fmt.Errorf("create the account: %w", err)
	}
	if err := q.InsertIdentity(ctx, sqlitegen.InsertIdentityParams{
		ID:           identityID.String(),
		AccountID:    accountID.String(),
		ProviderKind: id.Provider.String(),
		Subject:      id.Subject,
		Handle:       id.Handle,
		LinkedAt:     micros,
		RefreshedAt:  micros,
	}); err != nil {
		// The unique index on (provider_kind, subject) is what turns a race between two
		// simultaneous first logins into a constraint violation rather than two accounts holding
		// half a person's plugins each.
		return Completed{}, fmt.Errorf("link the identity: %w", err)
	}

	// The subject is recorded because it is the account's permanent link to a provider, and an
	// operator investigating a disputed claim needs it. It is an identifier, not a secret: it is
	// visible on the person's GitHub profile.
	if err := audit.Record(ctx, q, o.clk, audit.Entry{
		Actor:       audit.ActorAccount,
		AccountID:   accountID.String(),
		Action:      "account.create",
		SubjectKind: "account",
		SubjectID:   accountID.String(),
		Detail: map[string]any{
			"provider": id.Provider.String(),
			"subject":  id.Subject,
			"handle":   id.Handle,
		},
	}); err != nil {
		return Completed{}, err
	}

	return Completed{
		AccountID:   accountID.String(),
		DisplayName: display,
		Handle:      id.Handle,
		NewAccount:  true,
	}, nil
}

// pkceChallenge is the S256 code challenge for a verifier: base64url(sha256(verifier)), unpadded.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SafeRedirect returns path if it is a same-site absolute path, and "" otherwise.
//
// The three rejected shapes are the ones that are absolute URLs wearing a path's clothes:
// `https://evil.example` is obvious, `//evil.example` is protocol-relative, and `/\evil.example`
// is normalised to the second by several browsers. A column CHECK says the same thing, because a
// validator at one edge is a validator somebody adds a second caller around.
func SafeRedirect(path string) string {
	if path == "" || !strings.HasPrefix(path, "/") {
		return ""
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return ""
	}
	// A control character in a Location header is header injection. There is no legitimate path
	// containing one, so the whole value is discarded rather than sanitised — a sanitiser here
	// would be a second parser disagreeing with the browser's.
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return path
}
