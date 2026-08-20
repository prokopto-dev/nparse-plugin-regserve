package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Importing the static registry's ownership records.
//
// `owners.json` in prokopto-dev/nparseplus-plugins maps a plugin id to a list of GitHub HANDLES,
// compared case-insensitively. That comparison is exactly what this service replaces: a handle is
// decoration that its owner can change, and the claim has to survive a rename. So each handle is
// resolved to GitHub's immutable numeric id ONCE, here, at import — and both are recorded, the
// subject as the identity and the handle beside it for the humans (ADR-0003).
//
// It is a SEPARATE command from the catalogue seed, and deliberately not part of boot. It makes an
// outbound request per handle, against an unauthenticated rate limit, and a boot path that depends
// on GitHub answering is a boot path that fails when GitHub is slow. The catalogue is imported at
// boot because serving an empty index is an outage; ownership is not on that path.

// ownersFile is the shape of owners.json.
//
// `_readme` and `_example` are documentation in that file and are ignored, which the file itself
// says. Only `owners` is read, so a key added to the document later cannot become a claim here.
type ownersFile struct {
	Owners map[string][]string `json:"owners"`
}

// SeedOutcome is what an import did. Every number is reported, because an import that silently
// skipped half its input would look exactly like one that had nothing to do.
type SeedOutcome struct {
	// Granted is how many (plugin, account) pairs were created.
	Granted int

	// AccountsCreated is how many accounts this import minted for handles that had never signed
	// in. They are real accounts with a linked identity: the person signs in later and finds their
	// plugins already there.
	AccountsCreated int

	// AlreadyHeld is how many grants were already in place. On a second run this is everything.
	AlreadyHeld int

	// UnknownPlugins are ids in owners.json with no plugin row. They are NOT created: a claim on
	// an id this registry does not carry is a claim nobody can check, and inventing the row would
	// be the id-squatting the whole design exists to prevent.
	UnknownPlugins []string

	// UnresolvedHandles are handles GitHub does not know, or could not be asked about. Named, not
	// counted: each is a claim somebody has to look at.
	UnresolvedHandles []string
}

// Resolver turns a provider handle into the identity behind it. A consumer-declared interface, so
// the import can be tested without asking GitHub.
type Resolver interface {
	LookupHandle(ctx context.Context, handle string) (identity.Identity, error)
}

// LoadOwners reads and validates an owners.json document.
func LoadOwners(path string) (map[string][]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- an operator-supplied CLI flag
	if err != nil {
		return nil, fmt.Errorf("read owners file %s: %w", path, err)
	}

	var parsed ownersFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse owners file %s: %w", path, err)
	}
	if len(parsed.Owners) == 0 {
		// An empty document is refused rather than treated as "nothing to do". The failure this
		// prevents is a truncated or wrong-shaped file importing successfully and silently.
		return nil, fmt.Errorf("owners file %s lists no owners", path)
	}

	for id, handles := range parsed.Owners {
		if _, err := core.ParsePluginID(id); err != nil {
			return nil, fmt.Errorf("owners file %s: %w", path, err)
		}
		if len(handles) == 0 {
			return nil, fmt.Errorf("owners file %s: plugin %s lists no owners", path, id)
		}
	}
	return parsed.Owners, nil
}

// SeedOwners imports ownership records, resolving each handle to its numeric id.
//
// IT IS IDEMPOTENT AND ADDITIVE. Running it twice grants nothing new, and it never removes a grant
// somebody made here — the file is a starting point, not a description of the present. That is the
// only safe reading once ownership can also be changed through the account surface: a re-run that
// reconciled would silently undo a transfer.
func SeedOwners(
	ctx context.Context, db *store.DB, clk clock.Clock, resolver Resolver,
	owners map[string][]string,
) (SeedOutcome, error) {
	out := SeedOutcome{}

	// Sorted, so a run is reproducible and its log reads in the same order twice. Map iteration
	// would make two identical imports produce two different transcripts.
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// One resolution per handle, however many plugins it holds. The rate limit is the reason, and
	// so is honesty: the same handle must not resolve to two accounts within one import.
	resolved := map[string]identity.Identity{}

	for _, id := range ids {
		known, err := pluginExists(ctx, db, id)
		if err != nil {
			return out, err
		}
		if !known {
			out.UnknownPlugins = append(out.UnknownPlugins, id)
			continue
		}

		for _, handle := range owners[id] {
			key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(handle), "@"))
			who, ok := resolved[key]
			if !ok {
				who, err = resolver.LookupHandle(ctx, handle)
				switch {
				case errors.Is(err, identity.ErrProviderUnavailable):
					// Fatal. A rate limit part-way through would otherwise produce an import that
					// reported success having dropped every owner after it — the shape of failure
					// this repository exists to design against.
					return out, fmt.Errorf("resolve %s: %w", handle, err)
				case err != nil:
					out.UnresolvedHandles = append(out.UnresolvedHandles, handle)
					continue
				}
				resolved[key] = who
			}

			granted, created, err := grant(ctx, db, clk, id, who)
			if err != nil {
				return out, err
			}
			if created {
				out.AccountsCreated++
			}
			if granted {
				out.Granted++
			} else {
				out.AlreadyHeld++
			}
		}
	}
	return out, nil
}

func pluginExists(ctx context.Context, db *store.DB, id string) (bool, error) {
	_, err := db.Read().GetPlugin(ctx, id)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("look up plugin %s: %w", id, err)
	}
	return true, nil
}

// grant finds or creates the account behind an identity and gives it the plugin.
//
// All of it in one transaction: an account created without its identity is an account nobody can
// sign in to, and a grant without an account is a foreign-key violation. Reports whether it granted
// and whether it created an account.
func grant(
	ctx context.Context, db *store.DB, clk clock.Clock, pluginID string, who identity.Identity,
) (granted, created bool, err error) {
	now := clk.Now()
	micros := core.MicrosFromTime(now).Int64()

	err = db.Tx(ctx, func(q *store.Queries) error {
		accountID, madeAccount, err := accountFor(ctx, q, now, who)
		if err != nil {
			return err
		}
		created = madeAccount

		if _, err := q.GetPluginOwner(ctx, sqlitegen.GetPluginOwnerParams{
			PluginID:  pluginID,
			AccountID: accountID,
		}); err == nil {
			return nil
		} else if !errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("check the existing grant on %s: %w", pluginID, err)
		}

		// `owner`, not `maintainer`: owners.json recorded who may change a listing, which is what
		// `owner` means here. Downgrading somebody the static registry trusted would be this
		// migration quietly taking something away.
		//
		// granted_by is NULL: no account performed this. The audit row says the system did.
		if err := q.InsertPluginOwner(ctx, sqlitegen.InsertPluginOwnerParams{
			PluginID:  pluginID,
			AccountID: accountID,
			Role:      RoleOwner.String(),
			GrantedAt: micros,
		}); err != nil {
			return fmt.Errorf("grant %s to %s: %w", pluginID, who.Handle, err)
		}
		granted = true

		return audit.Record(ctx, q, clk, audit.Entry{
			Actor:       audit.ActorSystem,
			Action:      "owner.import",
			SubjectKind: subjectPlugin,
			SubjectID:   pluginID,
			Detail: map[string]any{
				detailAccount: accountID,
				detailHandle:  who.Handle,
				"subject":     who.Subject,
				"provider":    who.Provider.String(),
			},
		})
	})
	return granted, created, err
}

// accountFor finds the account behind a (provider, subject) pair, or creates one.
//
// An account created here has never signed in and has no session. It is a real account with a real
// linked identity, so when the person does sign in — with the same GitHub id — they land on it and
// find their plugins already there, rather than on a new empty one.
func accountFor(
	ctx context.Context, q *store.Queries, now time.Time, who identity.Identity,
) (string, bool, error) {
	micros := core.MicrosFromTime(now).Int64()

	existing, err := q.GetAccountByIdentity(ctx, sqlitegen.GetAccountByIdentityParams{
		ProviderKind: who.Provider.String(),
		Subject:      who.Subject,
	})
	switch {
	case err == nil:
		return existing.ID, false, nil
	case !errors.Is(err, store.ErrNoRows):
		return "", false, fmt.Errorf("look up the identity for %s: %w", who.Handle, err)
	}

	accountID, err := core.NewULID(now)
	if err != nil {
		return "", false, fmt.Errorf("mint an account id: %w", err)
	}
	identityID, err := core.NewULID(now)
	if err != nil {
		return "", false, fmt.Errorf("mint an identity id: %w", err)
	}

	display := strings.TrimSpace(who.DisplayName)
	if display == "" {
		display = who.Handle
	}

	if err := q.InsertAccount(ctx, sqlitegen.InsertAccountParams{
		ID:          accountID.String(),
		DisplayName: display,
		CreatedAt:   micros,
		UpdatedAt:   micros,
	}); err != nil {
		return "", false, fmt.Errorf("create an account for %s: %w", who.Handle, err)
	}
	if err := q.InsertIdentity(ctx, sqlitegen.InsertIdentityParams{
		ID:           identityID.String(),
		AccountID:    accountID.String(),
		ProviderKind: who.Provider.String(),
		Subject:      who.Subject,
		Handle:       who.Handle,
		LinkedAt:     micros,
		RefreshedAt:  micros,
	}); err != nil {
		return "", false, fmt.Errorf("link the identity for %s: %w", who.Handle, err)
	}

	if err := audit.Record(ctx, q, systemClock{now}, audit.Entry{
		Actor:       audit.ActorSystem,
		Action:      "account.import",
		SubjectKind: detailAccount,
		SubjectID:   accountID.String(),
		Detail: map[string]any{
			detailHandle: who.Handle,
			"subject":    who.Subject,
			"provider":   who.Provider.String(),
		},
	}); err != nil {
		return "", false, err
	}
	return accountID.String(), true, nil
}

// Log writes the outcome at a level that matches how much somebody needs to look at it.
//
// An unknown plugin id or an unresolved handle is a claim nobody can check, and it is NAMED rather
// than counted: "3 handles could not be resolved" is a number somebody nods at, and three handles
// is three people to go and ask about.
func (o SeedOutcome) Log(ctx context.Context) {
	slog.InfoContext(ctx, "ownership imported",
		"granted", o.Granted, "accounts_created", o.AccountsCreated, "already_held", o.AlreadyHeld)

	if len(o.UnknownPlugins) > 0 {
		slog.WarnContext(ctx, "owners.json names plugins this registry does not carry",
			"plugin_ids", o.UnknownPlugins)
	}
	if len(o.UnresolvedHandles) > 0 {
		slog.WarnContext(ctx, "owners.json names handles github does not know",
			"handles", o.UnresolvedHandles)
	}
}

// systemClock adapts a fixed instant to the clock interface internal/audit takes, so every row in
// one import carries the same timestamp.
type systemClock struct{ t time.Time }

func (c systemClock) Now() time.Time { return c.t }
