package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Package release accepts and records release submissions.
//
// It is separate from internal/plugin, which owns the CATALOGUE — the listings the index endpoints
// read. The split is not filing: internal/plugin depends on internal/api for the consumer-declared
// Catalogue interface it satisfies, and internal/api has to depend on THIS package for the publish
// request and its outcome. One package holding both would be a cycle, and the cycle is pointing at
// something real — reading the catalogue and writing to it are different jobs with different
// callers.
//
// Publishing a release. The sequence is ADR-0008's, and the order of the steps is the design:
//
//  1. The request is validated (submission.go) and the caller's authority is checked.
//  2. THE SERVER FETCHES THE ARTIFACT AND COMPUTES THE HASH ITSELF.
//  3. The submitted hash is COMPARED against it and then DISCARDED.
//  4. A release row is written carrying the hash from step 2, never the one from step 3.
//
// The step that is easiest to get wrong is the fourth, and it is the one that matters most: the
// published hash is what the nParse+ installer verifies against before extracting, so a submitted
// value stored there would have the client verifying perfectly against exactly the wrong bytes.
// It is made unrepresentable rather than reviewed for — artifact.Digest cannot be constructed
// outside the package that hashes bytes, artifact.StoredHash is the only door into the column, and
// gate HASH001 fails any assignment that goes around it.
//
// WHAT THIS PHASE DOES NOT DO YET: every release lands `pending`. Trust levels, which are what let
// a version bump by a sufficiently trusted owner publish automatically (ADR-0007), are Phase 3's
// fourth pull request. Landing "everything goes to human review" first is the conservative
// direction to be incomplete in — the failure mode is a queue, not a bad listing.

// ReleaseState is a release's position in its lifecycle. The values are the database's CHECK.
type ReleaseState string

const (
	// StatePending is submitted and waiting for a human. It is not in the index.
	StatePending ReleaseState = "pending"

	// StateApproved is the single live release of a plugin, and the one `latest` is derived from.
	StateApproved ReleaseState = "approved"
)

func (s ReleaseState) String() string { return string(s) }

// Errors the publish path returns.
var (
	// ErrNotPublishable is the caller having no grant on the plugin, OR the plugin not existing.
	//
	// ONE ERROR FOR BOTH, deliberately. Telling somebody "that plugin exists and is not yours"
	// enumerates the registry's claimed ids for anybody with a wordlist, and the ids are permanent
	// — so it also tells a squatter exactly which names are worth waiting for. The settings page
	// already answers this way; the API answers the same way for the same reason.
	ErrNotPublishable = errors.New("no such plugin, or you do not hold it")

	// ErrGitHubIdentityRequired is an account with no identity from a provider that may publish.
	//
	// ADR-0004 and ADR-0011: only GitHub identities may publish, and that is a CHECK against
	// identity_provider.kind rather than a column an operator sets.
	ErrGitHubIdentityRequired = errors.New("publishing requires a linked github identity")

	// ErrVersionExists is a version already used for this plugin, in any state.
	//
	// A version is used once per plugin, EVER — over a table nothing deletes from. It is reported
	// rather than allowed to become a UNIQUE constraint error, because the answer a workflow
	// author needs is "you already published 1.2.0", not a driver message.
	ErrVersionExists = errors.New("that version has already been submitted for this plugin")

	// ErrIdempotencyKeyReused is the same key presented with a different request.
	//
	// It is a 409 and not a replay. Answering with the first release's id would tell a caller that
	// their new version published when it did not, which is the confident mistake in miniature.
	ErrIdempotencyKeyReused = errors.New("that idempotency key was used for a different request")

	// ErrNoIdempotencyKey is a publish with no key at all. Canonical §6 requires one.
	ErrNoIdempotencyKey = errors.New("an idempotency key is required")
)

// The audit and review vocabulary this file writes. One spelling each: an incident review queries
// audit_log on (subject_kind, subject_id), and a second spelling puts half the rows out of reach.
const (
	subjectPluginKind = "plugin"
	actionPublish     = "plugin.publish"

	// operationPublishRelease is the OperationID of the route this serves. It scopes an
	// idempotency key, so it is the SDK method name rather than a description — a key reused
	// across two different operations is two different requests.
	operationPublishRelease = "publishRelease"
)

// Review notes. They are read by a human deciding whether to approve, and by the author, so each
// says what happened rather than which branch produced it.
const (
	// reviewAwaitingHuman is the ordinary case in this phase: nothing is wrong, and nothing
	// publishes automatically yet.
	reviewAwaitingHuman = "awaiting human review"

	// reviewHashMismatch is the one worth waking up for. The bytes this server fetched are not the
	// bytes the submitter hashed, which means something between their build and our fetch changed
	// them: a re-uploaded release asset, a compromised token, a hijacked URL.
	reviewHashMismatch = "the submitted sha256 does not match the artifact this server fetched"
)

// ArtifactFetcher is what the publisher needs from internal/artifact.
//
// A consumer-declared interface, so a test can supply a fetcher that fails on demand without
// standing up a server that refuses to answer. What it deliberately does NOT allow is a fake
// digest: the Result it returns carries an artifact.Digest, which no test can construct either.
// A test that wants a successful fetch has to hash real bytes, which is the point.
type ArtifactFetcher interface {
	Fetch(ctx context.Context, rawURL string) (artifact.Result, error)
}

// Publisher accepts release submissions.
type Publisher struct {
	db      *store.DB
	clk     clock.Clock
	fetcher ArtifactFetcher
}

// NewPublisher builds the service.
func NewPublisher(db *store.DB, clk clock.Clock, fetcher ArtifactFetcher) *Publisher {
	return &Publisher{db: db, clk: clk, fetcher: fetcher}
}

// Request is one call to Publish.
type Request struct {
	Submission Submission

	// AccountID is the authenticated caller. The middleware has already checked the token's scope
	// and its plugin pin; what is checked HERE is ownership, at the moment of the change.
	AccountID string

	// IdempotencyKey is the client's key. Required (canonical §6).
	IdempotencyKey string
}

// Outcome is what a publish did. It is what the route renders.
type Outcome struct {
	ReleaseID string
	State     ReleaseState

	// Verified says whether this server fetched the bytes and hashed them. FALSE IS NOT A
	// FAILURE OF THE REQUEST — it is a release that went to review with the reason recorded — but
	// it is never reported as a success either. See ADR-0008.
	Verified bool

	// SHA256 is the STORED hash: the one this server computed. Empty when the artifact could not
	// be fetched, because there is nothing honest to put there.
	SHA256 string

	// Bytes is the artifact's size as counted during the read. Nil when not verified.
	Bytes *int64

	// Review is why this release is waiting, in a sentence written for a human.
	Review string

	// Replayed says the idempotency key had been seen before and this is the original outcome.
	Replayed bool
}

// Publish submits a release.
//
// It is deliberately not one transaction. The artifact fetch takes up to forty-five seconds, and
// SQLite has exactly one writer — a transaction held open across the download would block every
// other publish, every ownership change and every token mint for the duration. So the fetch
// happens outside, and the authority checks that matter are made AGAIN inside the transaction that
// writes. Checking twice is not redundancy: the first check avoids downloading fifty megabytes on
// behalf of somebody who may not publish, and the second is the one ADR-0005 requires, made
// against the same snapshot as the write.
func (p *Publisher) Publish(ctx context.Context, req Request) (Outcome, error) {
	key := strings.TrimSpace(req.IdempotencyKey)
	if key == "" {
		return Outcome{}, ErrNoIdempotencyKey
	}
	requestHash := hashRequest(req.Submission)

	// A replay, answered without doing any of it again. This is the whole reason the key exists:
	// the dominant caller is a release workflow, and workflows get re-run.
	if out, found, err := p.replay(ctx, req.AccountID, key, requestHash); err != nil || found {
		return out, err
	}

	if err := p.checkAuthority(ctx, req); err != nil {
		return Outcome{}, err
	}

	// Read before write, so "you already published 1.2.0" is the answer rather than a UNIQUE
	// constraint error surfacing as a 500. The transaction below checks it again, because this
	// read and that write are forty-five seconds apart.
	if err := p.checkVersionUnused(ctx, req.Submission); err != nil {
		return Outcome{}, err
	}

	// STEP 2 AND 3 OF ADR-0008. The bytes are fetched, hashed and discarded; the submitted digest
	// is compared against what came back and plays no further part.
	verdict := p.verify(ctx, req.Submission)

	return p.record(ctx, req, key, requestHash, verdict)
}

// verdict is what the fetch-and-compare produced. It is a value rather than three return
// parameters so that "not verified" travels as one thing that cannot be half-read.
type verdict struct {
	// result is zero when the fetch failed. Its Digest is the ONLY digest that ever gets stored.
	result artifact.Result

	// verified is true only when bytes were fetched AND they matched the submitted hash.
	verified bool

	// review is the sentence recorded on the row, never empty in this phase.
	review string
}

// verify fetches the artifact, hashes it, and compares.
//
// EVERY FAILURE PATH PRODUCES A ROW, not an error. That is ADR-0008's rule and it is the one most
// likely to be "optimised" later by somebody reading a timeout as a transient annoyance: a release
// whose bytes could not be fetched is NOT PUBLISHED, but it is also not silently dropped — it goes
// to review with the reason recorded, so a human can see that something was submitted and could
// not be checked. "We could not check" and "we checked and it was fine" must never produce the
// same outcome, and neither must "we could not check" and "nothing happened".
func (p *Publisher) verify(ctx context.Context, sub Submission) verdict {
	res, err := p.fetcher.Fetch(ctx, sub.ArtifactURL)
	if err != nil {
		// Logged with the plugin and version, and with the error whose URL has already been
		// stripped of anything credential-shaped by internal/artifact.
		slog.WarnContext(ctx, "artifact not verified",
			"plugin_id", sub.PluginID.String(), "version", sub.Version, "error", err)
		return verdict{review: artifact.Reason(err)}
	}

	if !sub.Submitted.Matches(res.Digest) {
		// THE MISMATCH IS RECORDED, NOT SILENTLY CORRECTED. Storing our hash and saying nothing
		// would publish bytes the author never approved, under a listing that looked fine. The row
		// carries OUR hash — the truth about the bytes that exist — and goes to review saying the
		// two disagreed.
		slog.WarnContext(ctx, "submitted sha256 does not match the fetched artifact",
			"plugin_id", sub.PluginID.String(), "version", sub.Version,
			"submitted", sub.Submitted.String(), "computed", res.Digest.String())
		return verdict{result: res, review: reviewHashMismatch}
	}

	return verdict{result: res, verified: true, review: reviewAwaitingHuman}
}

// record writes the release, the idempotency row and the audit row in one transaction.
func (p *Publisher) record(
	ctx context.Context, req Request, key, requestHash string, v verdict,
) (Outcome, error) {
	now := p.clk.Now()
	releaseID, err := core.NewULID(now)
	if err != nil {
		return Outcome{}, fmt.Errorf("mint a release id for %s: %w", req.Submission.PluginID, err)
	}

	// Built here rather than inside the closure so that the transaction body is the writes and
	// nothing else, and so that a digest that cannot be stored fails before a lock is taken.
	params, err := releaseParams(releaseID, req, v, now)
	if err != nil {
		return Outcome{}, err
	}

	out := Outcome{
		ReleaseID: releaseID.String(),
		State:     ReleaseState(params.State),
		Verified:  v.verified,
		Bytes:     params.ArtifactBytes,
		Review:    v.review,
	}
	if params.ArtifactSha256 != nil {
		out.SHA256 = *params.ArtifactSha256
	}

	err = p.db.Tx(ctx, func(q *store.Queries) error {
		// Checked AGAIN, inside the transaction. Between the check above and this write the
		// artifact was downloaded, which is up to forty-five seconds in which an owner can be
		// removed. ADR-0005 wants the authority and the change decided against one snapshot.
		if err := ownership.RequireGrantTx(ctx, q, req.Submission.PluginID.String(), req.AccountID); err != nil {
			if errors.Is(err, ownership.ErrNotAnOwner) {
				return ErrNotPublishable
			}
			return err
		}

		// And the key again, because two re-runs of the same workflow can be in flight together.
		// The primary key would refuse the second insert anyway; reading first turns that into the
		// original outcome rather than an error for a caller who did nothing wrong.
		if existing, err := q.GetIdempotencyKey(ctx, sqlitegen.GetIdempotencyKeyParams{
			AccountID:      req.AccountID,
			Operation:      operationPublishRelease,
			IdempotencyKey: key,
		}); err == nil {
			if existing.RequestHash != requestHash {
				return ErrIdempotencyKeyReused
			}
			return errRaced{releaseID: existing.ReleaseID}
		} else if !errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("read the idempotency key: %w", err)
		}

		if _, err := q.GetReleaseByVersion(ctx, sqlitegen.GetReleaseByVersionParams{
			PluginID: req.Submission.PluginID.String(),
			Version:  req.Submission.Version,
		}); err == nil {
			return ErrVersionExists
		} else if !errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("check the version: %w", err)
		}

		if err := q.InsertPublishRelease(ctx, params); err != nil {
			return fmt.Errorf("record the release of %s %s: %w",
				req.Submission.PluginID, req.Submission.Version, err)
		}

		if err := q.InsertIdempotencyKey(ctx, sqlitegen.InsertIdempotencyKeyParams{
			AccountID:      req.AccountID,
			Operation:      operationPublishRelease,
			IdempotencyKey: key,
			RequestHash:    requestHash,
			ReleaseID:      releaseID.String(),
			CreatedAt:      core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return fmt.Errorf("record the idempotency key: %w", err)
		}

		return audit.Record(ctx, q, p.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   req.AccountID,
			Action:      actionPublish,
			SubjectKind: subjectPluginKind,
			SubjectID:   req.Submission.PluginID.String(),
			Detail:      publishDetail(req.Submission, v, out),
		})
	})

	// A concurrent re-run of the same key got there first. Its release is the answer, and this
	// request's fetch was wasted work rather than a second row.
	var raced errRaced
	if errors.As(err, &raced) {
		return p.outcomeOf(ctx, raced.releaseID, true)
	}
	if err != nil {
		return Outcome{}, err
	}
	return out, nil
}

// errRaced carries a concurrent winner's release id out of the transaction.
//
// It is an error type rather than a captured variable because returning it ROLLS THE TRANSACTION
// BACK, which is the point: this request wrote nothing, and the row it would have written must not
// be committed alongside the discovery that somebody else already wrote one. internal/auth uses
// the same shape to carry a rejection out of the OAuth flow's transaction, for the same reason.
type errRaced struct{ releaseID string }

func (errRaced) Error() string { return "another request with this idempotency key committed first" }

// releaseParams builds the insert.
//
// THIS IS THE ONE PLACE A HASH REACHES release.artifact_sha256 ON A PUBLISH PATH. The value comes
// from artifact.StoredHash, which takes an artifact.Digest — a type no package outside
// internal/artifact can construct, obtainable only by hashing bytes that were fetched. Gate
// HASH001 fails any assignment to that field whose right-hand side is not that call, unless the
// same literal declares itself an import.
//
// The submitted digest is NOT in this function. It has already done its whole job, in verify.
func releaseParams(
	id core.ULID, req Request, v verdict, now time.Time,
) (sqlitegen.InsertPublishReleaseParams, error) {
	sub := req.Submission
	micros := core.MicrosFromTime(now).Int64()

	params := sqlitegen.InsertPublishReleaseParams{
		ID:       id.String(),
		PluginID: sub.PluginID.String(),
		Version:  sub.Version,
		// Everything goes to review in this phase; see the file comment.
		State:             StatePending.String(),
		ArtifactUrl:       sub.ArtifactURL,
		SdkSpecifier:      sub.SDKSpecifier,
		MinimumAppVersion: sub.MinimumAppVersion,
		SubmittedBy:       &req.AccountID,
		SubmittedAt:       micros,
		ReviewNote:        &v.review,
	}
	if sub.Notes != "" {
		notes := sub.Notes
		params.Notes = &notes
	}

	if !v.result.Digest.Computed() {
		// No bytes were fetched, so there is no hash and no verified_at. The row records that
		// something was submitted and could not be checked, which is a different fact from both
		// "it was fine" and "nothing happened".
		return params, nil
	}

	// THE ASSIGNMENT IS THE CALL, in one expression, and that is not a style preference. Gate
	// HASH001 reads the right-hand side of this assignment with go/ast and no type information, so
	// `stored, err := artifact.StoredHash(d)` followed by `params.ArtifactSha256 = stored` would
	// present the gate with a bare identifier to judge — and a gate that cannot see where a value
	// came from has to either guess or wave it through. Writing it this way is what makes the rule
	// checkable. It is also why StoredHash returns *string rather than (string, error).
	var err error
	params.ArtifactSha256, err = artifact.StoredHash(v.result.Digest)
	if err != nil {
		return sqlitegen.InsertPublishReleaseParams{},
			fmt.Errorf("store the hash for %s %s: %w", sub.PluginID, sub.Version, err)
	}

	// verified_at and the hash are set TOGETHER. The database reads that pairing as its own record
	// that this server computed the value -- see release_a_stored_hash_was_verified_or_imported --
	// so setting one without the other is a row SQLite refuses.
	bytes := v.result.Bytes
	verifiedAt := core.MicrosFromTime(v.result.FetchedAt).Int64()
	params.ArtifactBytes = &bytes
	params.VerifiedAt = &verifiedAt
	return params, nil
}

// publishDetail is the audit row's detail object.
//
// It carries no secret: a content hash is served in the index to anybody who asks, and the hosts
// are hostnames rather than URLs — a signed CDN URL keeps its signature in the query string, and
// audit_log is append-only by trigger and can never be redacted afterwards.
func publishDetail(sub Submission, v verdict, out Outcome) map[string]any {
	detail := map[string]any{
		"version":       sub.Version,
		"state":         out.State.String(),
		"verified":      v.verified,
		"artifact_host": hostOf(sub.ArtifactURL),
		"review":        v.review,
	}
	if v.result.Digest.Computed() {
		detail["computed_sha256"] = v.result.Digest.Hex()
		detail["artifact_bytes"] = v.result.Bytes
		detail["fetched_host"] = v.result.FinalHost
	}
	if !v.verified && v.result.Digest.Computed() {
		// Recorded ONLY on a mismatch, and alongside the computed value, because a mismatch is
		// unreadable without both halves. On the ordinary path the submitted digest equals the
		// stored one and writing it twice would say nothing.
		detail["submitted_sha256"] = sub.Submitted.String()
	}
	return detail
}

// hostOf returns a URL's hostname, for a log line or an audit row. Never the URL.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// hashRequest digests the fields that make a publish request what it is.
//
// It is what distinguishes a REPLAY of the same request from a key REUSED for a different one. The
// fields are joined with a separator that cannot appear in any of them, so that two different
// submissions cannot produce one string: a version of "1.0" with a URL of "x" and a version of
// "1.0\x00x" with no URL would otherwise collide, which is a way to make somebody else's replay
// answer your request.
//
// The submitted digest IS part of the identity of the request. Two submissions of one version with
// different claimed hashes are different requests, and the second one deserves a 409 rather than
// the first one's answer.
func hashRequest(sub Submission) string {
	minApp := ""
	if sub.MinimumAppVersion != nil {
		minApp = *sub.MinimumAppVersion
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		sub.PluginID.String(),
		sub.Version,
		sub.ArtifactURL,
		sub.Submitted.String(),
		sub.SDKSpecifier,
		minApp,
		sub.Notes,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// replay answers a request this server has already answered.
//
// A key that has been seen with the SAME request is answered from the row it produced: no fetch,
// no second release, no work. A key seen with a DIFFERENT request is a 409 — a caller who reused a
// key for a new version has made a mistake, and handing them the old release's id would tell them
// their new version published when it did not.
func (p *Publisher) replay(ctx context.Context, accountID, key, requestHash string) (Outcome, bool, error) {
	row, err := p.db.Read().GetIdempotencyKey(ctx, sqlitegen.GetIdempotencyKeyParams{
		AccountID:      accountID,
		Operation:      operationPublishRelease,
		IdempotencyKey: key,
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Outcome{}, false, nil
	case err != nil:
		return Outcome{}, false, fmt.Errorf("read the idempotency key: %w", err)
	case row.RequestHash != requestHash:
		return Outcome{}, true, ErrIdempotencyKeyReused
	}

	out, err := p.outcomeOf(ctx, row.ReleaseID, true)
	return out, true, err
}

// outcomeOf rebuilds an outcome from a release row, for a replay.
//
// It reads the row rather than remembering what was returned the first time, so a replay reports
// the release's state AS IT IS NOW. A release approved by a reviewer between the first call and
// the re-run should answer "approved" — telling a workflow "pending" because that is what it said
// an hour ago would be reporting a stale fact as a current one.
func (p *Publisher) outcomeOf(ctx context.Context, releaseID string, replayed bool) (Outcome, error) {
	row, err := p.db.Read().GetReleaseByID(ctx, releaseID)
	if err != nil {
		return Outcome{}, fmt.Errorf("read the release %s: %w", releaseID, err)
	}

	out := Outcome{
		ReleaseID: row.ID,
		State:     ReleaseState(row.State),
		// Verified is read from verified_at, which is the DATABASE'S record that this server
		// fetched the bytes and hashed them -- and which the
		// release_a_stored_hash_was_verified_or_imported CHECK ties to the hash being present.
		Verified: row.VerifiedAt != nil,
		Bytes:    row.ArtifactBytes,
		Replayed: replayed,
	}
	if row.ArtifactSha256 != nil {
		out.SHA256 = *row.ArtifactSha256
	}
	if row.ReviewNote != nil {
		out.Review = *row.ReviewNote
	}
	return out, nil
}

// checkAuthority answers whether this caller may publish this plugin at all.
//
// Three questions in the order that leaks the least. Ownership is asked FIRST and its failure is
// the same answer as "no such plugin", so a caller cannot use this endpoint to discover which ids
// are claimed. The identity question comes after, because answering it for a plugin somebody does
// not hold would confirm the plugin exists.
func (p *Publisher) checkAuthority(ctx context.Context, req Request) error {
	held, err := p.db.Read().GetPluginOwner(ctx, sqlitegen.GetPluginOwnerParams{
		PluginID:  req.Submission.PluginID.String(),
		AccountID: req.AccountID,
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return ErrNotPublishable
	case err != nil:
		return fmt.Errorf("check ownership of %s: %w", req.Submission.PluginID, err)
	}
	// A maintainer may publish; only an owner may change who holds the plugin. The role is read
	// through ownership.Role so this file does not grow its own opinion about what a role permits.
	if !ownership.Role(held.Role).Valid() {
		return fmt.Errorf("%w: the grant names role %q, which is not one", ErrNotPublishable, held.Role)
	}

	// ONLY GITHUB IDENTITIES MAY PUBLISH. The query reads identity_provider.can_publish, which is
	// a CHECK against the provider kind rather than a column an operator sets -- so the answer
	// comes from the same place the constraint does, and a Go switch cannot drift away from it.
	publishable, err := p.db.Read().CanAccountPublish(ctx, req.AccountID)
	if err != nil {
		return fmt.Errorf("check the publishing identity of %s: %w", req.AccountID, err)
	}
	if publishable == 0 {
		return ErrGitHubIdentityRequired
	}
	return nil
}

// checkVersionUnused reports ErrVersionExists for a version this plugin has already used.
//
// In ANY state. A rejected 1.2.0 does not free 1.2.0: the version is what a client has already
// seen, and letting it be reused after a rejection is how different bytes ship under a number
// somebody already installed.
func (p *Publisher) checkVersionUnused(ctx context.Context, sub Submission) error {
	_, err := p.db.Read().GetReleaseByVersion(ctx, sqlitegen.GetReleaseByVersionParams{
		PluginID: sub.PluginID.String(),
		Version:  sub.Version,
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("check the version %s of %s: %w", sub.Version, sub.PluginID, err)
	}
	return fmt.Errorf("%w: %s", ErrVersionExists, sub.Version)
}
