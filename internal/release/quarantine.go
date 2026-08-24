package release

import (
	"fmt"
	"net/url"
	"strings"
)

// The quarantine rules (ADR-0007): the transitions that send a release to a human REGARDLESS of
// how much this service trusts the account that submitted it.
//
// They exist because trust is a judgement about a PERSON and these are facts about a CHANGE. An
// owner who has published fifty good releases is exactly who an attacker wants to be when they
// publish the fifty-first, and the useful signal at that moment is not who submitted it but that
// the artifact moved to a different host, or halved in size, or carries a version number that goes
// backwards.
//
// THE THRESHOLDS ARE A JUDGEMENT CALL. docs/concepts/invariants.md records that honestly rather
// than pretending the numbers are derived: the RULES are tested, the NUMBERS are reviewed when they
// produce a false positive. What is not a judgement call is the direction to be wrong in — a rule
// that cannot evaluate sends the release to review.

// QuarantineReason is one rule that fired. The values are written for a human reading a review
// queue at speed, so each names the observation rather than the rule.
type QuarantineReason string

const (
	// ReasonFirstRelease is the first appearance of a plugin id. ADR-0007 makes this
	// non-negotiable: nothing bypasses it, not trust, not automation, not an owner who has
	// published fifty times. The first appearance of an id is where impersonation is caught.
	ReasonFirstRelease QuarantineReason = "this is the plugin's first release, and a new plugin id always gets human review"

	// ReasonNotVerified is an artifact this server could not fetch. There is no hash, so there is
	// nothing to publish even if somebody wanted to.
	ReasonNotVerified QuarantineReason = "the artifact could not be fetched, so its bytes were never checked"

	// ReasonHashMismatch is the submitted sha256 disagreeing with the bytes. Something between the
	// author's build and this fetch changed them.
	ReasonHashMismatch QuarantineReason = "the submitted sha256 does not match the artifact this server fetched"

	// ReasonHostChanged is the artifact moving to a different host. It is how a hijacked domain or
	// a redirected release pipeline first shows up, and it is cheap for a legitimate author to
	// explain.
	ReasonHostChanged QuarantineReason = "the artifact is hosted somewhere other than the previous release"

	// ReasonSizeDelta is the artifact changing size sharply. A plugin that triples is a plugin
	// that gained something, and what it gained is worth a look.
	ReasonSizeDelta QuarantineReason = "the artifact's size differs sharply from the previous release"

	// ReasonVersionNotHigher is a version that does not advance. A version going backwards is what
	// a downgrade looks like: ship 1.0.0 again with different bytes, and a client comparing
	// version strings believes it is up to date.
	ReasonVersionNotHigher QuarantineReason = "the version does not advance on the current release"

	// ReasonVersionUncomparable is a version this service cannot order against the current one.
	// It is a SEPARATE reason from the above because they mean different things to a reviewer:
	// one is a release going backwards, the other is a versioning scheme nobody here can read.
	ReasonVersionUncomparable QuarantineReason = "the version cannot be ordered against the current release"
)

func (r QuarantineReason) String() string { return string(r) }

// sizeDeltaNumerator and sizeDeltaDenominator express the size threshold as a ratio rather than a
// float, so the arithmetic is exact and a reader can see the fraction.
//
// A HALF. An artifact that shrinks past half or grows past one-and-a-half times the previous
// release goes to review. The number is a judgement: nParse+ plugins are small and their releases
// are usually incremental, so a jump of this size is unusual enough to be worth a glance and
// common enough not to be. It is the kind of constant that should be revisited the first time it
// produces a false positive, and that is recorded rather than hidden.
const (
	sizeDeltaNumerator   = 1
	sizeDeltaDenominator = 2
)

// previous is what a plugin's current live release looked like, for comparison.
type previous struct {
	// exists is false when the plugin has nothing approved. Every other field is meaningless then,
	// which is why this is a struct rather than a set of nillable parameters.
	exists bool

	version     string
	artifactURL string
	bytes       *int64
}

// evaluateQuarantine returns every rule that fired, in the order a reviewer would want to read
// them: the reasons about the ARTIFACT first, because they are about bytes, and the ones about the
// submission's shape after.
//
// It returns ALL of them rather than the first. A release that changed host AND jumped in size AND
// went backwards is a different story from one that only changed host, and a reviewer who is shown
// one reason will investigate one thing.
func evaluateQuarantine(prev previous, sub Submission, v verdict) []QuarantineReason {
	var reasons []QuarantineReason

	// The artifact first. These are the ones about bytes, and they hold whether or not there is
	// anything to compare against.
	switch {
	case !v.result.Digest.Computed():
		reasons = append(reasons, ReasonNotVerified)
	case !v.verified:
		// Fetched, hashed, and the submitter's claim disagreed.
		reasons = append(reasons, ReasonHashMismatch)
	}

	if !prev.exists {
		// A NEW PLUGIN ID. Nothing below applies — there is nothing to compare against — and
		// nothing above it matters either, because this alone is enough.
		return append(reasons, ReasonFirstRelease)
	}

	if hostOf(sub.ArtifactURL) != hostOf(prev.artifactURL) {
		reasons = append(reasons, ReasonHostChanged)
	}

	if sizeChangedSharply(prev.bytes, v) {
		reasons = append(reasons, ReasonSizeDelta)
	}

	switch compareVersions(prev.version, sub.Version) {
	case versionHigher:
		// The ordinary case: this release advances on the live one.
	case versionUnknown:
		reasons = append(reasons, ReasonVersionUncomparable)
	default:
		reasons = append(reasons, ReasonVersionNotHigher)
	}

	return reasons
}

// sizeChangedSharply reports whether the artifact's size moved past the threshold.
//
// An unknown size on EITHER side does not fire the rule. That is deliberate and is the one place
// here where "cannot check" does not mean "quarantine": a missing size means the artifact was
// never fetched, which has already produced ReasonNotVerified — adding a second reason for the
// same fact would tell a reviewer two things went wrong when one did.
func sizeChangedSharply(prevBytes *int64, v verdict) bool {
	if prevBytes == nil || *prevBytes <= 0 || !v.result.Digest.Computed() {
		return false
	}

	before, after := *prevBytes, v.result.Bytes
	// Integer arithmetic on the difference rather than a ratio of floats: the comparison is exact,
	// and a zero-length previous release cannot divide by zero because it is excluded above.
	var delta int64
	if after > before {
		delta = after - before
	} else {
		delta = before - after
	}
	return delta*sizeDeltaDenominator > before*sizeDeltaNumerator
}

// hostOf returns a URL's hostname, lower-cased, for comparison.
//
// THE SUBMITTED URL'S HOST, never the one the redirect chain landed on. A GitHub release asset
// redirects to a CDN whose hostname varies between requests, so comparing final hosts would fire
// this rule on every release and teach reviewers to ignore it. The submitted URL is the stable
// statement of where the author says their artifact lives.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// quarantineNote renders the reasons into the sentence stored on the release and shown to whoever
// reviews it.
//
// fetchFailure is artifact.Reason's sentence when the artifact could not be fetched, and it
// REPLACES the generic ReasonNotVerified text. ADR-0008 requires the reason recorded, and "the
// artifact could not be fetched" is not the reason — "not verified: the artifact could not be
// downloaded within the time limit" is. A reviewer deciding whether to re-verify needs to know
// whether they are looking at a timeout, a 404, or an address this service refuses to connect to,
// and those call for three different actions.
func quarantineNote(reasons []QuarantineReason, fetchFailure string) string {
	if len(reasons) == 0 {
		// Unreachable: decide() calls this only when a rule fired, and a release that is waiting
		// for any other cause carries that cause's own sentence. Returning the bare one here
		// rather than the empty string keeps a future caller from writing a row whose note is
		// blank -- review_note is the only explanation an author ever gets.
		return "awaiting human review"
	}

	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if r == ReasonNotVerified && fetchFailure != "" {
			parts = append(parts, fetchFailure)
			continue
		}
		parts = append(parts, r.String())
	}

	if len(parts) == 1 {
		return parts[0]
	}
	// Numbered, because a reviewer scanning a queue needs to know at a glance whether a release
	// has one problem or four, and a semicolon-joined sentence hides that.
	return fmt.Sprintf("%d reasons: %s", len(parts), strings.Join(parts, "; "))
}
