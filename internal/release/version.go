package release

import (
	"strconv"
	"strings"
)

// Comparing two versions, for one purpose: deciding whether a submission goes BACKWARDS.
//
// ADR-0007 lists "the version is not greater than the current latest" among the quarantine rules,
// because a version that goes backwards is what a downgrade attack looks like — ship 1.0.0 again
// with different bytes, and any client comparing version strings believes it is up to date.
//
// # This is not a PEP 440 implementation, and must not become one
//
// The client evaluates version semantics; this service CARRIES them (db/schema.hcl says so about
// the column name). A registry that enforced its own idea of PEP 440 would start refusing releases
// the client would have accepted, and the divergence would show up as a plugin author unable to
// publish a version their own tooling produced.
//
// So this answers a narrower question — "is B clearly greater than A" — and is allowed to say
// I DO NOT KNOW. That third answer is the important one: an unknown comparison sends the release
// to review rather than publishing it, because "cannot check" must never resolve to "allow". The
// cost is a human looking at an unusual version scheme, which is cheap and visible.
//
// What it handles: dotted numeric releases, an optional epoch (`1!2.0`), a leading `v`, and
// pre-release or local suffixes attached to the final number. What it refuses to judge: anything
// where the ordering would depend on knowing that `rc` sorts before nothing and `dev` before `a`.

// versionOrder is the result of a comparison.
type versionOrder int

const (
	// versionUnknown means the two cannot be compared with confidence. It is FIRST so that the
	// zero value of a versionOrder is the safe answer rather than "equal".
	versionUnknown versionOrder = iota
	versionLower
	versionEqual
	versionHigher
)

// compareVersions reports how candidate orders against current.
//
// A suffix on either side that is not purely numeric makes the answer versionUnknown UNLESS the
// numeric parts already differ. `1.2.0rc1` against `1.1.0` is clearly higher whatever `rc1` means;
// `1.2.0rc1` against `1.2.0` is not, because whether a release candidate precedes its release is
// exactly the thing this refuses to decide.
func compareVersions(current, candidate string) versionOrder {
	curEpoch, curParts, curSuffix := splitVersion(current)
	newEpoch, newParts, newSuffix := splitVersion(candidate)

	if curEpoch != newEpoch {
		return orderOf(newEpoch - curEpoch)
	}
	if curParts == nil || newParts == nil {
		// One of them has no numeric spine at all — a date string, a git sha, a name. There is
		// nothing to compare.
		return versionUnknown
	}

	for i := 0; i < len(curParts) || i < len(newParts); i++ {
		// A missing component is zero, so 1.2 and 1.2.0 compare equal. That matches every
		// versioning scheme in use and is the one normalisation worth making.
		a, b := partAt(curParts, i), partAt(newParts, i)
		if a != b {
			return orderOf(b - a)
		}
	}

	// The numeric parts are identical, so everything now depends on the suffixes.
	switch {
	case curSuffix == "" && newSuffix == "":
		return versionEqual
	case curSuffix == newSuffix:
		return versionEqual
	default:
		// One of `1.0.0` vs `1.0.0rc1`, `1.0.0a1` vs `1.0.0b2`, `1.0.0+local.1` vs `1.0.0`. Each
		// has an answer under PEP 440 and none of them is one this service should be deciding.
		return versionUnknown
	}
}

// orderOf turns a difference into an order.
func orderOf(diff int) versionOrder {
	switch {
	case diff > 0:
		return versionHigher
	case diff < 0:
		return versionLower
	default:
		return versionEqual
	}
}

func partAt(parts []int, i int) int {
	if i < len(parts) {
		return parts[i]
	}
	return 0
}

// splitVersion breaks a version into its epoch, its dotted numeric spine, and whatever trailed.
//
// It returns a nil spine when the value does not begin with a number after the optional `v` and
// epoch, which is the signal that nothing here can be compared.
func splitVersion(v string) (epoch int, parts []int, suffix string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")

	// PEP 440's epoch: `1!2.0` is a deliberate restart of a numbering scheme, and it outranks
	// everything without one.
	if before, after, found := strings.Cut(v, "!"); found {
		n, err := strconv.Atoi(before)
		if err != nil {
			return 0, nil, v
		}
		epoch, v = n, after
	}

	for i, segment := range strings.Split(v, ".") {
		digits := leadingDigits(segment)
		if digits == "" {
			// A segment with no leading number ends the spine. Everything from here is suffix,
			// including this segment.
			return epoch, parts, strings.Join(strings.Split(v, ".")[i:], ".")
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			// An integer too large for the platform's int. Unlikely, and still not a thing to
			// guess about.
			return epoch, nil, v
		}
		parts = append(parts, n)

		if rest := segment[len(digits):]; rest != "" {
			// `1.2.0rc1` — the spine ends here and `rc1` plus anything after it is the suffix.
			tail := strings.Split(v, ".")[i:]
			tail[0] = rest
			return epoch, parts, strings.Join(tail, ".")
		}
	}
	return epoch, parts, ""
}

// leadingDigits returns the run of digits at the start of s.
func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}
