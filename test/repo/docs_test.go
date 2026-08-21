package repo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// DOC003, watched failing.
//
// `.github/workflows/publish-plugin.yml` is consumed by OTHER repositories through `workflow_call`:
// it runs their release job, with their publish token. So the ref this repository publishes decides
// what runs next to somebody else's secret, and it has to be one that CANNOT MOVE.
//
// A tag is not one. `git tag -f` and a force-push repoint `v0.3.0`, and every pipeline that copied
// it runs different code on its next release with no diff and no notification — `@main`'s property
// spelled slower. The tag still has to appear in a comment, because forty hex characters do not say
// which release a reader is on; and there has to be exactly ONE commit across every page, because
// two pages quoting different SHAs is drift where neither looks wrong on its own.
//
// The gate is shell, and shell gates fail in the direction that reports success: a grep pattern
// that stops matching prints "no findings" over files it never read, which is indistinguishable
// from a clean tree. So these point it at trees it must reject.

// doc003 runs the documentation gates with DOC003 reading `dir` instead of the repository, and
// returns that gate's line.
//
// The other gates in the script still run against the real repository and still pass, so a failure
// here is DOC003's. The line is returned rather than the exit code for exactly that reason: an
// exit code cannot say which gate produced it.
func doc003(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}

	cmd := exec.CommandContext(t.Context(), "bash", docsCheck())
	cmd.Env = append(os.Environ(), "DOC003_SOURCES="+dir)
	out, _ := cmd.CombinedOutput()

	// A GATE line, not merely a line mentioning the gate. Every gate prints its name in colour, so
	// its line starts with the escape; a finding's detail lines are indented plain text. Matching
	// on the substring alone once returned DOC002's list of unregistered gates, which contains the
	// string "DOC003" and says nothing about what DOC003 decided.
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "\x1b[") && strings.Contains(line, "DOC003") {
			return line
		}
	}
	require.Failf(t, "DOC003 printed nothing", "the gate must report either way:\n%s", out)
	return ""
}

// docsCheck is the gate script. Named once so the two callers cannot drift onto different paths.
func docsCheck() string { return filepath.Join("..", "..", "scripts", "docs-check.sh") }

// uses builds a reference to the reusable workflow at ref.
func uses(ref string) string {
	return "    uses: prokopto-dev/nparse-plugin-regserve/.github/workflows/publish-plugin.yml@" + ref
}

// sha is a whole commit, and pinned is that commit with the release comment DOC003 requires.
const (
	sha    = "5b0d87f7666f20c0c188b7208ad2738bd55c10d7"
	pinned = " # v0.3.0"
)

// TestDOC003_FiresOnEveryRefThatCanBeMoved — the mistake the gate exists for.
//
// The tag case is the one worth having: it is what this documentation used to publish, and it read
// as careful. A movable label handed to somebody whose CI runs it with their publish token is not
// a pin however carefully it is spelled.
func TestDOC003_FiresOnEveryRefThatCanBeMoved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ref  string
		why  string
	}{
		{
			name: "a branch",
			ref:  "main",
			why:  "`@main` means the caller's pipeline changes when this repository does",
		},
		{
			name: "a release tag",
			ref:  "v0.3.0",
			why: "`git tag -f` and a force-push repoint it, and every pipeline that copied it " +
				"runs new code on its next release with no diff and no notification",
		},
		{
			name: "a major-version alias",
			ref:  "v1",
			why:  "a floating major tag moves by design",
		},
		{
			name: "a named ref that is not a version",
			ref:  "release",
			why:  "anything a maintainer can repoint is not a pin",
		},
		{
			name: "a short sha",
			ref:  "5b0d87f",
			why:  "an abbreviated sha is ambiguous and GitHub does not resolve it for `uses:`",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			line := doc003(t, map[string]string{"publishing.md": uses(tc.ref) + pinned})
			require.Containsf(t, line, "movable ref",
				"DOC003 must refuse @%s: %s\ngot: %s", tc.ref, tc.why, line)
		})
	}
}

// TestDOC003_FiresOnTwoSpellingsOfThePin — one ref, two places, and they disagree.
//
// This is the drift a review does not catch. The publish page and the adoption doc are edited
// months apart by people looking at one file each, and neither looks wrong on its own.
func TestDOC003_FiresOnTwoSpellingsOfThePin(t *testing.T) {
	t.Parallel()

	other := "0603b68f284eb39a687e75845d70d5a4e5d2f0be"

	line := doc003(t, map[string]string{
		"publishing.md": uses(sha) + pinned,
		"web/page.html": uses(other) + " # v0.2.0",
	})
	require.Contains(t, line, "2 different commits",
		"DOC003 must refuse two commits: an author reaching one page publishes through a "+
			"version the other page does not document")
}

// TestDOC003_FiresOnAShaThatDoesNotSayWhichReleaseItIs.
//
// A commit SHA is the only immutable ref and it is also unreadable. Without the release beside it
// a reader cannot tell whether their pipeline is on the version the page documents, and a pin
// nobody can place is a pin nobody ever updates.
func TestDOC003_FiresOnAShaThatDoesNotSayWhichReleaseItIs(t *testing.T) {
	t.Parallel()

	naked := doc003(t, map[string]string{"publishing.md": uses(sha)})
	require.Contains(t, naked, "do not name the release",
		"DOC003 must refuse a commit pin with no release beside it")

	named := doc003(t, map[string]string{"publishing.md": uses(sha) + pinned})
	require.Contains(t, named, "pinned to one commit",
		"a commit that names its release is the whole rule and must pass")
}

// TestDOC003_FiresWhenOnlySomeReferencesNameTheirRelease.
//
// The page and the doc are edited separately, so "one of them carries the comment" is a state the
// gate has to reach and refuse rather than count as covered.
func TestDOC003_FiresWhenOnlySomeReferencesNameTheirRelease(t *testing.T) {
	t.Parallel()

	line := doc003(t, map[string]string{
		"publishing.md": uses(sha) + pinned,
		"web/page.html": uses(sha),
	})
	require.Contains(t, line, "1 reference(s) do not name the release")
}

// TestDOC003_IsVacantRatherThanGreen_WhenNothingReferencesTheWorkflow.
//
// A gate that inspected nothing must never look like a gate that found nothing. If the reference
// is renamed out from under the pattern, this is what says so.
func TestDOC003_IsVacantRatherThanGreen_WhenNothingReferencesTheWorkflow(t *testing.T) {
	t.Parallel()

	line := doc003(t, map[string]string{"unrelated.md": "# nothing to see"})
	require.Contains(t, line, "nothing to check yet",
		"DOC003 must report vacant over a tree with no reference at all")
}

// TestDOC003_PassesTheRepositoryItGuards — the gate agrees with the tree it ships in.
//
// Without this the tests above would all pass over fixtures while the real documentation said
// `@main`, which is the one arrangement worse than having no gate.
func TestDOC003_PassesTheRepositoryItGuards(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "bash", docsCheck())
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "the documentation gates must pass:\n%s", out)
	require.Contains(t, string(out), "the reusable workflow is pinned to one commit")
}
