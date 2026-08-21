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
// it runs their release job, with their publish token. Every reference this repository publishes
// therefore has to be a pin — `@main` hands an author an upgrade that arrives on their release day
// — and there has to be exactly ONE of them, because the website and the adoption doc quoting
// different refs is drift where neither page looks wrong on its own.
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

// TestDOC003_FiresOnEveryRefThatIsNotAPin — the mistake the gate exists for.
func TestDOC003_FiresOnEveryRefThatIsNotAPin(t *testing.T) {
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
			name: "a major-version alias",
			ref:  "v1",
			why:  "a floating major tag moves, which is the same defect spelled shorter",
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

			line := doc003(t, map[string]string{"publishing.md": uses(tc.ref)})
			require.Containsf(t, line, "moving ref",
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

	line := doc003(t, map[string]string{
		"publishing.md": uses("v0.3.0"),
		"web/page.html": uses("v0.2.0"),
	})
	require.Contains(t, line, "2 different tags",
		"DOC003 must refuse two tags: an author reaching one page publishes through a version "+
			"the other page does not document")
}

// TestDOC003_FiresOnAShaThatDoesNotSayWhichReleaseItIs.
//
// The SHA form is offered as the STRONGER pin — a tag can be moved and a SHA cannot — so it has to
// stay readable. Forty bare hex characters tell a reader nothing about whether the pin is the
// release the page around it documents.
func TestDOC003_FiresOnAShaThatDoesNotSayWhichReleaseItIs(t *testing.T) {
	t.Parallel()

	const sha = "5b0d87f7666f20c0c188b7208ad2738bd55c10d7"

	naked := doc003(t, map[string]string{
		"publishing.md": uses("v0.3.0") + "\n" + uses(sha),
	})
	require.Contains(t, naked, "do not name the tag",
		"DOC003 must refuse a SHA pin with no tag beside it")

	named := doc003(t, map[string]string{
		"publishing.md": uses("v0.3.0") + "\n" + uses(sha) + " # v0.3.0",
	})
	require.Contains(t, named, "pinned, at one tag",
		"a SHA that names its tag is the stronger pin and must pass")
}

// TestDOC003_FiresOnAShaWithNoTagAnywhere — a repository that documents only a SHA.
//
// It is a real pin and it is still a finding: nothing on the page says which release it is, so
// there is no readable form for an author to check theirs against.
func TestDOC003_FiresOnAShaWithNoTagAnywhere(t *testing.T) {
	t.Parallel()

	line := doc003(t, map[string]string{
		"publishing.md": uses("5b0d87f7666f20c0c188b7208ad2738bd55c10d7"),
	})
	require.Contains(t, line, "no tag reference")
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
	require.Contains(t, string(out), "the reusable workflow is pinned, at one tag")
}
