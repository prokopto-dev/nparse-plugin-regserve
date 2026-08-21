package repo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The GitHub Actions gates, watched failing.
//
// ACT001 and ACT002 are shell, and shell gates fail in the direction that reports success: an awk
// pattern that stops matching reports "no findings" over a file it never read, and looks exactly
// like a clean tree. That is not hypothetical here — the first version of ACT001 matched only
// `run: |`, so `run: echo "${{ github.ref_name }}"` walked past the gate whose entire purpose is
// that line, green all the way.
//
// So these tests point the gate at deliberately broken workflows and require it to fire. They are
// the reason scripts/act-gates.sh takes a directory instead of hard-coding .github/workflows.

// actGate runs one gate over a directory of fixtures and returns its exit code and output.
func actGate(t *testing.T, mode string, workflows map[string]string) (int, string) {
	t.Helper()

	dir := t.TempDir()
	for name, body := range workflows {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}

	cmd := exec.CommandContext(t.Context(), "bash", filepath.Join("..", "..", "scripts", "act-gates.sh"), mode, dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}

	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "the gate must exit with a status, not fail to run: %s", out)
	return exit.ExitCode(), string(out)
}

// TestACT001_FiresOnEveryWayAnExpressionCanReachAScript — the shapes that must all be findings.
//
// Each is a real spelling GitHub accepts, and each puts a caller-controlled value into the text of
// a script before bash sees it. The dash and no-dash forms are listed separately because they are
// two different lines to an awk pattern and one line to a person.
func TestACT001_FiresOnEveryWayAnExpressionCanReachAScript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		why  string
	}{
		{
			name: "a plain scalar on the run line",
			yaml: step(`      - run: echo "${{ github.ref_name }}"`),
			why:  "the spelling the first version of this gate did not look at",
		},
		{
			name: "a plain scalar that continues onto the next line",
			yaml: step("      - run: echo one\n          && echo \"${{ github.event.head_commit.message }}\""),
			why:  "a commit message is the most attacker-controlled string in a workflow",
		},
		{
			name: "a block scalar",
			yaml: step("      - name: x\n        run: |\n          echo \"${{ github.actor }}\""),
			why:  "the form the gate was written for",
		},
		{
			name: "a folded block scalar",
			yaml: step("      - name: x\n        run: >\n          echo \"${{ github.actor }}\""),
			why:  "> is a block indicator too",
		},
		{
			name: "a block scalar with a chomping indicator",
			yaml: step("      - name: x\n        run: |-\n          echo \"${{ github.actor }}\""),
			why:  "|- and |+ are the same block, differently chomped",
		},
		{
			name: "a secret",
			yaml: step("      - name: x\n        run: |\n          printf '%s' \"${{ secrets.DEPLOY_KNOWN_HOSTS }}\" > hosts"),
			why:  "this exact line was in deploy.yml before the gate existed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, out := actGate(t, "expressions", map[string]string{"broken.yml": tt.yaml})
			require.Equal(t, 1, code, "ACT001 must fail this workflow: %s\n%s", tt.why, out)
			require.Contains(t, out, "interpolates an expression")
			require.Contains(t, out, "broken.yml", "the finding must name the file")
		})
	}
}

// TestACT001_PassesWhatItShould is the other half, and the half that keeps the gate usable.
//
// A gate with false positives gets switched off, so the shapes below must all be clean: an
// expression in `env:` (which is the fix the gate recommends), an expression in a step key that is
// not a script, and an `env:` block belonging to a step whose `run:` is written with the list dash
// — which a scanner measuring the wrong indentation would read as script.
func TestACT001_PassesWhatItShould(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "the recommended fix",
			yaml: step("      - name: x\n        env:\n          REF: ${{ github.ref_name }}\n        run: |\n          echo \"$REF\""),
		},
		{
			name: "an expression in a with: block",
			yaml: step("      - uses: ./local\n        with:\n          tag: ${{ github.ref_name }}"),
		},
		{
			name: "an env: block after a dash-form run:",
			yaml: step("      - run: make check\n        env:\n          TOKEN: ${{ secrets.X }}"),
		},
		{
			name: "an expression in a job-level if",
			yaml: "name: t\non: push\njobs:\n  j:\n    if: ${{ github.ref_name != 'main' }}\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make check\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, out := actGate(t, "expressions", map[string]string{"fine.yml": tt.yaml})
			require.Equal(t, 0, code,
				"ACT001 must NOT fail this workflow; a gate with false positives gets switched "+
					"off, which is worse than the problem it was added for\n%s", out)
		})
	}
}

// TestACT002_FiresOnAScriptThatDoesNotParse — the syntax gate, in both spellings of `run:`.
func TestACT002_FiresOnAScriptThatDoesNotParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			// An unterminated heredoc INSIDE a construct that has to close. The bare case —
			// `cat <<EOF` with no terminator and nothing around it — is deliberately not asserted
			// here: bash 5 warns about it and bash 3.2, which is what macOS ships, accepts it in
			// silence. The gate reports any diagnostic as a finding, so CI (bash 5) catches it and
			// a laptop may not, and pretending otherwise in a test would be asserting something
			// that is false on half the machines that run it.
			name: "an unterminated heredoc inside an if",
			yaml: step("      - name: x\n        run: |\n          if true; then\n            cat <<EOF\n            body"),
		},
		{
			name: "an unbalanced quote in a block",
			yaml: step("      - name: x\n        run: |\n          echo \"open"),
		},
		{
			name: "an unbalanced quote in a plain scalar",
			yaml: step(`      - run: echo "open`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, out := actGate(t, "syntax", map[string]string{"broken.yml": tt.yaml})
			require.Equal(t, 1, code, "ACT002 must fail this workflow\n%s", out)
			require.Contains(t, out, "does not parse")
		})
	}
}

// TestACT002_FiresWhenNothingWasExtracted — the vacancy check.
//
// A scanner that stopped recognising `run:` would report "no findings" over every workflow in the
// repository and be indistinguishable from a clean tree. So extracting zero scripts from a
// directory that HAS workflows is itself the finding: a checker that checked nothing must never
// look like a checker that found nothing.
func TestACT002_FiresWhenNothingWasExtracted(t *testing.T) {
	t.Parallel()

	code, out := actGate(t, "syntax", map[string]string{
		"noscripts.yml": "name: t\non: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./local\n",
	})
	require.Equal(t, 1, code, "a workflow directory with no extracted scripts is a finding\n%s", out)
	require.Contains(t, out, "not matching")
}

// TestACT002_PassesAWorkflowThatParses keeps the test above honest: if the gate failed everything,
// every assertion in this file would pass while the gate was useless.
func TestACT002_PassesAWorkflowThatParses(t *testing.T) {
	t.Parallel()

	code, out := actGate(t, "syntax", map[string]string{
		"fine.yml": step("      - name: x\n        run: |\n          set -euo pipefail\n          cat <<EOF\n          a heredoc that ends\n          EOF\n      - run: make check"),
	})
	require.Equal(t, 0, code, "a workflow whose scripts parse must pass\n%s", out)
	require.Equal(t, "2", strings.TrimSpace(out), "both spellings of run: must have been extracted")
}

// step wraps step YAML in the smallest workflow that contains it.
func step(steps string) string {
	return "name: t\non: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n" + steps + "\n"
}
