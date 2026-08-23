package repo_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// GATE BACKUP001 (the half that is about the workflow): the pre-deploy snapshot is taken with a
// WAL-safe method, and a snapshot that fails stops the deploy.
//
// The SQLite half — that `cp` of a live WAL database silently loses committed rows and
// `VACUUM INTO` does not — is proved in internal/store/backup_test.go. This half asserts the
// workflow actually uses it, because a correct method nobody runs is not a backup.
//
// Both failures shipped together, in the step whose own comment calls the file it produces "the
// only undo that exists":
//
//	alpine:3 sh -c 'cp /data/regserve.db "/backups/pre-…db" 2>/dev/null' \
//	  || echo "no database file yet; nothing to snapshot"
//
// The `cp` took the main file and not the WAL. The `2>/dev/null || echo` then turned a permission
// error, a full disk and an sqlite failure into the same reassuring sentence — and the next lines
// are `compose pull && up -d`, which applies a forward-only migration. A deploy that walked past a
// failed backup did so quietly and arrived at the point of no return with nothing behind it.

// deployWorkflowPath is relative, like cataloguePath in authz_test.go: these tests run from their
// own directory and reach back into the repository they are about.
const deployWorkflowPath = "../../.github/workflows/deploy.yml"

// deployWorkflow is the file under test. Read as TEXT, deliberately: the properties below are about
// what the shell on the droplet will execute, and a YAML-aware reading would still have to look at
// the same string.
func deployWorkflow(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(deployWorkflowPath)
	require.NoError(t, err)
	return string(raw)
}

// executableLines strips every comment, so this gate reads CODE and not the prose about it.
//
// It is the difference between a gate and a decoration. The snapshot step is now heavily commented
// — the comments explain WHY it is `VACUUM INTO` and mention `integrity_check` by name — so a
// whole-file search for those strings would stay green with the actual `sqlite3` invocations
// deleted. That is a gate that passes because somebody wrote a paragraph, which is precisely the
// "reports success without having done its job" shape the rest of this PR is about.
//
// A line whose first non-blank character is `#` is a comment in both languages here: YAML's, and
// the shell inside the `run:` block. Neither has a trailing-comment form that matters for these
// checks, because every command asserted below is the whole of its line.
func executableLines(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// backupFindings returns what is wrong with a deploy script's snapshot, empty when nothing is.
//
// A function rather than assertions inline, so the same judgement can be run over the shapes this
// gate exists to reject — see the two fires-on tests. A gate that has never been shown to fail is a
// gate nobody knows the polarity of.
func backupFindings(wholeFile string) []string {
	// Everything below is asked of the CODE. That also makes the negative check correct rather
	// than merely stricter: a comment explaining that `cp /data/regserve.db` is the wrong way to
	// do this must not be the thing that fails the gate.
	script := executableLines(wholeFile)

	var found []string

	if !strings.Contains(script, "VACUUM INTO") {
		found = append(found, "the snapshot does not use VACUUM INTO")
	}
	// The exact shape that shipped. Any copy of the live database file is wrong for the same
	// reason, whatever it is named on the way out.
	if strings.Contains(script, "cp /data/regserve.db") {
		found = append(found, "the snapshot copies the live database file, which omits the WAL")
	}
	if !strings.Contains(script, "integrity_check") {
		found = append(found, "the snapshot is never checked for integrity")
	}
	// The swallow. `|| echo` on the snapshot turns every failure into a message and a green step.
	if strings.Contains(script, `|| echo "no database file yet`) {
		found = append(found, "a failed snapshot is reported as 'no database file yet' and continues")
	}
	if !strings.Contains(script, "FATAL: the pre-deploy snapshot") {
		found = append(found, "no branch stops the deploy when the snapshot is missing or bad")
	}
	// The probes have to ESTABLISH absence, not infer it from a non-zero exit. `docker volume
	// inspect` and a containerised `test -f` both fail for a daemon that is not answering, an
	// image that will not pull and a mount that did not work — and read as a boolean, every one of
	// those becomes "no database, carry on" and walks into the migration with nothing behind it.
	// That is the same fail-open shape as the `|| echo` above, one level up.
	if strings.Contains(script, "docker volume inspect") {
		found = append(found, "the volume probe reads a non-zero exit as 'no volume'")
	}
	if !strings.Contains(script, "echo PRESENT") || !strings.Contains(script, "echo ABSENT") {
		found = append(found, "the database probe does not answer positively")
	}
	return found
}

func TestBACKUP001_TheDeploySnapshotIsWALSafeAndFailsLoudly(t *testing.T) {
	t.Parallel()

	require.Empty(t, backupFindings(deployWorkflow(t)))
}

// TestBACKUP001_FirstDeployStillPasses.
//
// The one branch that may continue WITHOUT a snapshot is a volume that does not exist yet, or one
// with no database in it. Tightening the failure path is only correct if it left that alone —
// otherwise this gate would have traded a silent bad backup for a deployment that can never make
// its first one.
func TestBACKUP001_FirstDeployStillPasses(t *testing.T) {
	t.Parallel()

	script := deployWorkflow(t)
	require.Contains(t, script, "no data volume yet; first deploy",
		"a droplet with no volume must still deploy")
	require.Contains(t, script, "no database in the volume yet",
		"a volume whose server has never booted must still deploy")
}

// TestBACKUP001_FiresOnTheSnapshotItExistsToRefuse feeds it the block that shipped.
func TestBACKUP001_FiresOnTheSnapshotItExistsToRefuse(t *testing.T) {
	t.Parallel()

	shipped := `
          mkdir -p backups
          stamp="$(date -u +%Y%m%dT%H%M%SZ)"
          if docker volume inspect regserve_regserve-data >/dev/null 2>&1; then
            docker run --rm \
              -v regserve_regserve-data:/data \
              -v "$PWD/backups:/backups" \
              alpine:3 sh -c 'cp /data/regserve.db "/backups/pre-'"$stamp"'.db" 2>/dev/null' \
              || echo "no database file yet; nothing to snapshot"
          else
            echo "no data volume yet; first deploy"
          fi
`

	found := backupFindings(shipped)
	require.ElementsMatch(t, []string{
		"the snapshot does not use VACUUM INTO",
		"the snapshot copies the live database file, which omits the WAL",
		"the snapshot is never checked for integrity",
		"a failed snapshot is reported as 'no database file yet' and continues",
		"no branch stops the deploy when the snapshot is missing or bad",
		"the volume probe reads a non-zero exit as 'no volume'",
		"the database probe does not answer positively",
	}, found, "each finding must be the one it was written for, not any finding at all")
}

// TestBACKUP001_FiresWhenTheCommandGoesAndTheProseStays is the mutation half, and it is the one
// that decides whether this gate is real.
//
// Each case deletes an executable line from the ACTUAL workflow and leaves every comment intact —
// the shape a well-meaning edit produces, and the shape a whole-file string search cannot see. The
// fixture asserts the prose survived before asserting the finding fires, so a case can never pass
// by having removed the explanation along with the command.
func TestBACKUP001_FiresWhenTheCommandGoesAndTheProseStays(t *testing.T) {
	t.Parallel()

	real := deployWorkflow(t)

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "the vacuum statement",
			command: "VACUUM INTO",
			want:    "the snapshot does not use VACUUM INTO",
		},
		{
			name:    "the integrity check",
			command: "integrity_check",
			want:    "the snapshot is never checked for integrity",
		},
		{
			name:    "the refusal that stops the deploy",
			command: "FATAL: the pre-deploy snapshot",
			want:    "no branch stops the deploy when the snapshot is missing or bad",
		},
		{
			name:    "the positive answer from the database probe",
			command: "echo PRESENT",
			want:    "the database probe does not answer positively",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mutated := withoutExecutableLinesContaining(real, tc.command)

			require.NotContains(t, executableLines(mutated), tc.command,
				"the mutation must actually remove the command")
			if strings.Contains(commentLines(real), tc.command) {
				// The whole point: the file still TALKS about it. A gate reading the file as one
				// string would find the string and report green over code that no longer runs.
				require.Contains(t, mutated, tc.command,
					"the prose must survive, or this fixture is not testing what it claims")
			}
			require.Contains(t, backupFindings(mutated), tc.want)
		})
	}
}

// TestBACKUP001_FiresWhenTheUnsafeCopyComesBackInCode.
//
// The negative check has the same problem in reverse: it must fire on a `cp` that RUNS and stay
// quiet about a `cp` somebody wrote down in a comment as the thing not to do.
func TestBACKUP001_FiresWhenTheUnsafeCopyComesBackInCode(t *testing.T) {
	t.Parallel()

	real := deployWorkflow(t)
	const finding = "the snapshot copies the live database file, which omits the WAL"

	t.Run("a comment describing it is not a finding", func(t *testing.T) {
		t.Parallel()

		commented := real + "\n          # never do this: cp /data/regserve.db /backups/whatever.db\n"
		require.NotContains(t, backupFindings(commented), finding)
	})

	t.Run("the same line as code is", func(t *testing.T) {
		t.Parallel()

		executed := real + "\n          cp /data/regserve.db /backups/whatever.db\n"
		require.Contains(t, backupFindings(executed), finding)
	})
}

// withoutExecutableLinesContaining deletes the lines that RUN and mention `command`, keeping every
// comment that mentions it.
func withoutExecutableLinesContaining(script, command string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		isComment := strings.HasPrefix(strings.TrimSpace(line), "#")
		if !isComment && strings.Contains(line, command) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// commentLines is executableLines' complement, for asserting what the prose still says.
func commentLines(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
