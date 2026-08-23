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

// backupFindings returns what is wrong with a deploy script's snapshot, empty when nothing is.
//
// A function rather than assertions inline, so the same judgement can be run over the shape this
// gate exists to reject — see TestBACKUP001_FiresOnTheSnapshotItExistsToRefuse. A gate that has
// never been shown to fail is a gate nobody knows the polarity of.
func backupFindings(script string) []string {
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
	}, found, "each finding must be the one it was written for, not any finding at all")
}
