package repo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// GATE BACKUP001, third part: the deploy script is RUN, against a docker that misbehaves, and the
// deploy must be unreachable.
//
// The text half of this gate (backup_test.go) proves the failure branches say `FATAL`. It cannot
// prove they STOP, and that is a different claim: every one of those branches is inside `if !`,
// where `set -e` does nothing. Delete the `exit 1` from the volume-list branch and the script
// prints its FATAL, falls through to `[ -z "$volume" ]` — empty, because the command substitution
// failed — reports "first deploy, nothing to snapshot", and runs `compose pull && up -d` against a
// database it never backed up. The gate stayed green through all of that.
//
// So this half asserts the property itself: for each way the snapshot can fail, the script exits
// non-zero AND never reaches `docker compose pull`. `TestBACKUP001_TheExitsAreLoadBearing` then
// deletes the exits and requires every one of those scenarios to reach the deploy, which is what
// makes the scenarios above evidence rather than decoration.

// remoteScript extracts the script that runs ON THE DROPLET: the body of the quoted heredoc the
// deploy step pipes into `bash -seuo pipefail -s`.
//
// The runner's own `run:` block is not the subject. It opens an ssh connection, and what crosses it
// is this text — so this is the thing whose control flow decides whether a deploy proceeds.
func remoteScript(t *testing.T) string {
	t.Helper()

	const opener = "<<'REMOTE'"
	lines := strings.Split(deployWorkflow(t), "\n")

	start := -1
	for i, line := range lines {
		if strings.Contains(line, opener) {
			require.Equal(t, -1, start, "two heredocs named REMOTE; this extractor picks the wrong one")
			start = i + 1
		}
	}
	require.NotEqual(t, -1, start, "the deploy step no longer pipes a REMOTE heredoc to bash")

	var body []string
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "REMOTE" {
			// YAML strips the block's indentation before bash sees any of this, so the terminator
			// really is at column 0 in the script that runs.
			return dedent(body)
		}
		body = append(body, line)
	}
	t.Fatal("the REMOTE heredoc is never terminated")
	return ""
}

// dedent removes the YAML block indentation, which is what the YAML parser does on the runner.
func dedent(lines []string) string {
	width := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if width == -1 || indent < width {
			width = indent
		}
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) >= width {
			line = line[width:]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n") + "\n"
}

// dockerStub is how a scenario makes docker misbehave. Each field names a subcommand and what it
// should do; empty means "succeed and say the ordinary thing".
type dockerStub struct {
	// volumeLs is the stdout of `docker volume ls`. Empty means no volume exists.
	volumeLs string
	// volumeLsFails makes the daemon unreachable for that call — the case that used to be read as
	// "there is no volume yet".
	volumeLsFails bool

	// probeAnswer is what the containerised probe prints. probeFails is the image that would not
	// pull, the mount that did not work, the permission problem.
	probeAnswer string
	probeFails  bool

	// snapshot decides what the VACUUM INTO container leaves behind.
	snapshotFails     bool
	snapshotWritesNo  bool
	snapshotIntegrity string
}

// run executes a droplet script with this stub on PATH, and reports the exit status plus every
// docker invocation it made.
//
// The script is a PARAMETER rather than being read here, so the mutation test can hand it a
// modified one without a package-level switch — which would be shared mutable state across
// t.Parallel() subtests, and the race detector would be right about it.
func (s dockerStub) run(t *testing.T, script string) runResult {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "work"), 0o755))
	work := filepath.Join(dir, "work")

	// What the droplet already has before a deploy runs. The seed and compose preflights are not
	// this gate's subject and must not be what stops the script.
	write(t, filepath.Join(work, "compose.yaml.incoming"), "services: {}\n")
	write(t, filepath.Join(work, "seed.json"), `{"schema_version":1,"plugins":[]}`+"\n")
	write(t, filepath.Join(work, ".env"), "REGSERVE_IMAGE=ghcr.io/example/old\n")

	log := filepath.Join(dir, "docker.log")
	write(t, filepath.Join(bin, "docker"), s.script(log))
	require.NoError(t, os.Chmod(filepath.Join(bin, "docker"), 0o755))

	// `sed -i` with no suffix is GNU's spelling, which is what the droplet runs. BSD sed — on a
	// developer's Mac — requires an explicit empty suffix, and this gate is about control flow
	// rather than about sed, so the difference is absorbed here instead of skipping the test on
	// half the machines it should be protecting.
	write(t, filepath.Join(bin, "sed"), sedShim)
	require.NoError(t, os.Chmod(filepath.Join(bin, "sed"), 0o755))

	cmd := exec.CommandContext(t.Context(), "bash", "-seuo", "pipefail", "-s", "--", work, "ghcr.io/example/new")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	t.Logf("script output:\n%s", out)

	recorded, readErr := os.ReadFile(log)
	if readErr != nil {
		recorded = nil
	}

	if err == nil {
		return runResult{calls: string(recorded), work: work}
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "the script failed in a way that is not an exit status")
	return runResult{exitCode: exitErr.ExitCode(), calls: string(recorded), work: work}
}

// runResult is what one scenario produced: whether the script stopped, every docker call it made,
// and the droplet directory it left behind — because "did it stop" and "what did it leave in
// backups/" are two different questions and a corrupt snapshot must fail both.
type runResult struct {
	exitCode int
	calls    string
	work     string
}

// snapshots lists the finished snapshots in backups/, which is what a later restore would choose
// from. The dot-file the script writes first is deliberately not one of them until it is renamed.
func (r runResult) snapshots(t *testing.T) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(r.work, "backups", "pre-*.db"))
	require.NoError(t, err)
	return matches
}

// script renders the fake docker. It logs every call, then answers as the scenario dictates.
func (s dockerStub) script(log string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("printf '%s\\n' \"$*\" >> " + shellQuote(log) + "\n")
	b.WriteString("case \"$*\" in\n")

	b.WriteString("  'volume ls'*)\n")
	if s.volumeLsFails {
		b.WriteString("    echo 'Cannot connect to the Docker daemon' >&2; exit 1 ;;\n")
	} else {
		b.WriteString("    printf '%s' " + shellQuote(s.volumeLs) + "\n")
		if s.volumeLs != "" {
			b.WriteString("    printf '\\n'\n")
		}
		b.WriteString("    exit 0 ;;\n")
	}

	// The probe and the snapshot are both `docker run`; they are told apart the way a reader would.
	b.WriteString("  *'echo PRESENT'*)\n")
	if s.probeFails {
		b.WriteString("    echo 'Unable to find image' >&2; exit 125 ;;\n")
	} else {
		b.WriteString("    printf '%s\\n' " + shellQuote(s.probeAnswer) + "; exit 0 ;;\n")
	}

	b.WriteString("  *'VACUUM INTO'*)\n")
	switch {
	case s.snapshotFails:
		b.WriteString("    echo 'sqlite3: disk I/O error' >&2; exit 1 ;;\n")
	case s.snapshotWritesNo:
		b.WriteString("    : > backups/.snapshot.tmp; printf '%s\\n' " +
			shellQuote(s.snapshotIntegrity) + " > backups/.integrity; exit 0 ;;\n")
	default:
		b.WriteString("    printf 'a snapshot' > backups/.snapshot.tmp\n")
		b.WriteString("    printf '%s\\n' " + shellQuote(s.snapshotIntegrity) + " > backups/.integrity\n")
		b.WriteString("    exit 0 ;;\n")
	}

	b.WriteString("  *) exit 0 ;;\nesac\n")
	return b.String()
}

// sedShim gives the harness GNU `sed -i` semantics on a BSD sed. See dockerStub.run.
const sedShim = `#!/bin/sh
real=/usr/bin/sed
[ -x "$real" ] || real=/bin/sed
if "$real" --version >/dev/null 2>&1; then exec "$real" "$@"; fi
if [ "$1" = "-i" ]; then shift; exec "$real" -i '' "$@"; fi
exec "$real" "$@"
`

// deployReached is the string that must not appear in the recorded calls when a snapshot failed.
// It is the point of no return: `pull` fetches the image `up -d` then runs, applying a
// forward-only migration to the only copy of the data.
const deployReached = "compose pull"

func TestBACKUP001_AFailureBeforeTheSnapshot_NeverReachesTheDeploy(t *testing.T) {
	t.Parallel()

	const volume = "regserve_regserve-data"

	tests := []struct {
		name string
		stub dockerStub
	}{
		{
			// The one the previous review found: read as a boolean this said "no volume", and the
			// deploy carried on as a first deploy.
			name: "the daemon cannot be reached to list volumes",
			stub: dockerStub{volumeLsFails: true},
		},
		{
			name: "the probe container cannot run",
			stub: dockerStub{volumeLs: volume, probeFails: true},
		},
		{
			name: "the probe answers something that is neither PRESENT nor ABSENT",
			stub: dockerStub{volumeLs: volume, probeAnswer: "MAYBE"},
		},
		{
			name: "the snapshot command itself fails",
			stub: dockerStub{volumeLs: volume, probeAnswer: "PRESENT", snapshotFails: true},
		},
		{
			name: "the snapshot leaves an empty file",
			stub: dockerStub{
				volumeLs: volume, probeAnswer: "PRESENT",
				snapshotWritesNo: true, snapshotIntegrity: "ok",
			},
		},
		{
			name: "the snapshot is corrupt",
			stub: dockerStub{
				volumeLs: volume, probeAnswer: "PRESENT",
				snapshotIntegrity: "*** in database main *** Page 4: btreeInitPage() returns error code 11",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.stub.run(t, remoteScript(t))

			require.NotZero(t, got.exitCode, "the deploy script must fail")
			require.NotContains(t, got.calls, deployReached,
				"the deploy was reached after the snapshot failed; the calls were:\n%s", got.calls)
			require.NotContains(t, got.calls, "compose up",
				"the deploy was started after the snapshot failed")

			// And nothing that failed its checks is left wearing a finished snapshot's name. A
			// restore picks from these by timestamp, so a corrupt file among them is a backup that
			// will be chosen on the worst day.
			require.Empty(t, got.snapshots(t),
				"a snapshot that failed its checks was renamed into place anyway")
		})
	}
}

// TestBACKUP001_TheTwoBranchesThatMayContinue_StillDeploy is the other side.
//
// A gate that stopped every deploy would pass the test above and be useless. These are the only two
// states where there is genuinely nothing to snapshot, and both must still reach the deploy.
func TestBACKUP001_TheTwoBranchesThatMayContinue_StillDeploy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		stub dockerStub
	}{
		{name: "no volume at all: the first deploy on a droplet", stub: dockerStub{}},
		{
			name: "a volume whose server has never booted",
			stub: dockerStub{volumeLs: "regserve_regserve-data", probeAnswer: "ABSENT"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.stub.run(t, remoteScript(t))

			require.Zero(t, got.exitCode, "a deployment with nothing to snapshot must still deploy")
			require.Contains(t, got.calls, deployReached)
			require.NotContains(t, got.calls, "VACUUM INTO",
				"there was nothing to snapshot, so nothing should have been attempted")
		})
	}
}

// TestBACKUP001_AGoodSnapshot_DeploysAndKeepsTheFile is the happy path, which is what makes every
// assertion above about the FAILURE rather than about the harness being broken.
func TestBACKUP001_AGoodSnapshot_DeploysAndKeepsTheFile(t *testing.T) {
	t.Parallel()

	stub := dockerStub{volumeLs: "regserve_regserve-data", probeAnswer: "PRESENT", snapshotIntegrity: "ok"}
	got := stub.run(t, remoteScript(t))

	require.Zero(t, got.exitCode)
	require.Contains(t, got.calls, "VACUUM INTO", "a database that is there must be snapshotted")
	require.Contains(t, got.calls, deployReached)
	require.Len(t, got.snapshots(t), 1, "a good snapshot must be renamed into place and kept")
}

// TestBACKUP001_TheExitsAreLoadBearing is what makes the scenarios above a gate.
//
// It deletes every `exit 1` from the droplet script and requires each failure to reach the deploy.
// That is the mutation the text half could not see: those branches sit inside `if !`, so removing
// the exit leaves a script that prints FATAL and carries on — and the string "FATAL" is still in
// the file, so a search for it stays green.
func TestBACKUP001_TheExitsAreLoadBearing(t *testing.T) {
	t.Parallel()

	const volume = "regserve_regserve-data"

	tests := []struct {
		name string
		stub dockerStub
	}{
		{name: "the volume list fails", stub: dockerStub{volumeLsFails: true}},
		{name: "the probe fails", stub: dockerStub{volumeLs: volume, probeFails: true}},
		{
			name: "the snapshot is corrupt",
			stub: dockerStub{volumeLs: volume, probeAnswer: "PRESENT", snapshotIntegrity: "malformed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mutated := withoutExitStatements(remoteScript(t))
			require.Contains(t, mutated, "FATAL: could not list docker volumes",
				"the diagnostics must survive the mutation, or this proves nothing about the text half")

			got := tc.stub.run(t, mutated)

			require.Zero(t, got.exitCode,
				"without its exits the script does NOT stop -- which is the whole finding")
			require.Contains(t, got.calls, deployReached,
				"without its exits the deploy IS reached, so the exits are what the gate is gating")
		})
	}
}

// withoutExitStatements removes the lines that stop the script, keeping every message.
func withoutExitStatements(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) == "exit 1" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// shellQuote renders a value as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
