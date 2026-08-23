# Deploying to the DigitalOcean droplet

The target is a droplet already running Traefik, which owns `:80`/`:443` and issues certificates.
The registry is one more service on the network Traefik watches; it publishes no ports of its own.

Public URL: **`https://nparseplugins.prokopto.dev`**

The pipeline is two workflows, split deliberately:

| Workflow | Trigger | What it does | Approval |
|---|---|---|---|
| `Release` | push to `main`, tag `v*` | Builds a multi-arch image, pushes to GHCR | none |
| `Deploy` | successful `Release`, or manual | SSHes to the droplet, ships `compose.yaml`, checks the seed file, snapshots the DB, `compose pull && up -d`, verifies | `production` environment |

Building is safe and automatic. Applying an image to the machine holding the only copy of the
ownership records is neither, which is why it is a separate, approvable step.

---

## What you need to set up

### 1. On the droplet — a deploy user and the compose stack

```bash
# As root on the droplet.
adduser --disabled-password --gecos "" deploy
usermod -aG docker deploy          # needed to run `docker compose`; it is root-equivalent, so this
                                    # user should do nothing else

install -d -o deploy -g deploy -m 750 /opt/regserve
install -d -o deploy -g deploy -m 750 /opt/regserve/backups
```

Copy two files from this repo into `/opt/regserve/`:

```bash
# From your workstation, in a checkout of this repo. The hostname is REGSERVE_HOST — one name
# for SSH and for HTTPS.
scp deploy/compose.yaml    deploy@nparseplugins.prokopto.dev:/opt/regserve/compose.yaml
scp deploy/env.example     deploy@nparseplugins.prokopto.dev:/opt/regserve/.env
```

> **This is the only time you copy `compose.yaml` by hand.** Every deploy ships the version that
> came with the release and overwrites what is there, keeping the previous one as
> `compose.yaml.prev`. It is here at all so you can bring the stack up manually before the first
> deploy.
>
> **So a hand-edit to `/opt/regserve/compose.yaml` survives until the next deploy and no longer.**
> Change `deploy/compose.yaml` in the repository instead — that is the copy that wins, and it is the
> one anybody reviewing this service will read.
>
> `.env` is the opposite and always will be: it holds secrets, so it stays on the host and no
> pipeline ever writes it. When a release needs a new variable, the deploy fails on it *before*
> swapping anything, naming the variable.

Then, **on the droplet**, fill in `/opt/regserve/.env` and lock it down:

```bash
chmod 600 /opt/regserve/.env
```

`REGSERVE_HOST` is already `nparseplugins.prokopto.dev`. Set `TRAEFIK_NETWORK` to whatever
`docker network ls` shows Traefik on — commonly `traefik` or `proxy` — and generate the pepper:

```bash
openssl rand -base64 32     # -> REGSERVE_TOKEN_PEPPER
```

> **The pepper is effectively permanent.** Every PAT is stored as `HMAC-SHA256(pepper, secret)`,
> so rotating it invalidates every issued token at once and every plugin pipeline fails to publish
> until its owner mints a new one. Generate it once, back it up somewhere you will still have in a
> year, and change it only if it has leaked.

**The OAuth secrets stay here, on the host. They never go through GitHub Actions.** A secret routed
through a pipeline is a secret in that pipeline's logs, its cache, and the context of every pull
request from a fork. CI ships an image; the host holds the credentials.

#### Reviewers

`REGSERVE_REVIEWERS` is a comma-separated list of GitHub handles: the people who may approve what
this registry lists.

```bash
REGSERVE_REVIEWERS=prokopto-dev,someone-else
```

**This is the only way to grant moderation, and that is deliberate.** There is no column and no API
endpoint that makes somebody a reviewer — a row would be one somebody can `UPDATE` at 2am, and an
endpoint would be an escalation path. The authority to decide what every installed client downloads
comes from control of *this file*, which is the same place it came from when the registry was a
GitHub repository and a merge button.

Three things follow, and each has bitten somebody somewhere:

- **Unset means nobody can approve anything.** Not "everybody" — nobody. Releases will publish,
  verify, and sit in the queue for ever. `compose.yaml` defaults it to empty
  (`${REGSERVE_REVIEWERS:-}`), so this is the state a deployment is in until somebody sets it, and
  it is announced twice:
  - **At boot, as a `WARN`,** whether or not anything is waiting:
    `no reviewers are configured; nothing submitted to this registry can ever be approved`, or
    `releases are waiting for review and no reviewers are configured` once there is a backlog. Both
    carry `needs=REGSERVE_REVIEWERS`. The first used to be an `INFO`, which is where this hid: an
    empty queue is not evidence the setting is fine, it is what an unreachable queue looks like.
  - **On the account page of every signed-in visitor,** because an author waiting on a release
    needs it more than the operator does. The page says the registry has no reviewers and names the
    variable. It never says who the reviewers are, or how many — an empty list is a fault worth
    reporting; a populated one is a list of people to work through.
- **A handle grants nothing until that person has signed in here at least once.** The check
  resolves against a proven `identity` row, so a typo grants nobody rather than granting whoever
  registers that name next.
- **Removing a handle takes effect on that person's next request**, no restart needed. The list is
  read per request.

Reviewing is capability-floor: no personal access token can approve a release however it is scoped,
including a reviewer's own. Moderation is a browser-and-session operation only.

##### Working the queue

A configured reviewer signs in and gets a **review queue** link in the page header; the pages are at
`/review` and `/review/releases/{id}`, served by the same binary as everything else.

**If the link is not there, the account page says which of the two reasons applies:** this account
is not one of the configured reviewers, or the registry has no configured reviewers at all. Those
are different problems — the first is somebody else's account to fix, the second is this file — and
until the page distinguished them, both looked like a queue that happened to be empty.

The queue lists what is waiting, oldest first. Opening a release shows **why it is there** — every
quarantine rule that fired when it was submitted, read from the audit row the publish wrote rather
than recomputed — the hash this server computed, the hash the submitter claimed when the two
disagree, the notes that will be published to every client, and the release's audit trail. Approve,
reject and re-verify are forms on that page.

Two things a reviewer will meet:

- **A release whose artifact was never fetched cannot be approved**, and the button is not offered.
  The database refuses a listing with no hash, so the way out is a re-verification or a rejection.
- **A rejection must say why.** The author cannot see this queue and has no other way to learn what
  to fix.

Nothing on these pages edits history. `audit_log` is append-only by trigger, a rejected version is
never freed, and a superseded release is kept — so the record of what was approved, and by whom,
survives every decision made after it.

### 2. On the droplet — the catalogue

The catalogue lives in the database, on the `/data` volume. `seed.json` is how it got there: on the
first boot with an **empty** database the server imports the file and never reads it again. A
database that already holds plugins is never overwritten by a file on disk, so the mount is
harmless once it has done its job — and it must stay in place until it has.

`compose.yaml` starts the server with `--seed /etc/regserve/seed.json`, mounted read-only from
`/opt/regserve/seed.json`.

```bash
# As the deploy user, in /opt/regserve.
curl -fsS https://prokopto-dev.github.io/nparseplus-plugins/index.json -o seed.json
chmod 644 seed.json
```

`644` is not laziness: the container runs as uid `65532`, which matches nothing on the host, so the
file has to be world-readable or the server cannot open it.

The service is deliberately unable to start with a seed it cannot use. A missing file fails
`compose up` outright (`create_host_path: false`, so Docker will not helpfully create a directory in
its place), an unreadable or malformed one exits at boot naming the file, and the deploy workflow
checks it before it pulls anything. The seed is read and validated **before** the database is
touched, on every boot, whether or not it will be needed — so a file that has quietly rotted is
found on the deploy that follows, not on the day the volume turns out to be empty.

The failure this arrangement refuses to have is the quiet one: a container that comes up, answers
`/healthz` with `ok`, and serves an empty catalogue to every installed client.

**Removing the seed once the database holds the catalogue is safe** — drop the `--seed` flag and the
bind mount together, in the same change to `deploy/compose.yaml`. Leaving them is also safe, and is
the better default while `/data` is young enough that a volume loss is plausible: the seed is then
the thing that repopulates a fresh database.

### 3. On the droplet — access to the image

If the GHCR package is public, nothing to do. If it is private:

```bash
# As the deploy user. Use a PAT with read:packages ONLY.
echo "<github-pat>" | docker login ghcr.io -u <your-github-username> --password-stdin
```

### 4. In this repository — secrets, scoped to the `production` environment

**Create the environment first (step 6), then add these as _environment_ secrets on it** —
`Settings → Environments → production → Environment secrets`.

Not repository secrets. A repository secret is readable by any job in any workflow on the default
branch; an environment secret is readable only by a job that declares `environment: production`,
which is the job that cannot start until you approve it. The SSH key that reaches the droplet should
be gated by the same approval as the deploy itself, otherwise the approval gate protects the
*action* while leaving the *credential* available to anything else that runs.

| Secret | Value | How to get it |
|---|---|---|
| `DEPLOY_SSH_KEY` | The **private** half of a keypair made for this and nothing else | `ssh-keygen -t ed25519 -C "regserve-deploy" -f ./regserve-deploy -N ""` — paste the contents of `regserve-deploy`, then append `regserve-deploy.pub` to `/home/deploy/.ssh/authorized_keys` on the droplet |
| `DEPLOY_KNOWN_HOSTS` | The droplet's host key | `ssh-keyscan -t ed25519 nparseplugins.prokopto.dev` — the **exact string** in `REGSERVE_HOST`, scanned **once, from a network you trust**; paste the output |

There is no `DEPLOY_HOST`. The deploy SSHes to `vars.REGSERVE_HOST` (step 5), the same name it then
fetches over HTTPS — one record, one string to keep in step with `DEPLOY_KNOWN_HOSTS`.

That name was a secret until it cost four deploys. It is published in `deploy/env.example`, in this
file and in public DNS, so secrecy bought nothing; what it did buy was log masking, which rendered
`ssh: Could not resolve hostname ***` and hid which name was wrong. The credential
(`DEPLOY_SSH_KEY`) and the host-key pin (`DEPLOY_KNOWN_HOSTS`) are still secrets, so the security
posture is unchanged: knowing the hostname gets you as far as knowing the hostname.

#### Use a hostname, and keyscan that same hostname

A droplet's public IP is not guaranteed stable — a rebuild or a resize can change it, and a
hard-coded IP turns that into a deploy that fails at the worst moment. Point an A record at the
droplet and put **that** in `REGSERVE_HOST`.

The part that bites: `known_hosts` entries are keyed by the exact name used to connect. If you
`ssh-keyscan` the IP and then connect to a hostname, the entry does not match, and the deploy fails
with a host-key error that reads like a man-in-the-middle rather than a configuration mistake — so
the natural reaction is to disable the check, which is the one thing that must not happen. Keyscan
the same string you put in `REGSERVE_HOST`:

```bash
ssh-keyscan -t ed25519 nparseplugins.prokopto.dev
```

This droplet uses the **service record itself** — `nparseplugins.prokopto.dev` — for SSH as well as
for HTTPS. One name, one record, nothing extra to maintain.

The tradeoff to remember: if the registry is ever moved to a different host, `REGSERVE_HOST` and
`DEPLOY_KNOWN_HOSTS` move with it, because SSH access follows the service name. Updating both at the
same time as the A record is the whole of the discipline that requires.

Belt and braces: a DigitalOcean **Reserved IP** attached to the droplet makes the address itself
stable, so the A record only changes when you deliberately move it.

`DEPLOY_KNOWN_HOSTS` is pinned rather than scanned at deploy time on purpose: scanning trusts
whatever answers, which makes every deploy a free opportunity for a man-in-the-middle.

Lock the deploy key down further in `/home/deploy/.ssh/authorized_keys` if you want belt and
braces — prefixing the key with `from="140.82.112.0/20,143.55.64.0/20"` restricts it to GitHub's
ranges, at the cost of having to update it when those change.

If the droplet is ever rebuilt it gets a **new host key**, and every deploy will then fail on a
mismatch until you re-run `ssh-keyscan` and update `DEPLOY_KNOWN_HOSTS`. That failure is correct
behaviour, not a bug — a changed host key is indistinguishable from an interception, and the only
safe response is to re-verify out of band.

### 5. In this repository — variables, at the repository level

`Settings → Secrets and variables → Actions → Variables` — **repository** variables, not
environment ones:

| Variable | Value |
|---|---|
| `DEPLOY_USER` | `deploy` |
| `DEPLOY_PATH` | `/opt/regserve` |
| `REGSERVE_HOST` | `nparseplugins.prokopto.dev` — the SSH target, the HTTPS host and the environment URL |

These are repository-level for two reasons. None of them is sensitive — a username, a path and a
public hostname — so environment scoping buys nothing. And `REGSERVE_HOST` is referenced in the
job's `environment.url`, which GitHub evaluates as part of resolving the environment; a variable
defined *on* that environment is not reliably available at that point, so scoping it there can
render the deployment URL blank.

### 6. In this repository — the production environment

`Settings → Environments → New environment → production`.

Add yourself as a **required reviewer**. This is what turns a merge into a build and a deliberate
click into a deploy. Optionally restrict the environment to the `main` branch and tags.

### 7. First deploy

```bash
gh workflow run Deploy -f image_tag=edge -f source_ref=main
```

`source_ref` is the commit the image was built from, and it is what the compose file is taken from.
For an automatic deploy the workflow fills both in from the triggering release; for a manual one you
name them, and they must match — see [Pairing the image with its compose file](#pairing-the-image-with-its-compose-file).

Then check it — all three, in this order, because each failure means something different:

```bash
curl -fsS https://nparseplugins.prokopto.dev/healthz   # the process is up
curl -fsS https://nparseplugins.prokopto.dev/readyz    # the database answers and the catalogue renders
curl -fsS https://nparseplugins.prokopto.dev/index.json | head -c 400
```

`/readyz` says *why* when it is not ready. "no database is configured" means `REGSERVE_DB_PATH`
never reached the container; "the database could not be opened" means the `/data` volume is missing
or unwritable, and the reason is in `docker compose logs`. Neither is fatal to the process on
purpose: `/healthz` stays green so a brief volume problem does not restart-loop a container that
would recover.

The image ships `/data` owned by uid `65532`, and Docker applies that ownership when it initialises
an empty named volume — so the first boot can create the database. **A bind mount gets none of
that**: Docker never changes the ownership of a host directory, so `chown 65532:65532` it yourself
before starting, or the log will read `permission denied` on `/data/regserve.db`.

On the **first** boot against an empty database the log carries one line that matters:

```bash
docker compose logs regserve | grep catalogue
# "catalogue imported from the seed file"  path=/etc/regserve/seed.json plugins=N
# "catalogue loaded"                       plugins=N
```

Every boot after that says `seed file not imported` with a `reason`, and there are three:

| `reason` | What it means |
|---|---|
| `the database already holds a catalogue` | Normal. Every boot after the first |
| `a seed has already been imported into this database` | Normal, and the same statement made by the audit log rather than the plugin table |
| `the seed file lists no plugins` | **The file is empty.** Nothing was written — not even the import marker — so fixing the file and restarting still imports it |

If you ever see `the catalogue is empty`, the import did not happen and `/index.json` is about to
report an empty registry to every client — check the seed mount before anything else.

---

## How an update reaches production

1. Merge to `main`. `Release` builds and pushes `:edge` and `:sha-<full>`.
2. `Deploy` is queued and waits for your approval on the `production` environment.
3. On approval it checks out **the commit that release was built from**, copies its
   `deploy/compose.yaml` to the droplet, validates it
   against the host's `.env` (`docker compose config -q`, which fails on a malformed file *and* on
   any required variable the `.env` is missing), and adopts it — keeping `compose.yaml.prev`.
4. It asserts `/opt/regserve/seed.json` exists and is non-empty, snapshots `regserve.db` into
   `/opt/regserve/backups/pre-<timestamp>.db`, pins `REGSERVE_IMAGE` in `.env` to the exact image,
   pulls, and restarts the container.
5. It polls `/healthz`, then `/readyz`, then fetches `/index.json` and asserts it parses and
   declares `schema_version: 1`.

Steps 3 and 4 are what stop a release and the stack running it from drifting apart. The compose file
used to be copied once, at setup, and never again — so a release that added a flag started against a
compose file that had never heard of it. That is not hypothetical: it is exactly how a container came
up with no catalogue while `/healthz` answered `ok`.

The seed check in step 4 comes **before** the pull for the same reason the snapshot does: after
`compose up` the old container is already gone, so a failure there is a failure with nothing to fall
back to. It is a shell test — exists, non-empty — and no more than that honestly can be; the file's
contents are the server's business, and the server refuses to start on a file it cannot use.

Step 5 is not ceremony. A container that boots but serves a malformed index has taken down the
plugin browser for every installed client at once, and that failure is invisible from the outside —
the process is healthy, the certificate is valid, and every user sees "registry is malformed".

Tagged releases (`v1.2.0`) publish `:1.2.0`, `:1.2` and `:latest`. To deploy one:

```bash
gh workflow run Deploy -f image_tag=1.2.0 -f source_ref=v1.2.0
```

### Pairing the image with its compose file

The image and the compose file must come from one commit. The workflow checks out `source_ref` and
ships **that** commit's `deploy/compose.yaml`, rather than the default branch's — because a deploy
waits for a human, `main` keeps moving while it waits, and staging a newer compose file against an
older image would give you a container running with flags, mounts or required variables from a
release it was never built for. Nothing about that failure looks wrong in the run log.

For an automatic deploy both values come from the triggering release and cannot disagree. For a
manual one:

| `image_tag` | `source_ref` | Verified? |
|---|---|---|
| `sha-<full>` | `<full>` | Yes — the workflow fails if they disagree |
| `1.2.0` | `v1.2.0` | No — a tag is not commit-derived; the run prints which commit it used |
| `edge` | `main` | No, and `edge` moves. Prefer `sha-<full>` for anything reproducible |

Where it cannot verify the pairing, the run says so rather than implying a guarantee it has not
made.

## Updating the catalogue

**The catalogue is the database now.** Editing `seed.json` and recreating the container does
nothing: the import runs only against an empty database, on purpose, because the alternative is a
restart silently reverting every publish made since the file was written.

Until the publish API lands (Phase 3) there are exactly two honest ways to change the catalogue, and
both should be rare:

1. **Write the rows.** Stop the container, snapshot the database, and use `sqlite3` on the volume.
   A listing is a `plugin` row plus one `release` row at `state = 'approved'`; the CHECK constraints
   will refuse a hash that is not 64 lowercase hex characters, a URL that is not `https`, an
   approved release with no hash, and a second approved release for the same plugin. Record what you
   did in `audit_log` — it is append-only, so the row you write is the row that stays.
2. **Start over from a seed.** Snapshot the database, remove it, and let the next boot re-import
   `seed.json`. This throws away every publish and every ownership row the database holds, so it is
   only reasonable while the database holds nothing but the import.

The seed file below is still worth keeping current for case 2.

```bash
# On the droplet, as deploy, in /opt/regserve.
cp seed.json seed.json.prev                       # the only rollback there is

curl -fsS https://prokopto-dev.github.io/nparseplus-plugins/index.json -o seed.json
```

**Validate before recreating.** A seed that does not parse fails the boot — the server reads and
validates it before it touches the database — and the deploy-time preflight does not run here:

```bash
python3 - seed.json <<'CHECK'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("schema_version") == 1, f"schema_version is {d.get('schema_version')}, not 1"
assert isinstance(d["plugins"], list), "plugins must be a list"
for p in d["plugins"]:
    assert p["latest"]["url"].lower().startswith("https://"), f"{p['id']}: url is not https"
    assert len(p["latest"]["sha256"]) == 64, f"{p['id']}: sha256 is not 64 characters"
print(f"{len(d['plugins'])} plugin(s) - looks servable")
CHECK
```

That is a smoke test, not the server's validator: the server applies the full schema-v1 rules and is
the authority on what it will serve. This catches the mistakes people actually make by hand.

Then pick the file up — remembering that on a database that already holds a catalogue this changes
nothing served, and only refreshes what a future empty database would import:

```bash
docker compose up -d --force-recreate regserve
docker compose logs --tail 20 regserve          # "seed file not imported" reason="the database already holds a catalogue"
curl -fsS https://nparseplugins.prokopto.dev/readyz
```

`up -d --force-recreate`, not `restart`. Docker binds a **file** mount by inode, and any tool that
writes by rename — `mv`, and most editors — leaves the running container looking at the old file
with no error anywhere. Recreating the container re-resolves the path. Re-apply `chmod 644` if you
replaced the file rather than overwriting it.

To roll back: `cp seed.json.prev seed.json` and recreate again.

## Rolling back

Deploys pin an exact image, so a rollback is a deploy of the previous one:

```bash
gh workflow run Deploy -f image_tag=sha-<previous-full-sha> -f source_ref=<previous-full-sha>
```

**Rolling back restores that release's `compose.yaml` too** — the deploy ships the compose file from
`source_ref`, so naming the old commit rolls back both together. Naming the wrong one is the whole
hazard, which is why a `sha-<full>` tag is checked against the checkout and fails the run rather than
deploying a mismatched pair. The file being replaced is kept as `compose.yaml.prev`.

**If the bad release included a migration, the image alone is not enough.** Migrations are
forward-only ([ADR-0006](../adr/0006-atlas-authors-goose-applies.md)) — there are no down
migrations, and an older binary **refuses to start** against a newer schema rather than serving
against columns it does not know about. That refusal is deliberate and is the signal to restore the
snapshot the deploy took immediately before the migration ran:

```bash
# On the droplet, as deploy:
cd /opt/regserve
docker compose stop regserve
docker run --rm -v regserve_regserve-data:/data -v "$PWD/backups:/backups" alpine:3 \
  sh -c "cp /backups/pre-<timestamp>.db /data/regserve.db"
sed -i "s|^REGSERVE_IMAGE=.*|REGSERVE_IMAGE=ghcr.io/prokopto-dev/nparse-plugin-regserve:<old>|" .env
docker compose up -d regserve
```

## Downtime, and why it is acceptable

`compose up -d` stops the old container before starting the new one, so there are a few seconds of
502. There is no rolling restart, and there should not be: the service is one SQLite writer
([ADR-0001](../adr/0001-go-single-binary-and-sqlite.md)), and two containers sharing that volume is
precisely the situation the design assumes cannot happen.

A few seconds is genuinely fine here. The desktop client fetches the index on browse and once,
twelve seconds after launch; a failed fetch is reported per-registry and retried on the next browse.
Nobody loses work.

## Backups

The deploy takes one before each change and keeps the last ten. That covers "the deploy broke it"
and nothing else — it is not a backup strategy, because it only runs when you deploy.

Add a daily one:

```bash
# /etc/cron.daily/regserve-backup  (root, chmod 755)
#!/bin/sh
set -eu
docker run --rm -v regserve_regserve-data:/data -v /opt/regserve/backups:/backups alpine:3 \
  sh -c "cp /data/regserve.db /backups/daily-$(date -u +%Y%m%d).db"
find /opt/regserve/backups -name 'daily-*.db' -mtime +30 -delete
```

Copy them off the droplet. A backup on the same disk as the database survives a bad migration and
nothing else — not a failed droplet, not a deleted volume, not the droplet being destroyed.

> `cp` of a live SQLite file in WAL mode can capture a torn copy. It is good enough for a service
> with this write rate, and the honest fix once it matters is `sqlite3 .backup` or `VACUUM INTO`
> from inside the container. Recorded here rather than glossed over.

## What is deliberately not here

**Watchtower or any unattended image updater.** `compose.yaml` sets
`com.centurylinklabs.watchtower.enable: "false"` explicitly. An automatic swap can apply a
forward-only migration to the only copy of the ownership records with nobody watching and no
snapshot taken. If you run Watchtower for other services on this droplet, that label is what keeps
it away from this one — do not remove it.
