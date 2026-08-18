# Deploying to the DigitalOcean droplet

The target is a droplet already running Traefik, which owns `:80`/`:443` and issues certificates.
The registry is one more service on the network Traefik watches; it publishes no ports of its own.

Public URL: **`https://nparseplugins.prokopto.dev`**

The pipeline is two workflows, split deliberately:

| Workflow | Trigger | What it does | Approval |
|---|---|---|---|
| `Release` | push to `main`, tag `v*` | Builds a multi-arch image, pushes to GHCR | none |
| `Deploy` | successful `Release`, or manual | SSHes to the droplet, snapshots the DB, `compose pull && up -d`, verifies | `production` environment |

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
# From your workstation, in a checkout of this repo. Use the same hostname as DEPLOY_HOST.
scp deploy/compose.yaml    deploy@droplet.prokopto.dev:/opt/regserve/compose.yaml
scp deploy/env.example     deploy@droplet.prokopto.dev:/opt/regserve/.env
```

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

### 2. On the droplet — access to the image

If the GHCR package is public, nothing to do. If it is private:

```bash
# As the deploy user. Use a PAT with read:packages ONLY.
echo "<github-pat>" | docker login ghcr.io -u <your-github-username> --password-stdin
```

### 3. In this repository — secrets, scoped to the `production` environment

**Create the environment first (step 5), then add these as _environment_ secrets on it** —
`Settings → Environments → production → Environment secrets`.

Not repository secrets. A repository secret is readable by any job in any workflow on the default
branch; an environment secret is readable only by a job that declares `environment: production`,
which is the job that cannot start until you approve it. The SSH key that reaches the droplet should
be gated by the same approval as the deploy itself, otherwise the approval gate protects the
*action* while leaving the *credential* available to anything else that runs.

| Secret | Value | How to get it |
|---|---|---|
| `DEPLOY_SSH_KEY` | The **private** half of a keypair made for this and nothing else | `ssh-keygen -t ed25519 -C "regserve-deploy" -f ./regserve-deploy -N ""` — paste the contents of `regserve-deploy`, then append `regserve-deploy.pub` to `/home/deploy/.ssh/authorized_keys` on the droplet |
| `DEPLOY_KNOWN_HOSTS` | The droplet's host key | `ssh-keyscan -t ed25519 <the same name you put in DEPLOY_HOST>` — run this **once, from a network you trust**, and paste the output |
| `DEPLOY_HOST` | A **hostname**, not an IP — e.g. `droplet.prokopto.dev` | Add an A record pointing at the droplet |

#### Use a hostname, and keyscan that same hostname

A droplet's public IP is not guaranteed stable — a rebuild or a resize can change it, and a
hard-coded IP turns that into a deploy that fails at the worst moment. Point an A record at the
droplet and put **that** in `DEPLOY_HOST`.

The part that bites: `known_hosts` entries are keyed by the exact name used to connect. If you
`ssh-keyscan` the IP and then connect to a hostname, the entry does not match, and the deploy fails
with a host-key error that reads like a man-in-the-middle rather than a configuration mistake — so
the natural reaction is to disable the check, which is the one thing that must not happen. Keyscan
the same string you put in `DEPLOY_HOST`:

```bash
ssh-keyscan -t ed25519 droplet.prokopto.dev
```

Prefer a host-specific record (`droplet.prokopto.dev`) over the service record
(`nparseplugins.prokopto.dev`). They resolve to the same machine today, but the service name is
something you may want to move to another host later — and SSH access following the service around
is how a deploy ends up pointed at the wrong box.

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

### 4. In this repository — variables, at the repository level

`Settings → Secrets and variables → Actions → Variables` — **repository** variables, not
environment ones:

| Variable | Value |
|---|---|
| `DEPLOY_USER` | `deploy` |
| `DEPLOY_PATH` | `/opt/regserve` |
| `REGSERVE_HOST` | `nparseplugins.prokopto.dev` |

These are repository-level for two reasons. None of them is sensitive — a username, a path and a
public hostname — so environment scoping buys nothing. And `REGSERVE_HOST` is referenced in the
job's `environment.url`, which GitHub evaluates as part of resolving the environment; a variable
defined *on* that environment is not reliably available at that point, so scoping it there can
render the deployment URL blank.

### 5. In this repository — the production environment

`Settings → Environments → New environment → production`.

Add yourself as a **required reviewer**. This is what turns a merge into a build and a deliberate
click into a deploy. Optionally restrict the environment to the `main` branch and tags.

### 6. First deploy

```bash
gh workflow run Deploy -f image_tag=edge
```

Then check it: `https://nparseplugins.prokopto.dev/healthz` and `/index.json`.

---

## How an update reaches production

1. Merge to `main`. `Release` builds and pushes `:edge` and `:sha-<full>`.
2. `Deploy` is queued and waits for your approval on the `production` environment.
3. On approval it snapshots `regserve.db` into `/opt/regserve/backups/pre-<timestamp>.db`, pins
   `REGSERVE_IMAGE` in `.env` to the exact image, pulls, and restarts the container.
4. It polls `/healthz`, then fetches `/index.json` and asserts it parses and declares
   `schema_version: 1`.

Step 4 is not ceremony. A container that boots but serves a malformed index has taken down the
plugin browser for every installed client at once, and that failure is invisible from the outside —
the process is healthy, the certificate is valid, and every user sees "registry is malformed".

Tagged releases (`v1.2.0`) publish `:1.2.0`, `:1.2` and `:latest`. To deploy one:

```bash
gh workflow run Deploy -f image_tag=1.2.0
```

## Rolling back

Deploys pin an exact image, so a rollback is a deploy of the previous one:

```bash
gh workflow run Deploy -f image_tag=sha-<previous-full-sha>
```

**If the bad release included a migration, the image alone is not enough.** Migrations are
forward-only ([ADR-0006](../adr/0006-atlas-authors-goose-applies.md)) — there are no down
migrations, and an older binary will refuse a newer schema at boot. Restore the snapshot:

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
