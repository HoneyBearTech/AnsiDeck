# AnsiDeck

[![CI](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml/badge.svg)](https://github.com/HoneyBearTech/AnsiDeck/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/HoneyBearTech/AnsiDeck/badge)](https://scorecard.dev/viewer/?uri=github.com/HoneyBearTech/AnsiDeck)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14718/badge)](https://www.bestpractices.dev/projects/14718)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/14718/baseline)](https://www.bestpractices.dev/projects/14718)

Self-hosted web UI for running Ansible playbooks against target systems, packaged in Docker.

> [!WARNING]
> **Runs change real systems**: every run executes `ansible-playbook` on the hosts you pick, and what it
> changes stays changed, even if you cancel it. Start with check mode and a narrow limit. **Deletes are
> permanent**: AnsiDeck asks first, but there is no undo. Keep [backups](docs/upgrading.md#back-up).

## Documentation

- [Quick start](docs/quick-start.md), [installing a release](docs/installing.md),
  [upgrading and backups](docs/upgrading.md) and [verifying releases](docs/verifying-releases.md).
- The [user guide](docs/user-guide/README.md): every page of the UI, from projects and credentials to runs
  and notifications. The [documentation index](docs/README.md) lists everything.
- [Architecture](docs/architecture.md): the components and how a run flows through them.
- [Security requirements](docs/security.md): what AnsiDeck does and doesn't protect against, and the
  [assurance case](docs/assurance-case.md) behind it.
- [Roadmap](docs/roadmap.md): where the project is going, and what it won't do.
- [Accessibility](docs/accessibility.md): what is checked (WCAG 2.1 AA) and the known gaps.
- [External interfaces](docs/interfaces.md) (the HTTP API is described in
  [docs/api/openapi.json](docs/api/openapi.json)) and [dependencies and vulnerability management](docs/dependencies.md).
- [Support](SUPPORT.md): which versions get fixes, and for how long.
- [Contributing](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Governance](GOVERNANCE.md) and
  [reporting a vulnerability](SECURITY.md).

## Getting started

AnsiDeck is a FastAPI backend, a React frontend and a PostgreSQL database, started with Docker Compose. You
need Docker with Compose.

1. Get the code and create your settings file:

   ```sh
   git clone https://github.com/HoneyBearTech/AnsiDeck.git
   cd AnsiDeck
   cp .env.example .env
   ```

2. Edit `.env`. For anything beyond a local try-out, set your own values for:
   - `AUTH_SECRET_KEY`: a long random string that signs session cookies.
   - `ADMIN_PASSWORD`: the first admin's password. It is only read on the very first start; change it later
     under **Account** (click your username in the header).
   - `CREDENTIAL_ENCRYPTION_KEY`: the key that encrypts stored SSH credentials. Generate one with
     `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
   - `POSTGRES_PASSWORD`: the database password. It is only read when the `postgres-data` volume is first
     created; changing it later also needs `ALTER USER` inside Postgres.
   - `WORKER_TOKEN`: a long random string (at least 32 characters) the workers use to reach the backend.

3. Start it: `docker compose up --build`.
4. Open <http://localhost:5173> and sign in as `ADMIN_USERNAME` (default `admin`) with `ADMIN_PASSWORD`.
   The backend's interactive API docs are at <http://localhost:8000/docs>.

The bundled `docker-compose.yml` is the development stack (hot reload). To run a release in production,
use the signed images and [`deploy/compose.yaml`](deploy/compose.yaml) as described in
[docs/installing.md](docs/installing.md). The database lives in the
`postgres-data` volume; playbook files, run logs and Galaxy content live in the `backend-data` volume, mounted
at `/data`. Playbooks run in the `worker` service, not in the backend: add workers with
`docker compose up --scale worker=3`, and set how many runs each executes at once with `WORKER_SLOTS`.

The `runtime` targets of `backend/Dockerfile` and `frontend/Dockerfile` build the production images: both run
as a non-root user, and the frontend serves the UI on port 8080 and proxies `/api` to a host named `backend`.
The backend image runs both halves of the backend:

- **API** (the default command): port 8000, needs `DATABASE_URL` pointing at a PostgreSQL 18 database and
  applies migrations itself at startup. Run exactly one API container. Workers talk to it on its internal
  port 8001; set `INTERNAL_API_HOST=0.0.0.0` and `WORKER_TOKEN`, and never publish or proxy port 8001.
- **Worker** (command `python -m app.worker`): needs only `ANSIDECK_API_URL` (for example
  `http://backend:8001`), the same `WORKER_TOKEN`, optionally `WORKER_SLOTS`, and the API's `/data/galaxy`
  mounted read-only at `GALAXY_DIR` (default `/data/galaxy`). Give it no database URL and no keys: it refuses
  to start if it sees `DATABASE_URL`, `CREDENTIAL_ENCRYPTION_KEY` or `AUTH_SECRET_KEY`. Put workers on a
  network that reaches the API but not the database, and run it as the container's PID 1 (no `--init` or
  wrapper: it reaps processes itself, and hides its environment from playbooks only when nothing else holds
  it). Run it the way `docker-compose.yml` does: as root with only the `SETUID`, `SETGID`, `CHOWN` and
  `KILL` capabilities, `no-new-privileges`, a read-only root filesystem and a tmpfs at `/tmp`. It then runs
  each slot's playbooks as a user of its own (`ansideck-run0` to `ansideck-run63`, uid 20000 and up), and
  with `ENVIRONMENT=production` it refuses to start without those settings. On `docker stop` a worker lets
  its runs finish for
  `WORKER_DRAIN_SECONDS` (30 by default; give the container a longer stop timeout), then stops them.

To upgrade: stop the old backend, start the new API (it migrates the database, and runs that were still
queued or running are marked failed with a reason), then start the workers.

### Upgrading from SQLite

Versions before the move to PostgreSQL kept everything in `/data/ansideck.db`. The backend will not start
while that file exists and the new database is empty; it tells you to import it, once:

```sh
docker compose up -d postgres
docker compose run --rm backend uv run python -m app.cli import-sqlite /data/ansideck.db --check
docker compose run --rm backend uv run python -m app.cli import-sqlite /data/ansideck.db
docker compose up -d
```

`--check` runs the whole import and then rolls it back, so you can see the row counts and any problems first.
The import is all-or-nothing, only goes into an empty database, and keeps every id, so the playbook files and
run logs in `/data` still match. The SQLite file is never changed; keep it as a backup until you are happy with
the result. (In the production image, which has no `uv`, run `python -m app.cli import-sqlite ...`.)

## Using AnsiDeck

Content is grouped into projects, and a `Default` project exists on first start. A typical run:

1. **Credentials**: add the SSH private key AnsiDeck should use to connect. It is stored encrypted.
2. **Inventories**: define hosts and groups. Host names are exactly what ansible connects to: no port
   (`db:5432`; set `ansible_port` instead) and no ranges (`web[1:3]`). Group names use letters, digits, `.`,
   `_` and `-`, and `all` and `ungrouped` are ansible's own.
3. **Playbooks**: paste a playbook or import a YAML file.
4. **Runs → New Run**: pick the playbook, inventory, target and credential. Optionally add a vault password, a
   host limit, check or diff mode, and extra variables as JSON. The output streams live, and finished runs stay
   in the run history.

A run sees the inventory's whole group tree, so a play with `hosts: web` runs on the `web` group whatever the
target. Picking a group as the target narrows the run to that group's hosts (like `--limit web`); every group
still exists, holding only those hosts. A run uses the inventory as it was when it was started: edits made while
it waits in the queue don't change what it runs.

Credentials are SSH keys, or **environment variables** (named values such as an API token, stored encrypted or
read from the secret store) for dynamic inventory sources. Only SSH keys can run playbooks.

Runs wait in a queue until a worker is free; a queued run's page says what it is waiting for (a free
worker, the run ahead of it on the same inventory, a Galaxy install, or no worker being online). Runs against
the same inventory go one at a time, in the order they were started. A run is stopped after 2 hours (the
**Timeout** field, or `timeout_seconds` through the API; up to 24 hours). Anyone who may start runs in a
project can **Cancel** a queued or running run there: a queued run never starts, a running one is stopped
within seconds (what it already changed on the hosts stays changed). If a worker disappears mid-run, its run
is marked failed ("worker lost") about a minute later. While a Galaxy install is waiting or running, no new
run starts.

Other pages: **Vault** encrypts and decrypts values with Ansible Vault, **Galaxy** installs roles and
collections, **Projects** separate content and access, and admins manage **Users** (roles: admin, operator,
viewer, assigned per project), read the **Audit** log, and see which **Workers** are online and how busy
they are.

## Running it securely

- Set `ENVIRONMENT=production`. The app then refuses to start while `AUTH_SECRET_KEY` or `ADMIN_PASSWORD` still
  hold their insecure defaults.
- Keep the API's secrets in files rather than environment variables: a file in `SECRETS_DIR` (default
  `/run/secrets`, where Docker secrets appear) named after a setting, such as `credential_encryption_key`,
  `auth_secret_key`, `admin_password` or `database_url`, provides its value when the environment doesn't.
  Workers take `WORKER_TOKEN` from their environment only. `deploy/compose.yaml` does this.
- Serve it over HTTPS through a reverse proxy, set `COOKIE_SECURE=true`, and make sure the proxy forwards
  WebSocket upgrades (live run output needs them). If the browser's origin differs from the `Host` the backend
  sees, add it to `CORS_ORIGINS`. The frontend container already sends a Content-Security-Policy and other
  browser hardening headers; set `Strict-Transport-Security` on the proxy, and don't strip those headers.
- AnsiDeck is not designed to be exposed directly to the public internet. See [docs/security.md](docs/security.md).
- Back up both the database (for example
  `docker compose exec -T postgres pg_dump -U ansideck -Fc ansideck > ansideck.dump`, restored with
  `pg_restore`) and the `/data` volume, and keep `CREDENTIAL_ENCRYPTION_KEY` backed up separately: losing it
  makes stored credentials and two-factor secrets unrecoverable, and leaking it exposes every stored key.
- With `ENVIRONMENT=production` the app also refuses the default database password. Keep Postgres off the
  network: the compose file only publishes it on `127.0.0.1` (for running the tests).
- Give people the least role they need. Anyone who can run a playbook can run commands on the targets.
  Runs execute in worker containers that have no database access and no keys, each slot as a Linux user of
  its own, so a run can't reach the worker's token or other runs' files and processes. Runs still share the
  worker's network and resources. Details, and what isn't isolated, are in [docs/security.md](docs/security.md).
- With `ENVIRONMENT=production` the backend and the workers refuse the default `WORKER_TOKEN`. Anyone holding
  it can claim runs and receive their secrets, so treat it like `CREDENTIAL_ENCRYPTION_KEY`.
- Global admins cannot use single sign-on unless you set `SSO_ALLOW_ADMIN=true`, so password login stays your
  break-glass.
- Turn on two-factor login under **Account** (authenticator-app codes for password sign-ins; SSO and GitHub
  sign-ins rely on your provider's MFA). Keep the recovery codes it shows. An admin can reset someone else's
  under **Users**; if no admin can sign in, reset it on the server with
  `docker compose exec backend uv run python -m app.cli reset-totp <username>` (in the production image,
  which has no `uv`: `python -m app.cli reset-totp <username>`).
- The audit log records sign-ins, run activity and permission denials, and is kept for
  `AUDIT_RETENTION_DAYS` (365 by default).
- With a secret store, give AnsiDeck a read-only policy on its prefix only, put its secret id or token in a file
  only the backend can read, and bind the AppRole to AnsiDeck's address.
- If you turn on metrics (`METRICS_TOKEN`), never publish or proxy port 8002; give Prometheus the token
  in a file. The token only reads metrics.
- Give Grafana its own database role with `analytics-grant` (never the app's database user), and check it
  with `analytics-check`.

## Secret store (optional): OpenBao or HashiCorp Vault

Credentials (SSH keys) and vault passwords are stored encrypted in AnsiDeck's database by default. With a secret
store configured, a project's admins can instead create them as **references** into a KV v2 secrets engine:
AnsiDeck reads the value when a run starts (and when a git source or the Vault page needs it) and never stores
it. Rotate a secret in the store and the next run uses the new version.

Every project reads only its own subtree, `<SECRETS_STORE_KV_MOUNT>/<SECRETS_STORE_PATH_PREFIX>/<project id>/`
(by default `secret/ansideck/<id>/`); a reference is a path below it (letters, digits, `.`, `_`, `-`; no `..`) and
a key in that secret (`private_key` or `password` by default). On the **Credentials** page (and for vault
passwords, the **Vault** page) choose **In OpenBao** (or your `SECRETS_STORE_LABEL`) instead of **Stored in
AnsiDeck**: AnsiDeck reads the reference once to check it, and the card's **Test** button checks it again
without showing the value. Configure the store in `.env` (see `.env.example`), then set it up, for example
with the `bao` (or `vault`) CLI:

```sh
bao policy write ansideck - <<'POLICY'
path "secret/data/ansideck/*" { capabilities = ["read"] }
POLICY
bao auth enable approle
bao write auth/approle/role/ansideck token_policies=ansideck token_ttl=20m token_max_ttl=1h \
    secret_id_bound_cidrs=<AnsiDeck's address>/32 token_bound_cidrs=<AnsiDeck's address>/32
bao read -field=role_id auth/approle/role/ansideck/role-id          # SECRETS_STORE_ROLE_ID
bao write -f -field=secret_id auth/approle/role/ansideck/secret-id  # into SECRETS_STORE_SECRET_ID_FILE
bao kv put secret/ansideck/1/web/ssh private_key=@id_ed25519        # project 1's key
```

AnsiDeck's identity can read every project's subtree, so AnsiDeck itself keeps them apart. To have the store
enforce it too, set `SECRETS_STORE_PROJECT_POLICY=ansideck-project-{project_id}`, create one policy per project
(`path "secret/data/ansideck/<id>/*" { capabilities = ["read"] }`), add them all to the role's
`token_policies`, and add `path "auth/token/create" { capabilities = ["update"] }` to its policy: each read then
uses a single-use child token that holds only that project's policy.

If the store can't be reached, is sealed, or refuses AnsiDeck's login, runs that need its secrets fail with that
reason, and a **Secret store unavailable** notification goes to global channels once (and again when it works).
The **Workers** page shows the store's status as AnsiDeck last checked it (every minute). Never give workers the
`SECRETS_STORE_*` settings: a worker refuses to start with them.

To try it locally, Docker Compose has an `openbao` profile: a throwaway OpenBao dev server (in memory, a fixed
root token, on loopback only; never for real secrets) on a network only the backend joins.

```sh
docker compose --profile openbao up -d
docker compose exec backend uv run python scripts/openbao_dev_setup.py   # prints the .env lines to add
docker compose up -d backend                                             # after adding them
docker compose exec -T openbao bao kv put -mount=secret ansideck/1/web/ssh private_key=- < ~/.ssh/id_ed25519
```

The script sets up the AppRole and policies above (one per existing project) and keeps the secret id on the
backend's data volume. Run it again after OpenBao restarts or after you add projects.

## Playbooks from git (optional)

A project's admins can sync its playbooks from a git repository (**Playbooks → Git sources**, or
`/api/projects/{id}/git-sources`). AnsiDeck fetches the source's branch (only its latest commit) every 5
minutes by default (per source; 0 = only on **Sync now**, which operators can press too). Every file matching
the source's patterns (by default `*.yml`, `*.yaml`, `playbooks/*.yml` and `playbooks/*.yaml`, optionally
inside a subdirectory) that is a playbook appears as a read-only playbook: change it in the repository. A
file that disappears upstream is marked "removed upstream" (it keeps its id for CI, can't run, and can then
be deleted); it comes back if the file does.

A run of a synced playbook executes inside the repository (or its subdirectory) at the commit that was
current when the run was triggered, so its roles, templates, files, `group_vars`, includes and `ansible.cfg`
work; later pushes don't change a queued run. The run's page shows the commit (linked to your forge when the
source has a web URL). Roles and collections are looked up in the repository's `roles/` and `collections/`
(and the paths its `ansible.cfg` names inside the repository) before the Galaxy ones. Vaulted values in the
repository's `group_vars`, `host_vars`, `vars` and role vars/defaults are scrubbed from the output like
vaulted playbook variables.

- **Remotes:** `https://` (public, or with a user name and token, stored encrypted and never shown again),
  or `ssh://` / `user@host:path` with an SSH key from the project's credentials as the deploy key. For an ssh
  source, **Test connection** shows the server's host key fingerprint: compare it with the one your forge
  publishes, then trust it (or paste a `known_hosts` line). Syncs refuse to run until a key is trusted and fail
  if it changes.
- **Servers on your network** (private addresses) need `GIT_ALLOWED_PRIVATE_HOSTS`; plain `http://` only works
  to those.
- **What is never done:** hooks, submodules (they arrive as empty directories), tags, Git LFS, installing a
  repository's `requirements.yml` (use the Galaxy page), or following symlinks out of the repository (such a
  commit is refused and the previous one stays current). A commit over `GIT_MAX_SNAPSHOT_MB` (50) or
  `GIT_MAX_FILES` (20000), or a repository over `GIT_MAX_REPO_MB` (500), is refused.

## Dynamic inventory sources (optional)

An inventory can also get hosts and groups from **sources**: inventory plugin configs (YAML with a `plugin:`
key, for example `netbox.netbox.nb_inventory`, or `ansible.builtin.constructed` to group hosts by their vars).
A refresh runs them with `ansible-inventory` in an isolated worker slot, together with the inventory's own
hosts (so `constructed` can group those too), and keeps the result as a **snapshot**. Runs use the snapshot that
is current when they are started; the inventory's own host vars win over a source's. A refresh happens when a
source changes, when the inventory's own hosts or groups change, on demand, and on a schedule (at most every 5
minutes). If a refresh fails, runs keep the last good snapshot and an **Inventory refresh failed** notification
goes out once (and again when it works).

A source that needs an API token gets it from an **environment-variables credential** (for example
`NETBOX_TOKEN`), referenced in the config as `"{{ lookup('env', 'NETBOX_TOKEN') }}"`; configs may not hold
secrets themselves, since anyone who can see the inventory can read them. Text that comes from a source (a
NetBox description, a cloud tag) is never treated as a template in a run.

On an inventory's page, **Dynamic sources** lists its sources (with examples for NetBox, constructed and
generator), the last refresh and its error, the groups the sources found and every host a run will see, marked
by where it came from. **New Run** offers the sources' groups as targets and says how old the snapshot is.
Project admins manage sources (through the API too: `POST /api/inventories/{id}/sources`,
`PATCH`/`DELETE …/sources/{source id}`, `PUT …/refresh-settings`); operators can refresh (`POST …/refresh`);
anyone who can see the inventory can read `…/sources`, `…/refreshes`, `…/snapshot`, `…/hosts` and `…/targets`.
The image includes what the NetBox plugin needs; plugins that need other Python packages (AWS needs boto3,
Proxmox needs requests) don't work yet.

## Notifications

The **Notifications** page sends events to Discord, Slack, Microsoft Teams (a Workflows
webhook), a generic webhook, email, Pushbullet or Pushover. Each channel picks its events:

- **Run failed**: a run failed, timed out, or lost its worker. The message names the failed
  tasks and their hosts.
- **Run recovered**: a playbook succeeded on an inventory after its previous run there failed.
- **Inventory refresh failed**: a dynamic inventory's refresh failed (once per failing streak),
  and again when it works.

Global channels can also take operations and security events:

- **Worker offline**: a worker sent no heartbeat for `NOTIFY_WORKER_OFFLINE_SECONDS` (120 by
  default), and again when it is back online.
- **Worker not isolated**: a worker runs playbooks without per-slot users (once per worker).
- **Queue stuck**: a run has waited `NOTIFY_QUEUE_STUCK_MINUTES` (10 by default) for a worker or
  a Galaxy install, and again when the queue moves. Waiting behind another run on the same
  inventory never counts.
- **Secret store unavailable**: AnsiDeck can't reach or read the secret store, and again when it
  is back.
- **Login attack**: failed sign-ins locked out an address or user, or something used a wrong
  `WORKER_TOKEN` (at most once per address and kind every 15 minutes).
- **Admin change**: a global admin was created or promoted, a user's two-factor login was reset
  or turned off, or a global admin signed in with SSO.

Project admins manage their project's channels. Global admins manage global channels, which
get run events from every project. Use **Send test** to check a channel, and its **History**
to see what was sent; failed deliveries are retried for up to about 1 h 45 min.

- Messages carry names, statuses and counts, never secrets or task output. Webhook URLs and
  push tokens are stored encrypted and never shown again after you save them.
- Webhooks can't point at private addresses (localhost, `10.x`, `192.168.x`, the compose
  network) unless you list the host or network in `NOTIFY_ALLOWED_PRIVATE_HOSTS`, for example
  a self-hosted service on your LAN. Requests don't use a proxy and don't follow redirects.
- Email uses one SMTP server set in `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`,
  `SMTP_PASSWORD`, `SMTP_FROM` and `SMTP_TLS` (see `.env.example`); email channels only hold
  the recipients.
- A generic webhook gets JSON (`event`, `title`, `summary`, `url`, `data`) and, with a
  signing secret, an `X-AnsiDeck-Signature: sha256=<HMAC of "<X-AnsiDeck-Timestamp>.<body>">`
  header.
- Links to runs need `PUBLIC_URL`.

## Monitoring with Prometheus and Grafana (optional)

Set `METRICS_TOKEN` and the backend serves Prometheus metrics at `/metrics` on a port of its own, 8002
(`METRICS_PORT`, listening on `METRICS_HOST`, which compose sets to `0.0.0.0`). Scrapers must send the token
as a bearer token; wrong tokens get 401, are throttled per address and recorded in the audit log. Without a
token nothing listens. The port is never served through the frontend or the API's port 8000; the dev compose
stack publishes it on `127.0.0.1` only. [grafana/prometheus/scrape.example.yml](grafana/prometheus/scrape.example.yml)
is a scrape job to start from.

What you get:

- **Runs:** runs queued and finished (by project and status), run duration and queue-wait histograms,
  runs queued or running now, the oldest queued run's age.
- **Workers:** workers online and offline, slots and busy slots per worker, whether each isolates its runs,
  when each last reported in.
- **Notifications and alerts:** send attempts by channel kind and outcome, the outbox backlog, ops alerts
  raised now (worker offline or not isolated, queue stuck).
- **API:** requests and latency by route template and status, for the public and the internal worker API;
  audit events by action and outcome, sign-in lockouts; the usual process metrics.

Labels never carry user names, playbook names, inventory host names, run ids, raw paths or anything from a run's output.
Projects are labelled by id; `ansideck_project_info` maps ids to names. Counters live in the API process and
restart from zero with it, which `rate()` and `increase()` handle, so run exactly one API process (no
`--workers`).

### History for Grafana: the read-only analytics views

For history (run trends, durations, failures, sign-ins, audit events) Grafana reads the database through its
PostgreSQL data source, but only the views in the `analytics` schema: `runs`, `projects`, `workers`,
`galaxy_installs`, `audit_events`, `notification_deliveries`, `ops_alerts`, `api_keys` and `user_summary`
(user counts by role, nothing per user). The views leave out everything secret or sensitive: extra variables,
host limits, playbook contents, credential and vault password names, hashes, encrypted values, run output,
notification payloads and errors, and audit details beyond a few fixed fields. Client addresses appear only
as their network (`/24` for IPv4, `/48` for IPv6). User names are included: the audit trail is about who did
what.

Give Grafana a database role of its own. AnsiDeck never creates roles; create one as a database superuser,
for example with `docker compose exec postgres psql -U ansideck ansideck`:

```sql
CREATE ROLE grafana_ro LOGIN PASSWORD '<a long random password>' NOINHERIT CONNECTION LIMIT 10;
ALTER ROLE grafana_ro SET default_transaction_read_only = on;
ALTER ROLE grafana_ro SET statement_timeout = '30s';
ALTER ROLE grafana_ro SET search_path = analytics;
GRANT CONNECT ON DATABASE ansideck TO grafana_ro;
-- Recommended unless something else using this database needs temporary tables (AnsiDeck doesn't):
REVOKE TEMPORARY ON DATABASE ansideck FROM PUBLIC;
```

Then let it read the views (in the production image: `python -m app.cli analytics-grant grafana_ro`):

```sh
docker compose exec backend uv run python -m app.cli analytics-grant grafana_ro
```

`analytics-grant` refuses superusers and roles that belong to the app's own database user, grants `SELECT` on
the views (including views later upgrades add), and then runs `analytics-check`. The check fails if the role
can read or change anything outside the views, or can't read one of them, and warns about missing hardening
from the SQL above. Run `analytics-check grafana_ro` again after upgrades or role changes;
`analytics-revoke grafana_ro` takes the access away. Keep the database off the network: Grafana should reach it
over a private network (the dev compose stack publishes Postgres on `127.0.0.1:5433` only, which a Grafana
container on the same machine reaches as `host.docker.internal:5433`). Anyone who can edit dashboards or use
Explore in Grafana can read everything in these views, so give that access only to people you would let read
the audit log. In Grafana, set the data source's **Max open connections** below the role's `CONNECTION LIMIT`
(Grafana's default allows 100).

### Dashboards

[grafana/](grafana/README.md) has three importable dashboards (overview & runs; execution, queue & workers;
security & access) that use both data sources, provisioning examples for the data sources and dashboards, and
optional Grafana alert rules for trends that AnsiDeck's own notifications don't cover.

## Triggering runs from CI

A project admin can create an API key under **Projects → API keys**. Keys belong to one project, are shown
once, and expire (30 days, 90 days or 1 year) or can be revoked at any time. There are two kinds:

- `trigger` — start runs and read run status and output in that project. Never runs as root, never edits
  anything.
- `read-only` — read run status and output only.

Send the key as a bearer token, over HTTPS only:

```sh
KEY=ansd_...   # keep it in your CI secret store
BASE=https://ansideck.example.com

# start a run (ids come from the UI)
RUN=$(curl -sf -X POST "$BASE/api/runs" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"playbook_id": 1, "inventory_id": 1, "credential_id": 1, "extra_vars": {"version": "1.4.2"}}' \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])')

# poll until it finishes: status goes queued -> running -> success, failed, cancelled or timed_out
# (status_reason says why when it wasn't ansible's own result); return_code is the ansible exit code
curl -sf "$BASE/api/runs/$RUN" -H "Authorization: Bearer $KEY"

# cancel it (a trigger key may cancel only the runs it started itself)
curl -sf -X POST "$BASE/api/runs/$RUN/cancel" -H "Authorization: Bearer $KEY"
```

A key can only use the run endpoints (`GET/POST /api/runs`, `GET /api/runs/{id}`,
`POST /api/runs/{id}/cancel`, and the run log WebSocket
`/api/runs/{id}/ws` with the same header); everything else answers `403`. Extra vars you send are not
readable back through a key. Keys are access control, not isolation: a `trigger` key can run any playbook in
its project, so scope keys per project and rotate them.

## Single sign-on (optional)

AnsiDeck can sign people in with any OpenID Connect provider (Google, Microsoft Entra, Keycloak,
Authentik, Dex, ...) and, separately, with GitHub. Password login stays available, and it is your
break-glass. Both can be enabled at once.

**OpenID Connect**

1. Register `<PUBLIC_URL>/api/auth/oidc/callback` as a redirect URI at the provider and create a client.
2. Set `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` (see `.env.example`) and restart.
   The issuer must match the provider's `issuer` exactly. In production both URLs must be `https`.
3. In **Users**, create each person (or open an existing one) and set their **email**.

**GitHub**

1. Create an OAuth App (GitHub → Settings → Developer settings → OAuth Apps) whose callback URL is
   `<PUBLIC_URL>/api/auth/github/callback`.
2. Set `PUBLIC_URL`, `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` and restart. (GitHub Enterprise Server:
   also set `GITHUB_URL` and `GITHUB_API_URL`.)
3. In **Users**, set each person's **email** to a *verified* email on their GitHub account.

The first time someone signs in with SSO, they are linked to the user whose email matches an address the
provider has *verified* (for GitHub, any verified email on the account; a sign-in that would match two
different users is refused). From then on they are matched by the provider's stable subject id (GitHub's
numeric user id, not the renamable username), so a changed email or username can't hijack the account.
Nothing is ever created automatically: an identity with no matching user is refused. **Global admins cannot
sign in with SSO** unless you set `SSO_ALLOW_ADMIN=true`, and `SSO_ALLOWED_EMAIL_DOMAINS` can restrict which
email domains may sign in. Roles and project membership stay managed inside AnsiDeck (no group or
organisation mapping), and signing out ends only the AnsiDeck session.

Each user has one bound identity. Use **Unlink SSO** on a user if they move to a different account at the
provider, or to switch them from one provider to another.

GitHub specifics: AnsiDeck asks for the `read:user` and `user:email` scopes, uses the access token for two
reads and revokes it straight away (it is never stored; if the revoke call fails the token stays valid at
GitHub until the user revokes the app there). Trust in GitHub's email verification is the boundary for
first-time linking.

