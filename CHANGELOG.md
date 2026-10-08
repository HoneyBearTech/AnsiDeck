# Changelog

All notable changes to AnsiDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version may include changes that need
steps when upgrading; those are listed under "Upgrading" and in [docs/upgrading.md](docs/upgrading.md).

## [Unreleased]

### Security

- Inventory sources, environment-variable credentials and outgoing destinations are checked more tightly:
  refresh output whose host or group lists hold anything but names is refused (it caused an error and a
  refresh that hung until its lease ran out); the plugins that can't be sources are refused under their
  `ansible.legacy.` names too; IPv6 addresses that carry an IPv4 address (`::/96`, NAT64's
  `64:ff9b::/96`) are judged by that address, so they can't reach private or metadata addresses through a
  NAT64 gateway; and credentials can no longer set `AWS_CONTAINER_*` (a refresh would have used an ECS
  task's own role), AWS credential file paths or CA bundle, `GIT_*`, `KRB5*`, `OPENSSL_MODULES`,
  `SSH_AUTH_SOCK`, `HOSTALIASES` or `NETRC`. Upgrading: names are now also checked for every refresh, so
  a refresh that uses a credential holding one of these names fails, naming it, until the variable is
  removed from the credential.
- Galaxy installs no longer install dependencies: ansible-galaxy fetched a collection's or role's
  dependencies from wherever their metadata pointed (plain `http://`, local paths), past the rules for
  `requirements.yml`, into the content every run loads. List every collection and role you need in
  `requirements.yml`; an install's output now ends with any dependency that installed content declares but
  that isn't installed. Upgrading: content that relied on automatic dependencies needs them listed.
- System V shared memory, message queues and semaphores, and POSIX message queues, that a run created
  outlived it: the cleanup after each run only ended processes and deleted files. A run could leave data
  (readable by anyone, if it chose so) for the slot's later runs, including other projects'. The cleanup
  now removes them, and a slot is not used again while any are left. The worker also no longer collects
  the exit status of its own cleanup process by mistake (it collects orphaned processes as PID 1), which
  could make it miss that another slot had planted files in a run user's home.
- The two-factor setup's QR code shows again in production: the frontend's Content-Security-Policy blocked
  it (it is a `data:` image). After an upgrade, browsers no longer keep the previous release's page (app
  pages are now revalidated, while the hashed assets are cached for good), and a missing asset is a 404
  rather than a blank page. A refused request (422) no longer repeats what was sent, so a private key or
  vault password in it can't land in proxy or client logs. The API answers only to `ALLOWED_HOSTS`
  (by default localhost, 127.0.0.1 and the compose service name in development, any host in production
  behind your reverse proxy), so a DNS-rebinding page can't drive a development backend on localhost.
  The build pins uv by version and digest.
- A playbook could reach the process that runs it, which runs as the same user: reopen its message pipe
  through `/proc` to add forged output to the run's log or report a result of its choosing, and read the
  run's job (its SSH key and vault password) from that process's memory. The run process is now
  non-dumpable, like the API and the worker. The worker also stops a run process that sends a message
  line over 32 MiB instead of reading it whole: a task printing tens of megabytes at once could exhaust
  the worker's memory and end every run on it. Such an event is now kept without its output.
- A notification whose subject held a Unicode line break (one in an inventory name, say) was retried every
  minute for ever and never sent: email refuses such subjects, and the error left the delivery stuck. All
  line breaks are now turned into spaces in subjects, an unexpected error while sending fails the delivery
  instead of retrying it, and a delivery whose last attempt never finished is given up.
- Microsoft Teams cards no longer turn `[text](url)` in untrusted text (a host's error message, a playbook
  name) into a link: Teams renders Markdown in card text, unlike the other channels, which already escaped
  it.
- The run output viewer shows terminal hyperlinks (OSC 8) as plain text: output from a playbook, a
  repository or a managed host could make any text a clickable link to anywhere. Colours no longer carry
  from one line into the next, so a colour left switched on (black on black, say) can't hide later
  output, such as a failed task.
- Requests for something in a project you aren't a member of are now in the audit log
  (`permission.denied`, reason `not_member`), as the security documentation said; they are still answered
  like a missing id. A project admin can no longer add someone to their project by user id (which told
  them who exists and their username): they add people by username, and changing a member's role by id
  works for existing members only. Single sign-on no longer links an account through a look-alike address
  (one with a character such as the Kelvin sign, which lower-cases to a plain `k`).
- Edits to playbooks, inventories, groups and hosts, and requests to sync a git source, are now in the
  audit log (`playbook.*`, `inventory.*`, `git_source.sync_requested`), as the security documentation
  already said. Before, someone who can edit content could change a playbook or point a host somewhere
  else and change it back without a trace. Entries record a playbook's size and SHA-256 before and after,
  and the names, never the values, of host variables that changed.

- An API key now stops working while the person who created it is deactivated, no longer an admin of the
  key's project, or removed from it (it works again if that changes), and for good once they are deleted.
  Before, keys kept starting runs after their creator was offboarded. The key list shows such keys as
  suspended, with the reason, and refused requests are audited. Creating a key now needs your current
  password, or a single sign-on sign-in within the last 15 minutes, so a stolen session alone can't mint
  one. Upgrading: keys whose creator is already gone or deactivated stop working; create new ones. The API
  applies database migration 0016 when it starts.

## [0.4.0] - 2026-10-07

Security fixes from a full review: secrets in run output, become for operators, credentials in inventory
refreshes, insecure production settings, client addresses behind a proxy, and two ways to stall the API.
Also: changing the credential encryption key.

### Upgrading

- Follow [docs/upgrading.md](docs/upgrading.md) (back up, set `ANSIDECK_VERSION=0.4.0`, pull, restart).
  The API applies database migration 0015 when it starts.
- **Operators' runs no longer get become from the playbook or inventory.** Runs started by someone
  without `runs:become` (operators, trigger API keys) execute with `ansible_become: false`, and their
  `ansible_become*` extra vars are refused. If such a run relies on the playbook's own `become: true`,
  have an admin run it or give the operator the admin role.
- **Production refuses insecure settings.** With `ENVIRONMENT=production` the API no longer starts on the
  `change-me...` placeholders from `.env.example`, an `AUTH_SECRET_KEY` under 32 characters or equal to
  `WORKER_TOKEN`, or the example `CREDENTIAL_ENCRYPTION_KEY`. Installations that followed
  [docs/installing.md](docs/installing.md) generated their own and are not affected. If yours uses the
  example key, the error explains how to move to a new one
  ([docs/upgrading.md](docs/upgrading.md#changing-the-encryption-key)).
- **Reverse proxies:** a proxy on the same host as the documented `deploy/compose.yaml` needs nothing.
  A proxy in another container or on another machine needs its address or network in `TRUSTED_PROXIES`
  (`.env`), or sign-ins are throttled and audited under the proxy's address. Pass the client in
  `X-Forwarded-For` (the nginx example in docs/installing.md now does).
- **Development setup:** `docker-compose.yml` publishes ports on 127.0.0.1 only; set
  `DEV_BIND_ADDRESS=0.0.0.0` to reach it from other machines.
- Templates in the inventory's own host vars are no longer evaluated by `constructed` sources during a
  refresh (runs still evaluate them).

### Added

- Changing `CREDENTIAL_ENCRYPTION_KEY`: it can list several keys (the first encrypts, all decrypt), and
  `python -m app.cli reencrypt-secrets` rewrites every stored secret under the first one. See
  [docs/upgrading.md](docs/upgrading.md#changing-the-encryption-key).

### Security

- A refresh's output can no longer freeze the API. The check that refuses deeply nested JSON before
  parsing it took quadratic time on a string that never closes (80 KB of escaped quotes: 10 s, with the
  whole API stalled), which a plugin in the refresh slot or a stolen worker token could send. It is
  linear now.
- A git source can no longer exhaust the API's memory with a "tree bomb": a few tree objects that each list
  the one below many times describe millions of files in a repository of a few kilobytes, and their file
  list was read whole before `GIT_MAX_FILES` was checked (a million files: 15 s and 650 MB). The listing
  is now read as it comes and git is stopped at the file limit, or once the list passes 4 KiB per allowed
  file. A connection test also stops reading a server's answer at its limit instead of after it.
- With `ENVIRONMENT=production`, the API refuses to start on the placeholders from `.env.example`
  (`change-me...` values for `AUTH_SECRET_KEY`, `ADMIN_PASSWORD`, the database password, `WORKER_TOKEN`,
  `METRICS_TOKEN`), on an `AUTH_SECRET_KEY` shorter than 32 characters or equal to `WORKER_TOKEN`, and
  on the example `CREDENTIAL_ENCRYPTION_KEY` as its current key. Settings errors no longer print the
  rejected value. The installation guide's generated secrets are not affected.
- The development `docker-compose.yml` publishes the backend and frontend on 127.0.0.1 only (it has a
  well-known admin password); set `DEV_BIND_ADDRESS=0.0.0.0` in `.env` to open them to your network.
- Sign-in throttling and the audit log see each client's own address. Behind the documented reverse
  proxy, every client looked like the Docker gateway, so anyone could lock everybody (the break-glass
  admin included) out of password sign-in for five minutes at a time. The frontend now takes the client
  from `X-Forwarded-For` when the request comes from a trusted proxy (`TRUSTED_PROXIES`, default
  `gateway`: a proxy on the same host). The API trusted `X-Real-IP` from any private address, so a
  playbook in a worker could name a new address per request and guess passwords without being
  throttled; it now trusts it only from the frontend container (`TRUSTED_PROXY_HOSTS`, default
  `frontend`). An API behind a proxy of your own (not the frontend container) needs
  `TRUSTED_PROXY_HOSTS`.
- An inventory refresh no longer evaluates templates in the inventory's own host vars. A `constructed`
  source that read such a var (in `compose`, `keyed_groups` or `groups`) ran `{{ ... }}` in it, lookups
  included, during the refresh, which holds the sources' environment-variable credentials: anyone who
  can edit hosts (operators) could copy a source's token into a stored host var or group name, or run
  commands there. Sources now see those vars as plain text. Runs still evaluate them as before.
- Run output scrubbing catches more forms of a known secret. Runs now always print task results as JSON,
  even when a repository's `ansible.cfg` asks for YAML, which could fold a long secret across lines past
  the scrubber. Secrets are also redacted as Ansible prints non-ASCII text in JSON and as YAML quotes
  them, and a secret that is a number is replaced in structured task results.
- Unknown secrets in `name=value` and `name: value` text are caught under prefixed and suffixed names too
  (`DB_PASSWORD=`, `PGPASSWORD=`, `mysql_root_password:`, `client_secret:`), but not names of where a
  secret lives (`vault_password_file=`). Variables named `pwd`, `apikey`, `authtoken`, `passcode`,
  `community` and similar one-word names now count as secret.
- `runs:become` now holds beyond the run's checkbox. Runs started by someone without it (operators,
  trigger API keys) get `ansible_become: false` when they execute, so `become: true` in a playbook, an
  inventory or a source no longer escalates them, and `ansible_become*` extra vars are refused, in runs
  and in saved templates. The run's extra vars stay as typed, and **Run again** follows the permissions
  of whoever runs it again.

## [0.3.0] - 2026-10-06

A security fix for dynamic inventory sources, host vars masked for viewers, a group graph for inventories,
and a layout that works on phones, checked in a real browser on every pull request.

### Upgrading

- Follow [docs/upgrading.md](docs/upgrading.md) (back up, set `ANSIDECK_VERSION=0.3.0`, pull, restart).
  This release has no database migrations.
- **Dynamic inventory sources** may now only set `ansible_host`, `ansible_port`, `ansible_user`,
  `ansible_network_os` and a remote `ansible_connection`. Any other `ansible_*` variable a source returns
  is dropped, and the next refresh lists it in its warnings: set those on the inventory's own hosts or in
  the playbook instead.
- Viewers now see secret-looking host vars masked; operators and admins see them as stored.
- The full navigation bar shows from 1280 px wide; below that, use the menu button.

### Security

- Dynamic inventory sources can no longer set Ansible connection settings beyond where and as whom to
  connect (`ansible_host`, `ansible_port`, `ansible_user`, `ansible_network_os`, and `ansible_connection`
  limited to remote connection types). Other `ansible_*` variables from a source are dropped with a
  refresh warning, also in snapshots stored before upgrading. See the security advisory
  [GHSA-7xj5-pxgx-h5w4](https://github.com/HoneyBearTech/AnsiDeck/security/advisories/GHSA-7xj5-pxgx-h5w4).
- Viewers (anyone who can see an inventory but not edit it) no longer receive the inventory's host vars in
  full: secret-looking keys (passwords, tokens, keys) and vault-encrypted values are masked in
  `GET /api/inventories/{id}`. Operators and admins still get the real values, which the Edit host
  dialog needs.

### Added

- **Group graph** for inventories (`/inventories/{id}/graph`, linked from the inventory page): an
  accessible tree of how the groups nest, including groups from dynamic sources and groups with several
  parents, with each group's parents and children and the hosts in it and below it. API:
  `GET /api/inventories/{id}/graph` (names, edges and counts only, no vars) and a `group` filter on
  `GET /api/inventories/{id}/hosts`.
- The host list ("Hosts a run sees") pages through more than 100 hosts.
- A browser layout check on every pull request (`npm run test:layout`, Playwright in Google Chrome):
  every page at 375, 768, 1024 and 1280 px with long names must not scroll sideways, must pass axe's
  colour-contrast rule, and its "New/Add" dialogs must fit a phone. Not a required check yet.

### Changed

- The full navigation bar now shows from 1280 px wide (below that, the menu button), and pages use a
  slightly wider column. At 1024 px the header no longer overflows.
- On touch screens, small buttons, selects and the menu's links grow to about 40 px; checkboxes have a
  26 px hit area everywhere.
- The code editor wraps long lines instead of scrolling sideways.

### Fixed

- Long playbook, inventory, group, host and credential names no longer push run rows, the run page,
  the inventory page or the credentials list off a phone screen (the run page overflowed even at 1280 px).
- A long webhook URL pushed the notifications page off a phone screen, and the code editor's placeholder
  text was just under AA contrast (4.49:1); both found by the new layout check.
- Dialogs fit small screens: they keep a margin, scroll inside when taller than the screen, and their
  buttons wrap.
- [docs/verifying-releases.md](docs/verifying-releases.md) asked for cosign 2.0 or later, but the image
  signatures (since v0.1.0) are in Sigstore's bundle format, which needs cosign 3.0, or cosign 2.6 with
  `--new-bundle-format`.

## [0.2.0] - 2026-10-05

Run templates and re-runs, a code editor with ansible-lint checks, a reworked dashboard and a cleaner,
phone-friendly UI. Release files now carry SLSA build provenance.

### Added

- **A code editor** for playbooks, inventory source configs and Galaxy requirements: YAML highlighting,
  line numbers, undo, and markers for check findings. **Check** on a playbook runs ansible-lint on the
  editor's text (saved or not; a synced playbook in its repository) and lists the findings with links to
  each rule. The file upload controls now look like buttons.
- **Playbook checks** API (behind the Check button): `POST /api/playbooks/lint`
  checks text (unsaved, even invalid YAML) and `POST /api/playbooks/{id}/lint` a saved playbook; one
  synced from git is checked inside its repository at the current commit with the repository's own
  `.ansible-lint`. ansible-lint runs offline in an isolated worker; findings (rule, level, line, message,
  docs link) are polled from `GET /api/lint-jobs/{id}`, private to whoever asked, kept for an hour.
  Operators and admins can check; `LINT_TIMEOUT_SECONDS` and `LINT_MAX_RUNNING` set the limits.
- The backend image now includes `ansible-lint` and `yamllint` (Ansible-project tools, GPL-3.0, allowed
  by the dependency policy alongside Ansible), the groundwork for checking playbooks in the editor.
- **Run templates**: save a run's playbook, inventory and target, credential, vault password, options and
  extra vars under a name, and start it again in one step from the new Templates page, with the limit and
  check mode changeable per run. Operators and admins manage them (saving one that runs as root needs that
  permission); a template whose items were deleted says so and won't run until edited. `trigger` API keys
  can launch a project's templates (`POST /api/run-templates/{id}/launch`).
- **Run again** and **Edit and run** on a run's page: start the same run at once (after a confirmation), or
  open New Run with its settings filled in.
- **Download a run's output** as plain text or JSON lines, from the run's page or
  `GET /api/runs/{id}/log` (also with API keys).
- The run API now returns the ids of the playbook, inventory, credential and vault password a run used
  (null once deleted).
- Releases carry SLSA build provenance for their files: a signed attestation stored by GitHub
  (`gh attestation verify`) and attached as `ansideck-<version>.intoto.jsonl`
  ([docs/verifying-releases.md](docs/verifying-releases.md#build-provenance-from-v020)).

### Changed

- **A cleaner, phone-friendly UI**: a compact header with an Admin menu and a user menu (Account, Log out),
  and a menu button on tablets and phones; every page has the same header, with back links on detail
  pages; nothing scrolls sideways on a phone any more.
- **The dashboard** shows what is running now, recent failures and the latest runs, with shortcuts to New
  run and Templates (it showed placeholder cards before).
- **Run output** is coloured like Ansible's command line, keeps the play recap's line breaks, and no longer
  starts with ansible-runner's internal "Identity added" line; the runs list shows each run's number,
  duration and host outcome. `GET /api/runs` takes `status` (repeatable) and `limit`.
- Consistent sentence-case labels ("New run", "Start run"), Delete and Revoke buttons in red, real
  checkboxes, disabled buttons that say what's missing, a single choice preselected, project names on
  rows in "All projects", the audit log's details as readable fields, and a code editor for extra vars.

### Upgrading

- Follow [docs/upgrading.md](docs/upgrading.md) (back up, set `ANSIDECK_VERSION=0.2.0`, pull, restart).
  The API applies the new database migrations (0013 run templates, 0014 playbook checks) when it starts.
- Upgrade the workers together with the API (the compose files do): a worker from 0.1.x doesn't take
  playbook checks, and a check no worker takes fails after two minutes with the reason.
- Labels changed to sentence case (for example **New run**, and **Start run** instead of Trigger Run);
  the admin pages moved under the header's **Admin** menu, and Account and Log out under your user name.

## [0.1.0] - 2026-10-05

The first release. Container images are published to GitHub Container Registry, signed with cosign, and
come with SBOM and provenance attestations; see [docs/verifying-releases.md](docs/verifying-releases.md).

### Added

- **Running playbooks**: a Postgres-backed queue with any number of workers; each worker slot runs
  playbooks as a Linux user of its own, isolated from the worker and from other runs. Live output over
  WebSocket, run history, check and diff mode, host limits, extra variables, become (with a separate
  permission and an explicit confirmation), timeouts, cancel, and recovery from lost workers.
- **Content**: playbooks pasted, imported or synced read-only from git repositories (HTTPS tokens or SSH
  deploy keys with host-key trust, polling or "Sync now"), runs pinned to a commit; static inventories with
  groups and host vars; dynamic inventory sources (any allowed inventory plugin, e.g. NetBox or a cloud,
  plus `constructed`) refreshed in isolated workers and pinned per run.
- **Secrets**: SSH keys, environment-variable credentials and vault passwords encrypted at rest, or kept
  in OpenBao / HashiCorp Vault and read only when a run starts; Ansible Vault encrypt and decrypt tools;
  the API's own secrets can come from files (Docker secrets).
- **Galaxy**: install roles and collections from a requirements file, with runs held back meanwhile.
- **Access control**: projects with per-project admin, operator and viewer roles, global admins, API keys
  for CI with fixed presets, password sign-in with optional TOTP two-factor login, OpenID Connect and
  GitHub single sign-on, sign-in throttling and lockout alerts, and an audit log.
- **Notifications**: Discord, Slack, Microsoft Teams, webhooks (optionally signed), email, Pushbullet and
  Pushover, for run, operations and security events, with retries and delivery history.
- **Observability**: Prometheus metrics on their own port, read-only analytics views for Grafana, and
  provisioned dashboards.
- **Hardening**: production mode refuses insecure defaults, a strict Content-Security-Policy and other
  browser hardening headers, SSRF-guarded outgoing connections, and fail-closed handling of inventory
  sources and the secret store.
- **Documentation**: user guides, installation, upgrade and backup guides, security requirements, an
  assurance case, architecture, roadmap, accessibility notes, governance and a code of conduct.

### Upgrading

- New installation: nothing to do. Installations that ran AnsiDeck from `main` before this release only
  need the usual pull-and-restart: database migrations run on start-up. An installation still on the
  old SQLite database must run the one-time import first (see [docs/upgrading.md](docs/upgrading.md)).

[Unreleased]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HoneyBearTech/AnsiDeck/releases/tag/v0.1.0
