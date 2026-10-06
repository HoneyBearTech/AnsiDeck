# Changelog

All notable changes to AnsiDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version may include changes that need
steps when upgrading; those are listed under "Upgrading" and in [docs/upgrading.md](docs/upgrading.md).

## [Unreleased]

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
  refresh warning, also in snapshots stored before upgrading. See the security advisory for details.
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

[Unreleased]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HoneyBearTech/AnsiDeck/releases/tag/v0.1.0
