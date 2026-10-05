# Changelog

All notable changes to AnsiDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version may include changes that need
steps when upgrading; those are listed under "Upgrading" and in [docs/upgrading.md](docs/upgrading.md).

## [Unreleased]

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
  ([docs/verifying-releases.md](docs/verifying-releases.md#build-provenance-from-v011)).

### Upgrading

- Upgrade the workers together with the API (the compose files do): a worker from 0.1.x doesn't take
  playbook checks, and a check no worker takes fails after two minutes with the reason.

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

[Unreleased]: https://github.com/HoneyBearTech/AnsiDeck/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HoneyBearTech/AnsiDeck/releases/tag/v0.1.0
