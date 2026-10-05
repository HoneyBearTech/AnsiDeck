# Changelog

All notable changes to AnsiDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version may include changes that need
steps when upgrading; those are listed under "Upgrading" and in [docs/upgrading.md](docs/upgrading.md).

## [Unreleased]

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
