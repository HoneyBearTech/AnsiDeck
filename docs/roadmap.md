# Roadmap

This is where AnsiDeck intends to go over roughly the next year (from October 2026), and what it
deliberately won't do. It is a statement of intent, not a promise: plans change as the project learns, and
this page is updated when they do. Decisions about scope are made as described in
[GOVERNANCE.md](../GOVERNANCE.md); ideas and requests are welcome in
[GitHub Issues](https://github.com/HoneyBearTech/AnsiDeck/issues).

## Where it stands

The core is complete: projects with per-project roles, encrypted credentials or an external secret store
(OpenBao / HashiCorp Vault), static and dynamic inventories, playbooks pasted or synced from git, a
Postgres-backed queue with isolated workers, live output, cancel and timeouts, Ansible Vault and Galaxy
tools, notifications, an audit log, two-factor and single sign-on, API keys for CI, and Prometheus metrics
with Grafana dashboards.

**v0.1.0** (October 2026) was the first release: signed container images and release checksums, user
guides for every feature, upgrade and backup/restore guides, and a changelog, together with frontend tests
behind a coverage floor, stricter compiler and lint settings, and an accessibility pass on every page. The
most recent release is the supported version. Since then, on `main`: saved run templates (also for CI
keys), running a run again, and downloading run output.

## Over the following year

**Running playbooks**
- Showing which inventory snapshot a run used; refreshing dynamic inventory before a run when asked.
- Managed SSH `known_hosts` per inventory, so host keys are checked without custom arguments.

**Authoring**
- A playbook editor with syntax highlighting and inline `ansible-lint` (run in a worker).

**Layout and visualisation**
- A layout that works on phones and tablets, and a visual graph of inventory groups and hosts.

**Security and operations**
- Limiting what runs can reach on the network (for example cloud metadata and the API's own ports).
- Short-lived SSH certificates from the secret store, and more of the secret store's features.
- API key hardening: per-key playbook and inventory allowlists, address allowlists, and rotation.
- Single sign-on checked against more real providers, group-to-role mapping, and passkeys (WebAuthn) as a
  second factor.

**Integrations**
- More dynamic-inventory plugins out of the box, inventory files from git, and more notification services
  where people ask for them.

## What AnsiDeck will not do

- **Be exposed directly to the internet.** AnsiDeck is built for a trusted network behind your own
  TLS-terminating reverse proxy. It will not grow its own TLS termination or public-facing hardening
  such as bot protection.
- **Be a hosted, multi-tenant service.** Projects separate content and access for one team or
  organisation; they are not a boundary between mutually hostile customers.
- **Sandbox hostile playbooks.** Running a playbook is code execution on the targets. Isolation protects
  runs from each other and protects the worker; it doesn't make it safe to let untrusted people run
  playbooks.
- **Show stored secrets.** Credentials, vault passwords and tokens stay write-only; there will be no
  "reveal" button.
- **Replace Ansible or its ecosystem.** AnsiDeck runs `ansible-playbook` and `ansible-inventory` as they
  are. It won't fork Ansible, add a playbook language of its own, or install agents on managed hosts.
- **Become a general CI/CD system.** Pipelines, builds and approval workflows belong in your CI; AnsiDeck
  gives CI an API to start and watch runs.
