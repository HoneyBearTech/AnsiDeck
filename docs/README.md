# AnsiDeck documentation

> [!WARNING]
> **Runs change real systems.** Every run executes `ansible-playbook` against the hosts in its inventory,
> with the credential you pick, and what it changes stays changed, even if you cancel it part-way.
> Start with **check mode** (a dry run that reports what would change) and a narrow **limit**, and only
> give the operator role to people you would trust with the hosts themselves.
>
> **Deletes are permanent.** AnsiDeck asks before every delete, but there is no undo or trash: a deleted
> credential's key or vault password is gone from AnsiDeck for good. Run history stays when you delete the
> playbook, inventory or credential it used. Keep backups ([upgrading.md](upgrading.md#back-up)).

## Getting started

- [Quick start](quick-start.md): try AnsiDeck on your machine and run a first playbook in a few minutes.
- [Installing](installing.md): run a release in production from the signed images, behind HTTPS.
- [Upgrading, backups and restores](upgrading.md).
- [Verifying releases](verifying-releases.md): check the signatures on images, checksums and tags.

## Using AnsiDeck

The [user guide](user-guide/README.md) covers every part of the UI:

- [Projects, users and sign-in](user-guide/projects-and-users.md): projects and roles, members, users,
  two-factor login, single sign-on and API keys for CI.
- [Credentials and secrets](user-guide/credentials-and-secrets.md): SSH keys, environment variables,
  vault passwords, the Vault tool, and keeping secrets in OpenBao or HashiCorp Vault.
- [Inventories](user-guide/inventories.md): hosts and groups, and dynamic sources such as NetBox or a
  cloud.
- [Playbooks and Galaxy](user-guide/playbooks.md): writing or importing playbooks, syncing them from git,
  and installing roles and collections.
- [Runs](user-guide/runs.md): starting a run and its options, live output, the queue, cancelling and
  history.
- [Notifications](user-guide/notifications.md): Discord, Slack, Teams, webhooks, email and push.
- [Administration](user-guide/administration.md): workers, the audit log, metrics and Grafana.

The main [README](../README.md) lists every setting (environment variable) for deployment, and the
[API docs](http://localhost:8000/docs) of a running backend describe the HTTP API.

## About the project

- [Architecture](architecture.md), [security requirements](security.md), the
  [assurance case](assurance-case.md) and [accessibility](accessibility.md).
- [Roadmap](roadmap.md), [changelog](../CHANGELOG.md), [governance](../GOVERNANCE.md),
  [contributing](../CONTRIBUTING.md) and [reporting a vulnerability](../SECURITY.md).
