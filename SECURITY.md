# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability reporting](https://github.com/HoneyBearTech/AnsiDeck/security/advisories/new) rather than a public issue.

This is a personal project maintained by one person, so there is no formal SLA, but reports will be acknowledged as soon as reasonably possible.

## Supported Versions

There are no tagged releases yet. Until there are, only the current `main` branch is supported. Once releases exist, only the most recent tagged release (and its Docker image) will receive security fixes.

## Scope

AnsiDeck holds SSH keys and vault passwords and runs Ansible against real infrastructure, so treat a deployment as a sensitive system. It is designed to run on a trusted network behind a reverse proxy that terminates TLS, and it is **not** designed or tested to be exposed directly to the public internet.

Things worth knowing before you deploy or report:

- **Playbooks are code execution.** Anyone allowed to run a playbook can run arbitrary commands on the targets, and inside the worker container that runs it, as the worker's user. Workers have no database access and no encryption key: the API hands each run only its own secrets. But runs are **not sandboxed** from each other yet: a run can read the files of other runs executing on the same worker at the same time (including their SSH keys while they run) and whatever else the worker's user can reach, and it can reach the network the worker is on. The worker hides its own memory and environment (and with them its `WORKER_TOKEN`) from runs. Only give the operator role and project access to people you would trust with that; per-run isolation is planned.
- **Global admins are local only.** Single sign-on will not sign in a global admin unless you explicitly set `SSO_ALLOW_ADMIN=true`, so password login stays your break-glass.
- **Secrets are best-effort scrubbed** from run output. `no_log: true` and Ansible Vault remain the primary controls; the scrubber cannot catch transformed or unknown secrets.
- **Change the defaults.** Production mode (`ENVIRONMENT=production`) refuses to start with the default admin password or auth secret.

Reports of authentication or authorization bypass, credential or secret exposure, cross-project access, or anything that breaks the boundaries above are in scope. Issues that require an already-trusted operator to run a malicious playbook are expected behaviour, not vulnerabilities.
