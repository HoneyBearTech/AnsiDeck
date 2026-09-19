# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability reporting](https://github.com/HoneyBearTech/AnsiDeck/security/advisories/new) rather than a public issue.

This is a personal project maintained by one person, so there is no formal SLA, but reports will be acknowledged as soon as reasonably possible.

## Supported Versions

There are no tagged releases yet. Until there are, only the current `main` branch is supported. Once releases exist, only the most recent tagged release (and its Docker image) will receive security fixes.

## Scope

AnsiDeck holds SSH keys and vault passwords and runs Ansible against real infrastructure, so treat a deployment as a sensitive system. It is designed to run on a trusted network behind a reverse proxy that terminates TLS, and it is **not** designed or tested to be exposed directly to the public internet.

Things worth knowing before you deploy or report:

- **Playbooks are code execution.** Anyone allowed to run a playbook can run arbitrary commands on the targets, and on the AnsiDeck host as the app's user. Runs use a cleaned environment, and the app hides its own process environment from them, but runs are **not sandboxed**: a run can still read and write the application's data directory (including its database and other projects' files). Only give the operator role and project access to people you would trust with that.
- **Global admins are local only.** Single sign-on will not sign in a global admin unless you explicitly set `SSO_ALLOW_ADMIN=true`, so password login stays your break-glass.
- **Secrets are best-effort scrubbed** from run output. `no_log: true` and Ansible Vault remain the primary controls; the scrubber cannot catch transformed or unknown secrets.
- **Change the defaults.** Production mode (`ENVIRONMENT=production`) refuses to start with the default admin password or auth secret.

Reports of authentication or authorization bypass, credential or secret exposure, cross-project access, or anything that breaks the boundaries above are in scope. Issues that require an already-trusted operator to run a malicious playbook are expected behaviour, not vulnerabilities.
