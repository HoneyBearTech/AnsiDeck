# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability reporting](https://github.com/HoneyBearTech/AnsiDeck/security/advisories/new) rather than a public issue.

This is a personal project maintained by one person, so there is no formal SLA, but reports will be acknowledged as soon as reasonably possible.

## Supported Versions

There are no tagged releases yet. Until there are, only the current `main` branch is supported. Once releases exist, only the most recent tagged release (and its Docker image) will receive security fixes.

## Scope

AnsiDeck holds SSH keys and vault passwords and runs Ansible against real infrastructure, so treat a deployment as a sensitive system. It is designed to run on a trusted network behind a reverse proxy that terminates TLS, and it is **not** designed or tested to be exposed directly to the public internet.

Things worth knowing before you deploy or report:

- **Playbooks are code execution.** Anyone allowed to run a playbook can run arbitrary commands on the targets, and inside the worker container that runs it. Workers have no database access and no encryption key: the API hands each run only its own secrets. Each worker slot runs its playbooks as a Linux user of its own, with no capabilities. A run cannot read the worker's memory or environment (and with them its `WORKER_TOKEN`) or signal it, and it cannot read the files, environment or memory of runs on other slots. After every run, everything that user still runs is killed and its files are deleted, so nothing carries over to the slot's next run (which may belong to another project). Each run also has its own SSH connection cache. What runs still share: the worker's network (they can reach the API and anything else the worker can), its kernel, CPU and memory, the list of running processes and their command lines, and the read-only application code. A production worker refuses to start if it cannot isolate runs this way. Only give the operator role and project access to people you would trust with the rest.
- **Global admins are local only.** Single sign-on will not sign in a global admin unless you explicitly set `SSO_ALLOW_ADMIN=true`, so password login stays your break-glass.
- **Notifications send metadata, not output.** Messages to Discord, Slack, Teams, webhooks, email, Pushbullet and Pushover carry names, statuses, counts and failed task/host names, never secrets or task output. Webhook URLs and push tokens are stored encrypted and never returned by the API. Webhooks can't reach loopback, private or link-local addresses (checked after DNS resolution, connecting only to the checked address, no redirects) unless the deployment allowlists them in `NOTIFY_ALLOWED_PRIVATE_HOSTS`.
- **Metrics are counts, not content.** The optional Prometheus endpoint (only with `METRICS_TOKEN`, on its own port 8002 that must not be published) reports counts, durations and statuses labelled by project id, route template, worker id and audit action. It never reports user names, playbook names, inventory host names, run ids, raw request paths, secrets or run output. Wrong tokens are throttled per address and audited.
- **Secrets are best-effort scrubbed** from run output. `no_log: true` and Ansible Vault remain the primary controls; the scrubber cannot catch transformed or unknown secrets.
- **Change the defaults.** Production mode (`ENVIRONMENT=production`) refuses to start with the default admin password or auth secret.

Reports of authentication or authorization bypass, credential or secret exposure, cross-project access, or anything that breaks the boundaries above are in scope. Issues that require an already-trusted operator to run a malicious playbook are expected behaviour, not vulnerabilities, unless the playbook breaks out of the run isolation described above.
