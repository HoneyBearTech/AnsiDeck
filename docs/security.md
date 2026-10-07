# Security requirements

This page says what you can and cannot expect from AnsiDeck in terms of security. The reasoning behind it
(threat model, trust boundaries, design principles and how common weaknesses are countered) is in the
[assurance case](assurance-case.md). To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Intended deployment

AnsiDeck is meant to run on a **trusted network**, behind a reverse proxy that terminates TLS, for a team
that already trusts each other with the infrastructure it manages. It is **not** designed or tested to be
exposed directly to the public internet. The rest of this page assumes that deployment, with
`ENVIRONMENT=production` set and the advice in the README's "Running it securely" section followed.

## What AnsiDeck is designed to guarantee

**Authentication and sessions**

- Every API route, apart from health checks and the sign-in flow, requires a signed-in user or an API
  key (the workers' internal routes require the worker token). A test fails if a route is added without an
  access check.
- Passwords are stored as Argon2id hashes. Sign-in failures are throttled per user and per client address,
  and repeated failures are audited and can raise an alert. The address comes from proxy headers only when
  a trusted proxy sent them (`TRUSTED_PROXIES` on the frontend, `TRUSTED_PROXY_HOSTS` on the API).
- Optional two-factor sign-in (TOTP authenticator codes plus single-use recovery codes) for password
  logins. Single sign-on (OpenID Connect, GitHub) relies on the provider's MFA, and never signs in a global
  admin unless `SSO_ALLOW_ADMIN=true`.
- Session cookies are signed (HMAC-SHA-256), `HttpOnly`, `SameSite=Lax` and `Secure` when
  `COOKIE_SECURE=true`. Changing your password or turning on two-factor sign-in ends your other sessions, an
  admin resetting your password, two-factor login or deactivating you ends all of them; signing out deletes the cookie in that browser. State-changing requests
  and WebSocket handshakes from another origin are refused.
- The web app is served with a strict Content-Security-Policy and other browser hardening headers
  (no framing, no MIME sniffing, no referrer). HSTS is up to your TLS-terminating proxy.
- API keys carry 256 bits of entropy, are stored only as hashes, belong to exactly one project with a fixed
  preset (trigger or read-only), can expire, and are never global admins. A key works only while its creator
  is active and may still manage that project's keys, and creating one needs the current password (or an SSO
  sign-in within 15 minutes).
- Production mode refuses to start with the default admin password, auth secret, database password or
  worker token.

**Authorization**

- Access is role-based and per project (admin, operator, viewer), plus a global admin. Every resource is
  resolved through the caller's project memberships, so content in a project you don't belong to can't be
  read, changed or run, even by id. Denials are audited.
- Secrets are write-only through the API: credential values, vault passwords, webhook URLs and push tokens
  are never returned once stored.

**Secrets**

- Stored secrets (SSH keys, environment-variable credentials, vault passwords, notification tokens, TOTP
  secrets) are encrypted at rest with Fernet (`CREDENTIAL_ENCRYPTION_KEY`), or live in OpenBao / HashiCorp
  Vault and are read only when a run starts.
- A run receives only its own secrets, delivered by the API to the worker that claimed it. Workers have no
  database access and no encryption key.
- Known secret values are removed from run output before it is stored or streamed (best effort; see below).

**Running playbooks**

- Playbooks run only in worker containers, each worker slot as its own unprivileged Linux user. A run cannot
  read the worker's token, memory or environment, or another slot's files, environment, memory or
  processes, and nothing it leaves behind survives into the slot's next run. A production worker refuses to
  start if it can't isolate runs this way.
- A run uses the playbook, inventory and git commit as they were when it was started.

**Untrusted input**

- Input from users, git repositories, dynamic inventory sources and other services is validated against
  allowlists and size limits, and strings from inventory sources are never templated by Ansible.
- Outgoing connections that a user can point somewhere (webhooks, git remotes) are refused for loopback,
  private and link-local addresses unless the deployment allowlists them, are checked after DNS resolution,
  and don't follow redirects. TLS certificates are verified on every outgoing TLS connection (webhooks,
  e-mail, git over https, OpenBao, SSO providers).

**Accountability**

- Sign-ins, permission denials, run activity, configuration and secret changes are recorded in the audit
  log (kept for `AUDIT_RETENTION_DAYS`, 365 by default). Metrics and analytics views expose counts and
  curated fields, never secrets or run output.

## What AnsiDeck does not protect against

- **Trusted operators.** Anyone who may run a playbook can run any command on its targets and inside the
  worker's slot, and can read every secret the run uses (for example by printing it in a task). Give the
  operator role only to people you would trust with the hosts themselves.
- **Project admins and source owners.** Project admins can change git sources and dynamic inventory
  sources, whose plugins and Jinja run in workers. Whoever can push to a synced git repository or write a
  project's subtree in the secret store controls what that project runs and with which keys.
- **Shared worker resources.** Runs on the same worker share its network, kernel, CPU and memory, and can
  see the list of processes and their command lines. Runs can reach whatever the worker can reach,
  including the API and, in a cloud, the metadata address unless you block it.
- **Secret scrubbing is best effort.** Transformed or unknown secrets can appear in run output; `no_log:
  true` and Ansible Vault remain the primary controls.
- **Holders of the deployment's keys.** Anyone holding `CREDENTIAL_ENCRYPTION_KEY` can decrypt every stored
  secret, and anyone holding `WORKER_TOKEN` can claim runs and receive their secrets. Anyone with access to
  the host, the Docker daemon or the database is outside AnsiDeck's protection.
- **The network around it.** AnsiDeck does not terminate TLS itself; the reverse proxy must. Exposing it to
  the internet, or skipping `COOKIE_SECURE=true` behind HTTPS, is unsupported.
- **The targets and Ansible itself.** Vulnerabilities in Ansible, its collections, inventory plugins or the
  managed hosts are outside AnsiDeck; keep them up to date.

## Details by feature

- **Playbooks are code execution.** Anyone allowed to run a playbook can run arbitrary commands on the targets, and inside the worker container that runs it. Workers have no database access and no encryption key: the API hands each run only its own secrets. Each worker slot runs its playbooks as a Linux user of its own, with no capabilities. A run cannot read the worker's memory or environment (and with them its `WORKER_TOKEN`) or signal it, and it cannot read the files, environment or memory of runs on other slots. After every run, everything that user still runs is killed and its files are deleted, so nothing carries over to the slot's next run (which may belong to another project). Each run also has its own SSH connection cache. What runs still share: the worker's network (they can reach the API and anything else the worker can), its kernel, CPU and memory, the list of running processes and their command lines, and the read-only application code. A production worker refuses to start if it cannot isolate runs this way. Only give the operator role and project access to people you would trust with the rest.
- **Global admins are local only.** Single sign-on will not sign in a global admin unless you explicitly set `SSO_ALLOW_ADMIN=true`, so password login stays your break-glass.
- **Notifications send metadata, not output.** Messages to Discord, Slack, Teams, webhooks, email, Pushbullet and Pushover carry names, statuses, counts and failed task/host names, never secrets or task output. Webhook URLs and push tokens are stored encrypted and never returned by the API. Webhooks can't reach loopback, private or link-local addresses (checked after DNS resolution, connecting only to the checked address, no redirects) unless the deployment allowlists them in `NOTIFY_ALLOWED_PRIVATE_HOSTS`.
- **Git sources are fetched in the API container, never run there.** Project admins choose the remote, so the API checks it like a webhook (non-public addresses only when allowlisted in `GIT_ALLOWED_PRIVATE_HOSTS`, connecting to the checked address, no redirects, no proxy) and runs git with no system or user config, no hooks, no credential helpers or prompts, https/ssh only (never `ext::` or local paths), fsck on every fetch, no submodules, a timeout and size limits. Tokens and deploy keys exist only in a private temporary directory for one command. SSH remotes need a host key an admin confirmed. Commits whose symlinks point outside the repository are refused. A run of a synced playbook gets its commit as a tar that the worker checks against the job's size and hash; the run's own process (the slot's user) unpacks it with Python's `data` tar filter, so nothing lands outside the run's directory (no `..`, absolute or escaping links, devices or setuid bits). Git still parses the untrusted repository inside the API container (as its unprivileged user); keep git up to date.
- **A secret store keeps keys out of AnsiDeck's database.** Credentials and vault passwords can be references into OpenBao or HashiCorp Vault (KV v2), read when a run starts and never stored. Each project reads only its own subtree (`<mount>/<prefix>/<project id>/`, built from the credential's project; paths are plain segments, requests go out exactly as built, redirects are never followed), and optionally through a single-use child token that holds only that project's store policy. AnsiDeck's store login (a token or AppRole secret id) comes from a file, never reaches workers, logs or errors. What remains: anyone who can run a playbook with a credential can read it through the playbook (as with stored ones), whoever can write a project's subtree in the store controls its keys, and a stolen `WORKER_TOKEN` still receives the secrets of claimed runs.
- **Dynamic inventory sources are code, run in workers only.** A source's config names an inventory plugin, and its options (`compose`, `keyed_groups`, lookups) are Jinja that runs when the inventory is refreshed, so only project admins can change sources. Refreshes run `ansible-inventory` in an isolated worker slot like a playbook, read plugin configs and YAML only, fail when any source fails (rather than quietly giving fewer hosts), and never ask a cloud metadata service for the worker host's identity (`AWS_EC2_METADATA_DISABLED`). The API treats what a refresh returns as untrusted: size, host, group and nesting limits, names ansible would read differently are skipped, and every string that came from a source is rendered `!unsafe` in runs, so data from NetBox or a cloud API is never templated. Source credentials are environment variables given only to refreshes, and their values are removed from the output exactly. What remains: workers can reach the network, including the cloud metadata address, so block `169.254.169.254` for worker containers if they run in a cloud.
- **Metrics are counts, not content.** The optional Prometheus endpoint (only with `METRICS_TOKEN`, on its own port 8002 that must not be published) reports counts, durations and statuses labelled by project id, route template, worker id and audit action. It never reports user names, playbook names, inventory host names, run ids, raw request paths, secrets or run output. Wrong tokens are throttled per address and audited.
- **Grafana reads curated views only.** The optional `analytics` schema holds read-only views for a Grafana database role that the operator creates; `python -m app.cli analytics-grant` gives it `SELECT` on those views and nothing else, and `analytics-check` verifies that. The views leave out extra variables, host limits, playbook contents, credential names, hashes, encrypted values, run output, notification payloads and audit details beyond a few fixed fields, and show client addresses only as /24 (IPv4) or /48 (IPv6) networks. They do include user names and the names of projects, playbooks and inventories.
- **Secrets are best-effort scrubbed** from run output. `no_log: true` and Ansible Vault remain the primary controls; the scrubber cannot catch transformed or unknown secrets.
- **Change the defaults.** Production mode (`ENVIRONMENT=production`) refuses to start with the default admin password or auth secret.
