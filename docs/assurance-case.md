# Assurance case

This document argues that AnsiDeck meets its [security requirements](security.md). It describes the
threat model, identifies the trust boundaries, shows how secure design principles were applied, and lists
how common implementation weaknesses are countered, with pointers to the code and tests that back each
claim. The component overview is in [architecture.md](architecture.md).

The top-level claim is:

> **Deployed as documented, AnsiDeck lets each user do only what their role in each project allows; it
> never discloses stored secrets except to the run that needs them; and a run cannot affect AnsiDeck,
> its keys or other runs beyond the limits stated in [security.md](security.md).**

It rests on four arguments: the threat model is understood (1), every trust boundary is mediated (2),
the design follows secure design principles (3), and the implementation counters common weaknesses and
is continuously verified (4).

## 1. Threat model

**Assets**, most valuable first: SSH private keys, vault passwords, environment-variable credentials and
the secret-store login; the deployment's own keys (`CREDENTIAL_ENCRYPTION_KEY`, `AUTH_SECRET_KEY`,
`WORKER_TOKEN`, `METRICS_TOKEN`); the ability to run playbooks on managed hosts; playbooks, inventories
and run output (which can contain sensitive data); user accounts and sessions; the audit log.

**Actors and what they may try:**

| Actor | Trusted with | Threats considered |
| --- | --- | --- |
| Unauthenticated network client | Nothing | Guess passwords or API keys, forge cookies, cross-site requests, reach internal ports, exploit parsers. |
| Viewer | Reading a project's content | Read other projects, read secrets, change anything, run anything, escalate role. |
| Operator | Running playbooks in a project | Use another project's credentials, run as root without `runs:become`, read secret values through the API, attack the worker or other runs from inside a playbook. |
| Project admin | Managing one project (members, sources, secrets) | Reach other projects; use a git remote, webhook or inventory source to reach internal services (SSRF) or run code in the API. |
| Global admin | Everything | Out of scope as an attacker (break-glass account); defended against account takeover via SSO (`SSO_ALLOW_ADMIN`). |
| API key holder (CI) | One project, a fixed preset | Exceed the preset, reach other projects, act as an admin. |
| Hostile content | Nothing | A malicious git repository, inventory source response (NetBox, cloud API), playbook output or Galaxy content trying to execute code in the API, template code into runs, escape directories or exhaust resources. |
| Compromised worker | One claimed job at a time | Claim other jobs' secrets, write to the database, persist into the next run. |
| Network attacker between components | Nothing | Intercept outgoing traffic (webhooks, git, secret store, SSO). |

**Out of scope** (see [security.md](security.md#what-ansideck-does-not-protect-against)): a malicious
global admin; anyone with access to the host, the Docker daemon, the database or the deployment's keys;
a trusted operator using a playbook to do harm on the targets (that is the product's purpose);
vulnerabilities in Ansible, its plugins or the managed hosts; deployments exposed directly to the internet.

## 2. Trust boundaries

| # | Boundary | What crosses it | How it is mediated |
| --- | --- | --- | --- |
| B1 | Browser / CI → reverse proxy → frontend nginx → public API | HTTP and WebSocket requests | TLS at the proxy; session cookie or API key on every route (`app/dependencies.py`, `app/api_keys.py`); per-route permission guard (`app/permissions.py`) and per-project resolution (`app/scoping.py`); Origin check on state-changing requests and WebSocket handshakes (`app/hardening.py`); login throttles; Pydantic request schemas (`app/schemas/`). |
| B2 | Public API → Postgres | SQL | SQLAlchemy with bound parameters; the database is on its own Docker network (`db`) and published only on `127.0.0.1`; workers are not on that network. |
| B3 | Worker → internal API | Claims, job descriptions with secrets, events, output | Separate ASGI app on an unpublished port (`app/internal_api.py`); shared `WORKER_TOKEN` compared in constant time, plus a per-claim token; `410 Gone` once a claim ends; uploads size-limited and validated; workers sit only on the `workers` network. |
| B4 | Worker process → slot (playbook) | The job directory, environment, the run's own secrets | A separate Linux user per slot with no capabilities, `no_new_privs`, no supplementary groups (`app/run_isolation.py`); the worker is non-dumpable (`app/process_hardening.py`), so a run can't read its memory or token; allowlisted environment (`app/subprocess_env.py`); sweep after every run. The worker container itself drops all capabilities except `SETUID`, `SETGID`, `CHOWN`, `KILL`, has `no-new-privileges`, a read-only root filesystem and a PID limit (`docker-compose.yml`). |
| B5 | API → git remotes, webhooks, e-mail, push services | Outgoing connections chosen by project admins | Destination resolved and refused unless public or allowlisted, then connected to exactly the checked address with no redirects or proxy (`app/netguard.py`, `app/notifications/safe_http.py`); TLS verified against the real host name; git run with no config, hooks, helpers or `ext::`, with fsck, timeouts and size limits (`app/git_sync.py`). |
| B6 | Inventory source / git repository / playbook output → API | Untrusted data | Size, count and nesting limits (`app/json_limits.py`, `app/inventory_sources.py`); safe YAML loading; host and group names checked with Ansible's own parser; source strings rendered `!unsafe` (`app/inventory_render.py`); tar snapshots unpacked with Python's `data` filter by the slot user; run output scrubbed (`app/scrub.py`). |
| B7 | API → secret store | Project-scoped secret reads | Paths built from the credential's project, never from the request; token or AppRole secret read from a file; optional single-use child token limited to one project (`app/secret_store.py`); TLS verified (custom CA supported). |
| B8 | Prometheus / Grafana → API metrics and analytics views | Counts and curated fields | Separate port with bearer token, throttled and audited (`app/metrics_api.py`); a read-only database role limited to the `analytics` views (`app/analytics.py`). |

### Attack surface

What an attacker can reach, from where, and what protects it. Each entry is detailed in
[interfaces.md](interfaces.md).

| Entry point | Reachable by | Main protections | Critical code paths |
| --- | --- | --- | --- |
| Web UI and HTTP API (port 8080 → 8000) | anyone who can reach your proxy | authentication on every route, per-project authorization, Origin check, throttling, CSP, input schemas | `app/dependencies.py`, `app/permissions.py`, `app/scoping.py`, `app/routers/` |
| Run output WebSocket | signed-in users and API keys | the same authentication and read permission, Origin check | `app/routers/runs.py` |
| Worker API (port 8001) | anything on the workers' network | `WORKER_TOKEN` (constant-time), per-claim tokens, size limits, not published | `app/internal_api.py` |
| Metrics (port 8002) | Prometheus | bearer token, throttled and audited, counts only, not published | `app/metrics_api.py` |
| Git repositories | whoever can push to a synced repository | SSRF guard, hardened git, size limits, data-only tar unpacking by the run user | `app/git_sync.py`, `app/run_worker.py` |
| Inventory source responses | whoever controls NetBox, a cloud account, or the plugin's API | runs only in isolated workers, bounded parsing, name checks, `!unsafe` rendering | `app/inventory_sources.py`, `app/inventory_render.py` |
| Playbook checks (ansible-lint) | operators, and whoever can push to a synced repository | run only in isolated workers like playbooks (ansible-lint loads module, collection and a repository's own rule code), no secrets; its config is always passed explicitly (no search of parent directories), and a repository's config can't make it write files or load rules from outside the repository; findings private to the requester; size, time and concurrency limits | `app/run_worker.py`, `app/lint.py` |
| Playbooks, roles, collections | operators and Galaxy publishers | per-slot Linux users, sweep after each run, no keys or database on workers | `app/run_isolation.py`, `app/worker/` |
| Notification destinations | project admins (choosing URLs) | SSRF guard, no redirects, TLS verification | `app/netguard.py`, `app/notifications/` |
| Secret store | whoever controls the store or its network | per-project paths built server-side, TLS, short-lived child tokens | `app/secret_store.py` |
| The release pipeline | the maintainer, GitHub Actions | protected `main`, pinned actions, Trivy gate, keyless signing | `.github/workflows/docker-publish.yml` |

The threats, boundaries and countermeasures in this document are reviewed whenever a feature adds an
entry point or changes one of these paths (the pull request says so), and at each release.

## 3. Secure design principles

The principles below are Saltzer and Schroeder's, plus the additional ones the OpenSSF badge lists.

- **Economy of mechanism.** One authorization path: a coarse permission guard on every route plus
  `app/scoping.py` resolving every project-owned resource. One queue (Postgres rows, `app/queue.py`), one
  source of truth for run output (`app/run_log.py`). Dependencies are kept small and pinned.
- **Fail-safe defaults.** Access is denied unless a guard grants it, and a test fails if a route has no
  guard (`tests/test_rbac.py::test_every_route_carries_a_permission_guard_or_is_explicitly_public`).
  Production mode refuses default secrets; outgoing connections to private addresses are refused unless
  allowlisted; a worker that can't isolate runs refuses to start; failing inventory sources and an
  unreachable secret store fail the job rather than quietly continuing.
- **Complete mediation.** Every request is authenticated and authorized, including WebSocket streams
  (`tests/test_rbac.py::test_websocket_requires_auth_permission_and_valid_origin`) and every internal API
  call. Sessions are re-checked against the user's current `session_version` on each request.
- **Open design.** The code, this case and the threat model are public. Security relies on keys, not on
  the secrecy of the design.
- **Separation of privilege.** Running a playbook needs the operator role in that project and a credential
  from that project; running as root needs a separate `runs:become` permission; an SSH key that can run
  playbooks is a different credential kind from inventory-source variables.
- **Least privilege.** Per-project roles; API keys with one project and a fixed preset; workers without
  database access or keys; one unprivileged user per slot; containers with dropped capabilities and
  read-only filesystems; a Grafana role that can read only curated views; secret-store policies limited to
  AnsiDeck's prefix and, optionally, one project per child token.
- **Least common mechanism.** Each run has its own directory, home, SSH connection cache and slot user; each
  project its own secret-store subtree. What runs still share is listed in [security.md](security.md).
- **Psychological acceptability.** Secure options are the defaults; denials explain what is missing;
  two-factor sign-in is one page; the UI never asks users to copy secrets out of AnsiDeck.
- **Limited attack surface.** Only the frontend's port needs to be published. The internal API and
  metrics ports are separate apps that are never proxied; there is no shell, no file browser and no
  "reveal secret" endpoint.
- **Input validation with allowlists.** Request schemas constrain types, lengths and ranges; names use
  allowlisted character sets; URLs are limited to allowlisted schemes; plugin configs to allowlisted
  plugin types (see section 4).

## 4. Countering common implementation weaknesses

Mapped to the [OWASP Top 10 (2021)](https://owasp.org/Top10/) and the
[CWE Top 25](https://cwe.mitre.org/top25/):

| Weakness | Countermeasures |
| --- | --- |
| **Broken access control** (A01; CWE-862, CWE-863, CWE-639 IDOR, CWE-352 CSRF) | Guards on every route and project scoping that answers 404 for resources in other projects (`app/scoping.py`); a full role × route permission matrix (`tests/test_rbac.py::test_permission_matrix`); an IDOR matrix that every project-scoped route with an id must be part of (`tests/test_projects.py::test_every_project_scoped_route_with_an_id_is_covered_by_the_idor_matrix`); Origin check plus `SameSite=Lax` cookies against CSRF; API keys can't be admins (`app/api_keys.py`). |
| **Cryptographic failures** (A02; CWE-327, CWE-916, CWE-798) | Argon2id for passwords (`app/crypto.py`); HMAC-SHA-256 signed cookies; Fernet for secrets at rest; SHA-256 for 256-bit API keys; no SHA-1, MD5 or DES in security functions; TLS certificate and host-name verification on all outgoing TLS; no hard-coded production secrets (production mode refuses the development defaults). |
| **Injection** (A03; CWE-89, CWE-78, CWE-79, CWE-94, CWE-1336) | SQL through SQLAlchemy with bound parameters (the few formatted statements use constants or quoted identifiers in the operator CLI); every subprocess gets an argument list, never a shell (no `shell=True` anywhere); React escapes output, run logs are converted by `ansi_up` with HTML escaping on, and the Content-Security-Policy blocks inline and third-party scripts if something slips through; Jinja injection from inventory data is prevented by `!unsafe` rendering; YAML is loaded with a `SafeLoader` subclass. |
| **Insecure design** (A04) | The threat model and trust boundaries above; run isolation designed in (Phase 4C) rather than added afterwards; security-relevant decisions reviewed in each pull request. |
| **Security misconfiguration** (A05) | Production mode refuses insecure defaults (`app/config.py`); the frontend's nginx sends a strict Content-Security-Policy (scripts only from the app's own origin, no framing, no plugins), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP and a restrictive `Permissions-Policy` (`frontend/docker/nginx.conf`, checked by the runtime smoke test); compose publishes Postgres, OpenBao and metrics only on `127.0.0.1`; the API and frontend containers run as non-root users, and the worker starts as root only to run each slot as its own unprivileged user, with every other capability dropped; base images are pinned by digest. |
| **Vulnerable and outdated components** (A06; CWE-1104) | Locked dependencies (`uv.lock`, `package-lock.json`); `pip-audit` and `npm audit` in CI; Dependabot for Python, npm, Docker and GitHub Actions; GitHub Actions pinned by commit hash. |
| **Identification and authentication failures** (A07; CWE-287, CWE-307, CWE-384) | Per-user and per-address throttles for passwords, TOTP, API keys and SSO (`app/hardening.py`), with lockouts audited and alerted; TOTP with replay protection and single-use recovery codes (`app/totp.py`); session versioning ends sessions on password and 2FA changes; SSO state and nonce checks and ID-token verification (`app/oidc.py`, `app/sso_common.py`). |
| **Software and data integrity failures** (A08; CWE-502, CWE-345) | No pickle or unsafe deserialization; git commits pinned per run and snapshots checked by size and hash by the worker; tar snapshots unpacked with the `data` filter; JSON from plugins parsed with bounded nesting (`app/json_limits.py`). |
| **Logging and monitoring failures** (A09; CWE-778) | Audit log for sign-ins, denials, run activity and configuration and secret changes (`app/audit.py`); security alerts for login attacks and failing refreshes; Prometheus metrics and Grafana dashboards. Secrets are never logged: they are scrubbed from run output, and stored values are never returned. |
| **Server-side request forgery** (A10; CWE-918) | `app/netguard.py`: resolve, refuse non-public addresses unless allowlisted, connect to the checked address, no redirects or proxies; the same for git remotes. Cloud metadata is disabled for inventory refreshes (`AWS_EC2_METADATA_DISABLED`). |
| **Path traversal** (CWE-22) and **unrestricted upload** (CWE-434) | Storage paths are built from database ids, not request data (`app/storage.py`); symlinks escaping a repository are refused; snapshots unpacked with the `data` filter; upload, repository and output sizes are limited. |
| **Resource exhaustion** (CWE-400, CWE-770) | Size limits on internal API uploads (4 MiB per request), playbooks, inventory-source output and git repositories, run timeouts (2 h default, 24 h maximum), git and refresh timeouts and size limits, playbook checks (1 MiB, 2 min, two at once, one queued per person), PID limits on workers, bounded JSON nesting, throttled authentication. |
| **Memory-safety weaknesses** (CWE-787, CWE-125, CWE-416) | AnsiDeck is written in memory-safe languages (Python, TypeScript). |

## 5. Verification evidence

- **Automated tests** on every pull request: over 900 backend tests on Postgres with a CI-enforced
  branch-coverage floor of 80% (`backend/scripts/check_branch_coverage.py`), including authorization
  matrices, cross-project tests, real `ansible-playbook` and `ansible-inventory` runs, and isolation
  tests run as root in the worker image; and frontend tests (Vitest and Testing Library) that drive every
  page through the real routing and permission checks against a fake API, with a CI-enforced statement
  coverage floor of 80%.
- **Static analysis**: CodeQL (Python and TypeScript) on every pull request and weekly; ruff with security (bandit), correctness and style rules; TypeScript in strict mode with extra checks; oxlint with correctness, suspicious, React and accessibility rules; warnings fail CI, and the test suite treats Python warnings as errors.
- **Fuzzing**: Atheris drives the Hypothesis properties for secret scrubbing, vault encryption, inventory
  rendering and secret collection on every pull request that touches the backend (`backend/fuzz/`).
- **Supply chain**: OpenSSF Scorecard weekly; dependency audits in CI; Dependabot; digest-pinned images and
  hash-pinned actions; secret scanning with push protection on the repository. Releases are built by a
  workflow that refuses images with fixable HIGH or CRITICAL vulnerabilities (Trivy), attaches SBOM and SLSA
  provenance, and signs images and checksums keylessly with cosign ([verifying-releases.md](verifying-releases.md));
  the frontend build is reproducible.
- **End-to-end checks** in CI against the runtime images (`.github/workflows/docker-build.yml`): startup
  refusals, metrics, analytics roles, Grafana dashboards, secret-store outages and inventory refreshes.
- **Process**: protected `main` with required checks; security-sensitive changes called out in pull
  requests (see [CONTRIBUTING.md](../CONTRIBUTING.md)); vulnerability handling as in
  [SECURITY.md](../SECURITY.md).

This case is updated when the design changes; a claim here that no longer matches the code is a bug.
