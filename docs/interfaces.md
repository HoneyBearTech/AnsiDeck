# External interfaces

Every way people and other software interact with a running AnsiDeck, what each one expects and produces,
and where it's specified. Which of these should be reachable from where is described in the
[assurance case](assurance-case.md#attack-surface) and in [installing.md](installing.md).

## Interfaces AnsiDeck offers

| Interface | Where | Who uses it | Authentication | Specification |
| --- | --- | --- | --- | --- |
| Web UI | frontend container, port 8080 (behind your HTTPS proxy) | people, in a browser | session cookie after sign-in | the [user guide](user-guide/README.md) |
| HTTP API | `/api/…` on the backend's port 8000, also proxied by the frontend | the web UI, CI/CD, scripts | session cookie, or `Authorization: Bearer <API key>` | [`api/openapi.json`](api/openapi.json) (OpenAPI 3) |
| Run output stream | WebSocket `/api/runs/{id}/ws?from=<n>` | the web UI, CI/CD | as the HTTP API | [below](#run-output-stream) |
| Worker API | `/internal/…` on the backend's port 8001, never published | AnsiDeck's workers only | `WORKER_TOKEN`, plus a per-job claim token | [`api/internal-openapi.json`](api/internal-openapi.json) |
| Metrics | `/metrics` on the backend's port 8002 (only with `METRICS_TOKEN`), never published | Prometheus | `Authorization: Bearer <METRICS_TOKEN>` | Prometheus text format; the metrics are listed in the README's [monitoring section](../README.md#monitoring-with-prometheus-and-grafana-optional) |
| Analytics views | the `analytics` schema in Postgres | Grafana | a database role granted by `analytics-grant` | the README's [analytics section](../README.md#history-for-grafana-the-read-only-analytics-views) |
| Command line | `python -m app.cli <command>` in the backend container | operators | access to the container | [below](#command-line) |
| Configuration | environment variables, and files in `SECRETS_DIR` | operators | access to the host | [`.env.example`](../.env.example) and the [README](../README.md) |

### HTTP API

The OpenAPI description lists every route with its parameters, request and response bodies, and status
codes. A running backend also serves it interactively at `/docs` and as `/openapi.json`. Conventions:

- JSON in and out; errors are `{"detail": "…"}` with a 4xx or 5xx status. 401 means not signed in, 403 not
  permitted, 404 also covers resources in projects you can't see, and 409 a conflict with the current
  state (for example deleting something still in use).
- State-changing requests from a browser must come from the same origin (or one in `CORS_ORIGINS`).
- API keys (see the [user guide](user-guide/projects-and-users.md#api-keys-for-ci)) reach only their
  project's run routes; the README's [Triggering runs from CI](../README.md#triggering-runs-from-ci) shows
  them in use.
- The committed description is checked against the code by a test, so it's current for each commit.

### Run output stream

`GET /api/runs/{id}/ws?from=<n>` upgrades to a WebSocket and sends the run's log from line `n` (0 for the
start), one JSON event per message (Ansible's event, with its `stdout` text and a `counter`), as Ansible
produces it. The server closes with code **1000** once the run has finished and every line was sent, and
with **1008** when the caller may not read the run. Any other close cut the stream short: reconnect with
`from` set to the number of messages received so far. Secret values known to AnsiDeck are removed from the
output before it's stored or sent.

### Command line

In the backend container (`docker compose exec backend python -m app.cli …`):

| Command | Does |
| --- | --- |
| `migrate` | bring the database schema to the latest revision (the API also does this when it starts) |
| `import-sqlite` | import a pre-Postgres `ansideck.db` once (see [upgrading.md](upgrading.md#from-the-sqlite-era)) |
| `reset-totp <username>` | turn off a user's two-factor login |
| `analytics-grant <role>` / `analytics-check <role>` / `analytics-revoke <role>` | manage a database role's read access to the analytics views |

## Interfaces AnsiDeck uses

| Interface | Used for | Protocol | Configured by |
| --- | --- | --- | --- |
| Managed hosts | running playbooks | SSH (Ansible), from the workers | inventories and credentials |
| Inventory sources | dynamic inventory (NetBox, clouds, …) | each plugin's API, from the workers | inventory sources |
| Git remotes | syncing playbooks | HTTPS or SSH, from the API | git sources |
| Ansible Galaxy | installing roles and collections | HTTPS | the Galaxy page |
| OpenBao / HashiCorp Vault | reading secrets kept in the store | KV v2 HTTP API over TLS | `SECRETS_STORE_*` settings |
| OpenID Connect provider, GitHub | single sign-on | OAuth 2.0 / OpenID Connect over HTTPS | `OIDC_*`, `GITHUB_*` settings |
| Chat, push and webhook services | notifications | HTTPS (JSON) | notification channels |
| SMTP server | email notifications | SMTP with STARTTLS or TLS | `SMTP_*` settings |
| PostgreSQL | all state | PostgreSQL protocol | `DATABASE_URL` |

### Webhook notifications

A generic webhook receives a `POST` with a JSON body: `event` (for example `run.failed`), `title`,
`summary`, `url` (a link to the run, when `PUBLIC_URL` is set) and `data` (event-specific fields such as the
run's id, status and failed tasks). With a signing secret, the request also carries `X-AnsiDeck-Timestamp`
and `X-AnsiDeck-Signature: sha256=<hex HMAC-SHA-256 of "<timestamp>.<body>">`. The event list is in the
[notifications guide](user-guide/notifications.md#events). Messages never contain secrets or task output.
