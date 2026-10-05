# Administration

## Workers

**Workers** (global admins) shows the worker processes that run playbooks: how many are online, how many of
their slots are busy, when each was last seen, and whether it **isolates** runs (each slot runs playbooks
as a Linux user of its own). The page warns when no worker is online (queued runs then wait) and when a
worker runs without isolation, which is only acceptable for development. It refreshes every few seconds.

With a secret store configured, a card shows whether AnsiDeck can reach it, its version, whether it is
sealed, and how long AnsiDeck's token has left.

Add capacity with more workers (`docker compose up -d --scale worker=3`) or more slots per worker
(`WORKER_SLOTS`). See [installing.md](../installing.md).

## Audit log

**Audit** (global admins) records who did what: sign-ins and sign-in failures, permission denials, runs
started and cancelled, changes to users, projects, members, credentials, sources and settings. Filter by an
action prefix (`auth.`, `credential.`), by actor, and by outcome (success, failure, denied), and page
through the results. Entries are kept for `AUDIT_RETENTION_DAYS` (365 by default) and never contain
secrets.

## Metrics and Grafana

AnsiDeck can expose Prometheus metrics (runs, queue, workers, HTTP requests, audit events) on a separate
port, and provides read-only database views and ready-made dashboards for Grafana. Setting them up is
described in the README's [Monitoring with Prometheus and
Grafana](../../README.md#monitoring-with-prometheus-and-grafana-optional).

## Backups and upgrades

See [upgrading.md](../upgrading.md): what to back up (including the encryption key), how to restore, and
how to move to a new release.
