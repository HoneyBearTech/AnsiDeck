# Notifications

**Notifications** sends events to Discord, Slack, Microsoft Teams (a Workflows webhook), a generic webhook,
email, Pushbullet or Pushover. Messages carry names, statuses, counts and failed task and host names, never
secrets or task output.

## Channels

- **Project channels** (project admins) receive the project's events.
- **Global channels** (global admins) receive run events from every project, plus operations and security
  events.

**New channel**: a name, where to send it (**Send to**), the destination (a webhook URL, a push token and
user key, or email recipients, one per line), and the events. A generic webhook can have a **signing
secret**: requests then carry `X-AnsiDeck-Timestamp` and `X-AnsiDeck-Signature: sha256=<HMAC of
"<timestamp>.<body>">`. URLs and tokens are stored encrypted and never shown again: when editing, leave them
empty to keep them.

On each channel: a switch turns it off and on, **Send test** sends a test message, **History** shows the
recent deliveries (with errors and retries), **Edit** and **Delete** (after a confirmation). The last
delivery's result is shown on the card. Failed deliveries are retried for up to about 1 h 45 min.

## Events

| Event | When | Channels |
| --- | --- | --- |
| Run failed | A run failed, timed out or lost its worker; the message names the failed tasks and hosts | project, global |
| Run recovered | A playbook succeeded on an inventory after its previous run there failed | project, global |
| Inventory refresh failed | A dynamic inventory's refresh failed (once per failing streak), and when it works again | project, global |
| Worker offline | A worker stopped reporting in, and when it is back | global |
| Worker not isolated | A worker runs playbooks without per-slot users | global |
| Queue stuck | A run has waited too long for a worker or a Galaxy install, and when the queue moves | global |
| Secret store unavailable | AnsiDeck can't reach or read the secret store, and when it is back | global |
| Login attack | Failed sign-ins locked out an address or user, or something used a wrong worker token | global |
| Admin change | A global admin was created or promoted, someone's two-factor login was reset or turned off, or a global admin signed in with SSO | global |

The server settings behind this (email server, private webhook hosts, links to runs, thresholds) are in the
README's [Notifications](../../README.md#notifications) section.
