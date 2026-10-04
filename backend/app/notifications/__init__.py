"""Notifications (Phase 4D): channels (Discord, Slack, Microsoft Teams, a generic webhook,
email, Pushbullet, Pushover) subscribe to events; app.notifications.events writes one outbox
row per matching channel in the same transaction as what happened, and
app.notifications.dispatch sends them from the API process with retries. Workers never
send anything (they have no key or database).

Messages carry metadata only (names, statuses, counts, failed task and host names), never
secrets or module output. Webhook URLs and push tokens are secrets themselves: stored
encrypted, shown masked, never logged or audited.
"""

from dataclasses import dataclass

KINDS = ("webhook", "discord", "slack", "teams", "email", "pushbullet", "pushover")

RUN_FAILED = "run.failed"
RUN_RECOVERED = "run.recovered"
WORKER_OFFLINE = "worker.offline"
WORKER_UNISOLATED = "worker.unisolated"
QUEUE_STUCK = "queue.stuck"
SECRETS_UNAVAILABLE = "secrets.unavailable"
LOGIN_ATTACK = "security.login_attack"
ADMIN_CHANGE = "security.admin_change"
# Data "state" of an all-clear: sent on the same event as its alert (worker back online,
# queue moving again), so whoever got the alert gets the all-clear.
RESOLVED = "resolved"


@dataclass(frozen=True)
class EventInfo:
    label: str
    description: str
    # Project events come from one project: its channels get them, and so does every global
    # channel subscribed to them. Global events (ops, security) go to global channels only.
    project: bool
    group: str  # for the UI: Runs, Operations, Security


EVENTS: dict[str, EventInfo] = {
    RUN_FAILED: EventInfo(
        "Run failed", "A run failed, timed out, or lost its worker.", project=True, group="Runs"
    ),
    RUN_RECOVERED: EventInfo(
        "Run recovered",
        "A playbook succeeded on an inventory after its previous run there failed.",
        project=True,
        group="Runs",
    ),
    WORKER_OFFLINE: EventInfo(
        "Worker offline",
        "A worker stopped reporting in (and again when it is back online).",
        project=False,
        group="Operations",
    ),
    WORKER_UNISOLATED: EventInfo(
        "Worker not isolated",
        "A worker runs playbooks as its own user, so runs can read each other's files.",
        project=False,
        group="Operations",
    ),
    QUEUE_STUCK: EventInfo(
        "Queue stuck",
        "Runs have waited too long for a worker (and again when the queue moves).",
        project=False,
        group="Operations",
    ),
    SECRETS_UNAVAILABLE: EventInfo(
        "Secret store unavailable",
        "AnsiDeck can't read from the secret store (unreachable, sealed, or its login fails), "
        "so runs needing its secrets fail (and again when it works).",
        project=False,
        group="Operations",
    ),
    LOGIN_ATTACK: EventInfo(
        "Login attack",
        "Repeated failed sign-ins locked out an address or user, or a wrong worker token.",
        project=False,
        group="Security",
    ),
    ADMIN_CHANGE: EventInfo(
        "Admin change",
        "A global admin was created or promoted, 2FA was reset or turned off, or an admin "
        "signed in with SSO.",
        project=False,
        group="Security",
    ),
}

PROJECT_EVENTS = frozenset(name for name, info in EVENTS.items() if info.project)
