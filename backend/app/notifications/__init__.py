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


@dataclass(frozen=True)
class EventInfo:
    label: str
    description: str
    # Project events come from one project: its channels get them, and so does every global
    # channel subscribed to them. Global events (ops, security; 4D-2) go to global channels only.
    project: bool


EVENTS: dict[str, EventInfo] = {
    RUN_FAILED: EventInfo(
        "Run failed", "A run failed, timed out, or lost its worker.", project=True
    ),
    RUN_RECOVERED: EventInfo(
        "Run recovered",
        "A playbook succeeded on an inventory after its previous run there failed.",
        project=True,
    ),
}

PROJECT_EVENTS = frozenset(name for name, info in EVENTS.items() if info.project)
