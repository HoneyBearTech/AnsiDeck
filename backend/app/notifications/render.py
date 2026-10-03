"""Turns an event's payload into what each kind of channel expects. Everything shown comes
from the payload (metadata) and is treated as untrusted text: playbook, inventory and task
names are written by users, so each format escapes its own markup and mentions."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from app.notifications import (
    ADMIN_CHANGE,
    LOGIN_ATTACK,
    QUEUE_STUCK,
    RESOLVED,
    RUN_FAILED,
    RUN_RECOVERED,
    WORKER_OFFLINE,
    WORKER_UNISOLATED,
)

TEST = "test"
_RED, _GREEN, _BLUE = 0xE5484D, 0x30A46C, 0x3E63DD
_MAX_FIELD = 1000


@dataclass
class Message:
    title: str
    summary: str  # one line, for previews and plain-text fallbacks
    color: int
    facts: list[tuple[str, str]] = field(default_factory=list)
    items_title: str | None = None
    items: list[str] = field(default_factory=list)
    url: str | None = None


def _clip(text: object, limit: int = 200) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _hosts(hosts: dict | None) -> str | None:
    if not hosts or not hosts.get("total"):
        return None
    parts = [
        f"{hosts[k]} {label}"
        for k, label in (("ok", "ok"), ("failed", "failed"), ("unreachable", "unreachable"))
        if hosts.get(k)
    ]
    return f"{', '.join(parts) or 'none finished'} (of {hosts['total']})"


def _link(public_url: str, path: str) -> str | None:
    return f"{public_url}{path}" if public_url else None


def _ops(event: str, payload: dict, public_url: str) -> Message:
    resolved = payload.get("state") == RESOLVED
    worker = _clip(payload.get("worker", "?"), 150)
    if event == WORKER_OFFLINE:
        if resolved:
            return Message(
                f"Worker {worker} is back online",
                "It is reporting in again and can take runs.",
                _GREEN,
                url=_link(public_url, "/workers"),
            )
        facts = [("Last seen", _clip(payload.get("last_seen_at") or "?", 40))]
        if payload.get("slots"):
            facts.append(("Slots", str(payload["slots"])))
        return Message(
            f"Worker {worker} is offline",
            "It stopped reporting in; its running runs are failed as worker lost, and queued "
            "runs wait for another worker.",
            _RED,
            facts=facts,
            url=_link(public_url, "/workers"),
        )
    if event == WORKER_UNISOLATED:
        return Message(
            f"Worker {worker} runs playbooks without isolation",
            "Its playbooks run as the worker's own user and can read other runs' files. Run it "
            "as root with only the SETUID, SETGID, CHOWN and KILL capabilities "
            "(docker-compose.yml).",
            _RED,
            url=_link(public_url, "/workers"),
        )
    if resolved:
        return Message(
            "Queue moving again",
            "No run is waiting too long for a worker any more.",
            _GREEN,
            url=_link(public_url, "/runs"),
        )
    waiting = payload.get("waiting", "?")
    return Message(
        f"Queue stuck: {waiting} run{'' if waiting == 1 else 's'} waiting over "
        f"{payload.get('minutes', '?')} min",
        _clip(payload.get("reason") or "", 300),
        _RED,
        facts=[
            (
                "Oldest",
                f"run #{payload.get('oldest_run_id', '?')}, "
                f"queued {_clip(payload.get('queued_at') or '?', 40)}",
            )
        ],
        url=_link(public_url, "/runs"),
    )


def _security(event: str, payload: dict, public_url: str) -> Message:
    ip = _clip(payload.get("ip") or "?", 64)
    if event == LOGIN_ATTACK:
        if payload.get("kind") == "second_factor":
            return Message(
                f"Repeated wrong 2FA codes for {_clip(payload.get('user') or '?', 150)} from {ip}",
                "Someone who knows this user's password is guessing two-factor codes; sign-ins "
                "are blocked for a while. Consider changing the password.",
                _RED,
                url=_link(public_url, "/audit"),
            )
        if payload.get("kind") == "worker_token":
            return Message(
                f"Wrong worker token from {ip}",
                "Something called the internal worker API with an invalid WORKER_TOKEN.",
                _RED,
                url=_link(public_url, "/audit"),
            )
        return Message(
            f"Login attack from {ip}",
            "Repeated failed sign-ins locked this address or user out for a few minutes.",
            _RED,
            facts=[("User name tried", _clip(payload.get("user") or "?", 150))],
            url=_link(public_url, "/audit"),
        )
    user = _clip(payload.get("user") or "?", 150)
    facts = [("By", _clip(payload.get("by") or "?", 150))]
    if payload.get("ip"):
        facts.append(("From", ip))
    return Message(
        f"Admin change: {user} {_clip(payload.get('change', '?'), 100)}",
        "Check the audit log if you didn't expect this.",
        _RED,
        facts=facts,
        url=_link(public_url, "/audit"),
    )


def build(event: str, payload: dict, public_url: str = "") -> Message:
    if event == TEST:
        return Message(
            title="AnsiDeck test notification",
            summary=f"This channel works (sent by {_clip(payload.get('sent_by', '?'), 150)}).",
            color=_BLUE,
        )
    if event in (WORKER_OFFLINE, WORKER_UNISOLATED, QUEUE_STUCK):
        return _ops(event, payload, public_url)
    if event in (LOGIN_ATTACK, ADMIN_CHANGE):
        return _security(event, payload, public_url)
    run_id = payload.get("run_id")
    target = _clip(payload.get("inventory", "?"), 150)
    if payload.get("group"):
        target += f" / {_clip(payload['group'], 150)}"
    what = f"{_clip(payload.get('playbook', '?'), 150)} on {target}"
    if event == RUN_RECOVERED:
        title, color = f"Run #{run_id} recovered: {what}", _GREEN
        summary = "The previous run of this playbook on this inventory failed; this one succeeded."
    elif event == RUN_FAILED:
        verb = "timed out" if payload.get("status") == "timed_out" else "failed"
        title, color = f"Run #{run_id} {verb}: {what}", _RED
        summary = _clip(payload.get("reason") or f"The run {verb}.", 300)
    else:
        title, color, summary = f"AnsiDeck: {event}", _BLUE, ""
    facts = [("Project", _clip(payload.get("project", "?"), 150))]
    if payload.get("triggered_by"):
        facts.append(("Triggered by", _clip(payload["triggered_by"], 150)))
    if hosts := _hosts(payload.get("hosts")):
        facts.append(("Hosts", hosts))
    items = [
        f"{_clip(t.get('host', '?'), 100)}: {_clip(t.get('task', '?'), 150)}"
        for t in payload.get("failed_tasks") or []
    ]
    url = f"{public_url}/runs/{run_id}" if public_url and run_id is not None else None
    return Message(
        title=_clip(title, 250),
        summary=summary,
        color=color,
        facts=facts,
        items_title="Failed tasks" if items else None,
        items=items,
        url=url,
    )


def _limit(lines: list[str], limit: int = _MAX_FIELD) -> str:
    text = ""
    for i, line in enumerate(lines):
        more = f"\n…and {len(lines) - i} more"
        candidate = f"{text}\n{line}" if text else line
        if len(candidate) + len(more) > limit:
            return text + more
        text = candidate
    return text


# ------------------------------------------------------------------ Discord


def _discord_escape(text: str) -> str:
    for ch in "\\*_~`|>[]()#-":
        text = text.replace(ch, f"\\{ch}")
    return text


def discord(message: Message) -> dict:
    embed: dict = {
        "title": message.title,
        "description": _discord_escape(message.summary),
        "color": message.color,
        "fields": [
            {"name": name, "value": _discord_escape(value), "inline": True}
            for name, value in message.facts
        ],
    }
    if message.items:
        embed["fields"].append(
            {
                "name": message.items_title,
                "value": _limit([_discord_escape(i) for i in message.items]),
                "inline": False,
            }
        )
    if message.url:
        embed["url"] = message.url
    # No pings: a playbook named "@everyone" must stay text.
    return {"username": "AnsiDeck", "embeds": [embed], "allowed_mentions": {"parse": []}}


# ------------------------------------------------------------------ Slack


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack(message: Message) -> dict:
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": _clip(message.title, 150)}},
    ]
    if message.summary:
        blocks.append({"type": "section", "text": {"type": "plain_text", "text": message.summary}})
    if message.facts:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{name}*\n{_slack_escape(value)}"}
                    for name, value in message.facts
                ],
            }
        )
    if message.items:
        text = _limit([_slack_escape(i) for i in message.items], 2900)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{message.items_title}*\n{text}"},
            }
        )
    if message.url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in AnsiDeck"},
                        "url": message.url,
                    }
                ],
            }
        )
    return {"text": _slack_escape(message.title), "blocks": blocks}


# ------------------------------------------------------------------ Microsoft Teams


def teams(message: Message) -> dict:
    """An Adaptive Card for a Teams Workflows webhook ("When a Teams webhook request is
    received"); the old Office 365 connectors are retired. TextBlocks get plain text only."""
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": message.title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
    ]
    if message.summary:
        body.append({"type": "TextBlock", "text": message.summary, "wrap": True})
    if message.facts:
        body.append(
            {"type": "FactSet", "facts": [{"title": n, "value": v} for n, v in message.facts]}
        )
    if message.items:
        body.append(
            {"type": "TextBlock", "text": message.items_title, "weight": "Bolder", "wrap": True}
        )
        body.append({"type": "TextBlock", "text": _limit(message.items, 3000), "wrap": True})
    card: dict = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if message.url:
        card["actions"] = [
            {"type": "Action.OpenUrl", "title": "Open in AnsiDeck", "url": message.url}
        ]
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }


# ------------------------------------------------------------------ generic webhook


def webhook(event: str, payload: dict, message: Message) -> dict:
    return {
        "event": event,
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "title": message.title,
        "summary": message.summary,
        "url": message.url,
        "data": payload,
    }


def signature_headers(body: bytes, secret: str | None, now: int | None = None) -> dict[str, str]:
    """X-AnsiDeck-Timestamp, and with a secret X-AnsiDeck-Signature: sha256=HMAC(secret,
    "<timestamp>.<body>") so a receiver can check origin and freshness."""
    timestamp = str(int(time.time()) if now is None else now)
    headers = {"X-AnsiDeck-Timestamp": timestamp}
    if secret:
        digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
        headers["X-AnsiDeck-Signature"] = f"sha256={digest.hexdigest()}"
    return headers


# ------------------------------------------------------------------ push services


def plain(message: Message, limit: int) -> str:
    """The message as plain text within `limit` characters (push notification bodies)."""
    lines = [message.summary] if message.summary else []
    lines += [f"{name}: {value}" for name, value in message.facts]
    if message.items:
        lines += [f"{message.items_title}:", *message.items]
    text = "\n".join(lines)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def pushbullet(message: Message) -> dict:
    push = {"type": "note", "title": message.title, "body": plain(message, 4000)}
    if message.url:
        push |= {"type": "link", "url": message.url}
    return push


def pushover(message: Message, app_token: str, user_key: str) -> dict:
    push = {
        "token": app_token,
        "user": user_key,
        "title": _clip(message.title, 250),
        "message": plain(message, 1024) or message.title,
    }
    if message.url:
        push |= {"url": message.url, "url_title": "Open in AnsiDeck"}
    return push


# ------------------------------------------------------------------ email


def email(message: Message) -> tuple[str, str]:
    """(subject, plain-text body)."""
    lines = [message.title, ""]
    if message.summary:
        lines += [message.summary, ""]
    lines += [f"{name}: {value}" for name, value in message.facts]
    if message.items:
        lines += ["", f"{message.items_title}:", *[f"  - {i}" for i in message.items]]
    if message.url:
        lines += ["", message.url]
    lines += ["", "-- ", "Sent by AnsiDeck. Change notifications on its Notifications page."]
    subject = message.title.replace("\r", " ").replace("\n", " ")
    return f"[AnsiDeck] {subject}", "\n".join(lines) + "\n"


def to_json(document: dict) -> bytes:
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
