"""A channel's configuration (validated, encrypted, masked for display) and sending one
message to it."""

import json
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx

from app.config import Settings
from app.crypto import decrypt_secret, encrypt_secret
from app.models import NotificationChannel
from app.notifications import render, safe_http
from app.notifications.safe_http import DestinationError

MAX_RECIPIENTS = 20
SMTP_TIMEOUT_SECONDS = 15
_EMAIL = re.compile(r"^[^@\s,;<>\"]+@[^@\s,;<>\"]+\.[^@\s,;<>\"]+$")
_DISCORD_HOSTS = {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
PUSHBULLET_URL = "https://api.pushbullet.com/v2/pushes"
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
_TOKEN = re.compile(r"^[A-Za-z0-9._-]{8,200}$")


class ConfigError(ValueError):
    """The channel's settings are unusable (shown to the admin who entered them)."""


@dataclass
class Outcome:
    ok: bool
    status_code: int | None = None
    error: str | None = None
    retry_after: float | None = None  # seconds, from Retry-After
    permanent: bool = False  # retrying can't help


def validate(kind: str, config: dict, settings: Settings) -> dict:
    """The stored form of a channel's config, or ConfigError. Checks the URL's destination
    now too (it is checked again on every send)."""
    if kind == "email":
        if not settings.smtp_host:
            raise ConfigError("email needs an SMTP server: set SMTP_HOST (see the README)")
        recipients = [r.strip() for r in config.get("recipients") or [] if r.strip()]
        if not 1 <= len(recipients) <= MAX_RECIPIENTS:
            raise ConfigError(f"give between 1 and {MAX_RECIPIENTS} recipient addresses")
        if bad := [r for r in recipients if not _EMAIL.match(r) or len(r) > 254]:
            raise ConfigError(f"not an email address: {bad[0][:100]}")
        return {"recipients": recipients}
    if kind == "pushbullet":
        token = (config.get("token") or "").strip()
        if not _TOKEN.match(token):
            raise ConfigError("a Pushbullet access token is required (Settings > Access Tokens)")
        return {"token": token}
    if kind == "pushover":
        token, user = (config.get("token") or "").strip(), (config.get("user_key") or "").strip()
        if not (_TOKEN.match(token) and _TOKEN.match(user)):
            raise ConfigError("Pushover needs an application API token and a user (or group) key")
        return {"token": token, "user_key": user}
    url = (config.get("url") or "").strip()
    if not url or len(url) > 2000:
        raise ConfigError("a webhook URL is required")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if kind == "discord" and not (
        parts.scheme == "https"
        and host in _DISCORD_HOSTS
        and parts.path.startswith("/api/webhooks/")
    ):
        raise ConfigError("a Discord webhook URL looks like https://discord.com/api/webhooks/…")
    if kind == "slack" and not (parts.scheme == "https" and host == "hooks.slack.com"):
        raise ConfigError("a Slack webhook URL looks like https://hooks.slack.com/…")
    if kind == "teams" and parts.scheme != "https":
        raise ConfigError("a Teams Workflows webhook URL starts with https://")
    try:
        safe_http.check(url, settings.notify_allowlist)
    except DestinationError as exc:
        raise ConfigError(str(exc)) from exc
    stored: dict = {"url": url}
    if kind == "webhook" and config.get("secret"):
        stored["secret"] = str(config["secret"])[:500]
    return stored


def seal(config: dict) -> bytes:
    return encrypt_secret(json.dumps(config).encode())


def unseal(channel: NotificationChannel) -> dict:
    return json.loads(decrypt_secret(channel.config_encrypted))


def describe(kind: str, config: dict) -> dict:
    """What the API shows: never the URL's path or query (they hold the token) or the
    signing secret."""
    if kind == "email":
        return {"target": ", ".join(config["recipients"]), "recipients": config["recipients"]}
    if kind == "pushbullet":
        return {"target": "Pushbullet", "recipients": None, "has_secret": True}
    if kind == "pushover":
        return {"target": "Pushover", "recipients": None, "has_secret": True}
    parts = urlsplit(config["url"])
    tail = (parts.path + (f"?{parts.query}" if parts.query else ""))[-4:]
    return {
        "target": f"{parts.scheme}://{parts.hostname}/…{tail}",
        "recipients": None,
        "has_secret": bool(config.get("secret")),
    }


def _http_outcome(response: httpx.Response) -> Outcome:
    code = response.status_code
    if 200 <= code < 300:
        return Outcome(True, code)
    retry_after = None
    if code in (429, 503):
        try:
            retry_after = float(response.headers.get("Retry-After", ""))
        except ValueError:
            retry_after = None
    permanent = 400 <= code < 500 and code not in (408, 429)
    return Outcome(False, code, f"HTTP {code}", retry_after=retry_after, permanent=permanent)


def _send_email(settings: Settings, recipients: list[str], subject: str, text: str) -> None:
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(text)
    context = ssl.create_default_context()
    if settings.smtp_tls == "tls":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS, context=context
        )
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS)
    with server:
        if settings.smtp_tls == "starttls":
            server.starttls(context=context)
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


def send(
    channel: NotificationChannel,
    event: str,
    payload: dict,
    settings: Settings,
    transport: httpx.BaseTransport | None = None,
) -> Outcome:
    """Sends one message; never raises for delivery problems (they become the Outcome).
    Error texts never include the URL."""
    try:
        config = unseal(channel)
    except Exception:  # noqa: BLE001 - a key change makes old channels unreadable
        return Outcome(False, error="the channel's settings can't be decrypted", permanent=True)
    message = render.build(event, payload, settings.public_url)
    if channel.kind == "email":
        subject, text = render.email(message)
        try:
            _send_email(settings, config["recipients"], subject, text)
        except smtplib.SMTPResponseException as exc:
            return Outcome(
                False, exc.smtp_code, f"SMTP {exc.smtp_code}", permanent=500 <= exc.smtp_code < 600
            )
        except (OSError, smtplib.SMTPException) as exc:
            return Outcome(False, error=f"SMTP: {type(exc).__name__}")
        return Outcome(True)

    headers = {"Content-Type": "application/json"}
    url = config.get("url")
    if channel.kind == "pushbullet":
        url, body = PUSHBULLET_URL, render.to_json(render.pushbullet(message))
        headers["Access-Token"] = config["token"]
    elif channel.kind == "pushover":
        url = PUSHOVER_URL
        body = render.to_json(render.pushover(message, config["token"], config["user_key"]))
    elif channel.kind == "discord":
        body = render.to_json(render.discord(message))
    elif channel.kind == "slack":
        body = render.to_json(render.slack(message))
    elif channel.kind == "teams":
        body = render.to_json(render.teams(message))
    else:
        body = render.to_json(render.webhook(event, payload, message))
        headers |= render.signature_headers(body, config.get("secret"))
    try:
        response = safe_http.post(
            url, body, headers, settings.notify_allowlist, transport=transport
        )
    except DestinationError as exc:
        if exc.retryable:
            return Outcome(False, error=str(exc)[:300])
        return Outcome(False, error=f"refused: {exc}"[:300], permanent=True)
    except httpx.TimeoutException:
        return Outcome(False, error="timed out")
    except httpx.HTTPError as exc:
        return Outcome(False, error=f"connection failed ({type(exc).__name__})")
    return _http_outcome(response)
