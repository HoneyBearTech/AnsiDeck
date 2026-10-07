"""Request hardening: Origin check for CSRF, login throttling, client IP. Process hardening
lives in app.process_hardening (the worker uses it too)."""

import ipaddress
import json
import logging
import socket
import threading
import time
from urllib.parse import urlsplit

from fastapi import Request

from app.config import get_settings

logger = logging.getLogger(__name__)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class TrustedProxies:
    """TRUSTED_PROXY_HOSTS as networks, its names looked up again after TTL seconds."""

    TTL = 30.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached: tuple[str, float, tuple[Network, ...]] = ("", 0.0, ())

    def networks(self) -> tuple[Network, ...]:
        setting = get_settings().trusted_proxy_hosts
        with self._lock:
            cached_setting, expires, networks = self._cached
            if cached_setting == setting and time.monotonic() < expires:
                return networks
        networks = tuple(_networks(setting))
        with self._lock:
            self._cached = (setting, time.monotonic() + self.TTL, networks)
        return networks

    def trusts(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return addr.is_loopback or any(addr in network for network in self.networks())

    def clear(self) -> None:
        with self._lock:
            self._cached = ("", 0.0, ())


def _networks(setting: str) -> list[Network]:
    found: list[Network] = []
    for entry in (e.strip() for e in setting.split(",")):
        if not entry:
            continue
        try:
            found.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(entry, None, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            logger.debug("trusted proxy %s does not resolve", entry)
            continue
        found += [ipaddress.ip_network(info[4][0]) for info in infos]
    return found


trusted_proxies = TrustedProxies()


def client_ip(request: Request) -> str:
    """The peer address, or X-Real-IP when (and only when) the peer is a trusted proxy
    (TRUSTED_PROXY_HOSTS: our own nginx) or loopback. Anyone else, a worker's playbook
    included, could otherwise pick an address per request and dodge the throttles."""
    peer = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if trusted_proxies.trusts(addr):
        forwarded = request.headers.get("x-real-ip", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return peer


def origin_allowed(origin: str, host: str | None, allowed_origins: list[str]) -> bool:
    if origin.rstrip("/") in {o.rstrip("/") for o in allowed_origins}:
        return True
    return bool(host) and urlsplit(origin).netloc.lower() == host.lower()


class OriginCheckMiddleware:
    """Rejects state-changing requests and WebSocket handshakes whose Origin header
    is present but neither allow-listed nor same-origin (Host). A missing Origin
    (curl, CI, API clients) is allowed — browsers always send it cross-origin."""

    def __init__(self, app, allowed_origins: list[str]) -> None:
        self.app = app
        self.allowed_origins = allowed_origins

    async def __call__(self, scope, receive, send) -> None:
        kind = scope["type"]
        checked = kind == "websocket" or (kind == "http" and scope["method"] in UNSAFE_METHODS)
        if checked:
            headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
            origin = headers.get("origin")
            if origin is not None and not origin_allowed(
                origin, headers.get("host"), self.allowed_origins
            ):
                if kind == "websocket":
                    await receive()  # consume websocket.connect, then refuse
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    body = json.dumps({"detail": "Origin not allowed"}).encode()
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 403,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


class FailureThrottle:
    """In-memory sliding-window failure counter (single-process, resets on restart)."""

    def __init__(self, max_failures: int, window_seconds: float) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[object, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: object, now: float) -> list[float]:
        recent = [t for t in self._failures.get(key, []) if now - t < self.window]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def blocked(self, key: object) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.max_failures

    def record_failure(self, key: object) -> None:
        with self._lock:
            now = time.monotonic()
            if len(self._failures) > 10_000:
                for stale in list(self._failures):
                    self._recent(stale, now)
            self._failures.setdefault(key, []).append(now)

    def reset(self, key: object) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


# Per (ip, username) so an attacker can't lock a legitimate user out from
# elsewhere, plus a per-IP ceiling against password spraying across usernames.
user_login_throttle = FailureThrottle(max_failures=5, window_seconds=300)
ip_login_throttle = FailureThrottle(max_failures=20, window_seconds=300)

# Bad API keys, per client IP. The tokens are unguessable, so this is about not letting
# a scanner hammer the DB and the audit log rather than about brute force.
api_key_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)

# Wrong second factors per user, whatever the IP: only reachable after a correct
# password, and it caps guessing the 6 digits from many addresses (~3 of 10^6 codes
# are valid at a time, so 10 per 15 min makes that take years).
totp_user_throttle = FailureThrottle(max_failures=10, window_seconds=900)

# Failed SSO callbacks, per client IP (bounds audit writes and provider round-trips).
sso_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)
