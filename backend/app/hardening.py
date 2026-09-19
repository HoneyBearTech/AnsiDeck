"""Request hardening: Origin check (CSRF), login throttling, client IP."""

import ipaddress
import json
import threading
import time
from urllib.parse import urlsplit

from fastapi import Request

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def client_ip(request: Request) -> str:
    """The peer address, or X-Real-IP when (and only when) the peer is a private
    or loopback address — i.e. our own reverse proxy. Otherwise a client could
    spoof the header to dodge throttling."""
    peer = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if addr.is_private or addr.is_loopback:
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
