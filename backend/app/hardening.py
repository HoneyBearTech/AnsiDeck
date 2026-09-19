"""Request hardening (Origin check for CSRF, login throttling, client IP) and process
hardening (keeping playbook runs from reading the app's memory/environment)."""

import ctypes
import ipaddress
import json
import logging
import sys
import threading
import time
from urllib.parse import urlsplit

from fastapi import Request

logger = logging.getLogger(__name__)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PR_SET_DUMPABLE = 4


def disable_process_inspection() -> bool:
    """Marks this process non-dumpable (Linux), which makes /proc/<pid>/environ, mem and
    friends unreadable to other processes of the same user. Playbook runs execute as the
    app's own user, so without this a playbook could read the app's original environment
    (encryption key, auth key) straight out of /proc even though runs are spawned with a
    clean environment. execve resets the flag, so the spawned worker/ansible are unaffected.
    Returns whether it took effect; a no-op (False) off Linux."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
    except (OSError, AttributeError):
        logger.warning(
            "Could not mark the process non-dumpable; playbook runs may be able to read "
            "the app's environment via /proc",
            exc_info=True,
        )
        return False
    return True


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

# Bad API keys, per client IP. The tokens are unguessable, so this is about not letting
# a scanner hammer the DB and the audit log rather than about brute force.
api_key_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)

# Failed SSO callbacks, per client IP (bounds audit writes and provider round-trips).
sso_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)
