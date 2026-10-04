"""Outgoing notification requests that can't be turned against the internal network.

Admins (project admins too) choose webhook URLs and the API container sends to them, so a
URL could point at the internal API, Postgres's network, the host or the LAN (blind SSRF).
Every request resolves the host, refuses any address that isn't public unless the
deployment allowlisted it (NOTIFY_ALLOWED_PRIVATE_HOSTS), and then connects to exactly the
address it checked (no second DNS lookup to rebind), with redirects off. Response bodies are
never read back to the caller.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.netguard import Address, DestinationError, literal, resolve, vet

__all__ = ["Destination", "DestinationError", "check", "post"]

TIMEOUT_SECONDS = 10.0
# None: real network. Tests put an httpx.MockTransport here.
default_transport: httpx.BaseTransport | None = None
_resolve = resolve  # module-level, so tests can stub DNS


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str  # as written in the URL (lowercase), for Host and TLS
    port: int
    address: Address
    path: str  # path + query


def check(url: str, allowlist: list[str]) -> Destination:
    """Where `url` would be sent, or DestinationError. Every address the name resolves to
    must pass (one private answer is enough to refuse: DNS can hand out either)."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise DestinationError("the URL must start with https:// (or http://) and name a host")
    if parts.username or parts.password:
        raise DestinationError("the URL must not contain a user name or password")
    host = parts.hostname.lower()
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise DestinationError("the URL has an invalid port") from exc
    addresses = literal(host) or _resolve(host, port)
    address, private = vet(host, addresses, allowlist, "NOTIFY_ALLOWED_PRIVATE_HOSTS")
    if scheme == "http" and not private:
        raise DestinationError("public destinations must use https://")
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    return Destination(scheme, host, port, address, path)


def post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    allowlist: list[str],
    transport: httpx.BaseTransport | None = None,
) -> httpx.Response:
    """POSTs `body` to `url` after check(), connected to the checked address."""
    dest = check(url, allowlist)
    literal = f"[{dest.address}]" if dest.address.version == 6 else str(dest.address)
    default_port = 443 if dest.scheme == "https" else 80
    host_header = dest.host if dest.port == default_port else f"{dest.host}:{dest.port}"
    with httpx.Client(
        transport=transport or default_transport,
        timeout=TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        return client.post(
            f"{dest.scheme}://{literal}:{dest.port}{dest.path}",
            content=body,
            headers={**headers, "Host": host_header, "User-Agent": "AnsiDeck"},
            extensions={"sni_hostname": dest.host},
        )
