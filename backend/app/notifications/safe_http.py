"""Outgoing notification requests that can't be turned against the internal network.

Admins (project admins too) choose webhook URLs and the API container sends to them, so a
URL could point at the internal API, Postgres's network, the host or the LAN (blind SSRF).
Every request resolves the host, refuses any address that isn't public unless the
deployment allowlisted it (NOTIFY_ALLOWED_PRIVATE_HOSTS), and then connects to exactly the
address it checked (no second DNS lookup to rebind), with redirects off. Response bodies are
never read back to the caller.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

TIMEOUT_SECONDS = 10.0
# None: real network. Tests put an httpx.MockTransport here.
default_transport: httpx.BaseTransport | None = None
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class DestinationError(ValueError):
    """The URL may not be sent to (bad scheme, refused address), or its host doesn't resolve
    right now (`retryable`: DNS can come back)."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str  # as written in the URL (lowercase), for Host and TLS
    port: int
    address: _Address
    path: str  # path + query


def _public(address: _Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def _allowlisted(host: str, address: _Address, allowlist: list[str]) -> bool:
    for entry in allowlist:
        entry = entry.strip().lower()
        if not entry:
            continue
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if host == entry:
                return True
    return False


def _resolve(host: str, port: int) -> list[_Address]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DestinationError(f"cannot resolve {host}", retryable=True) from exc
    return [ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos]


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
    try:
        addresses = [ipaddress.ip_address(host)]  # a literal address: no lookup
    except ValueError:
        addresses = _resolve(host, port)
    if not addresses:
        raise DestinationError(f"cannot resolve {host}", retryable=True)
    private = [a for a in addresses if not _public(a)]
    if private and not all(_allowlisted(host, a, allowlist) for a in private):
        raise DestinationError(
            f"{host} resolves to a non-public address ({private[0]}); allow it with "
            "NOTIFY_ALLOWED_PRIVATE_HOSTS"
        )
    if scheme == "http" and not private:
        raise DestinationError("public destinations must use https://")
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    return Destination(scheme, host, port, addresses[0], path)


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
