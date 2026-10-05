"""Where the API process may connect to on a user's behalf (notification webhooks, git
remotes). Admins choose those destinations, so a name could point at the internal API,
Postgres's network, the host or the LAN (SSRF). A destination is resolved, refused if any
address it resolves to isn't public unless the deployment allowlisted it, and callers then
connect to exactly the address that was checked (no second lookup to rebind).
"""

import ipaddress
import socket

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class DestinationError(ValueError):
    """The destination is refused, or its host doesn't resolve right now (`retryable`: DNS
    can come back)."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def public(address: Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def allowlisted(host: str, address: Address, allowlist: list[str]) -> bool:
    for raw in allowlist:
        entry = raw.strip().lower()
        if not entry:
            continue
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if host == entry:
                return True
    return False


def resolve(host: str, port: int) -> list[Address]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DestinationError(f"cannot resolve {host}", retryable=True) from exc
    return [ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos]


def vet(
    host: str, addresses: list[Address], allowlist: list[str], setting: str
) -> tuple[Address, bool]:
    """The address to connect to, and whether the destination is private (allowlisted).
    Every address the name resolves to must pass: one private answer is enough to refuse,
    since DNS can hand out either."""
    if not addresses:
        raise DestinationError(f"cannot resolve {host}", retryable=True)
    private = [a for a in addresses if not public(a)]
    if private and not all(allowlisted(host, a, allowlist) for a in private):
        raise DestinationError(
            f"{host} resolves to a non-public address ({private[0]}); allow it with {setting}"
        )
    return addresses[0], bool(private)


def literal(host: str) -> list[Address] | None:
    """The host as an address if it is an IP literal (no lookup), else None."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        return None
