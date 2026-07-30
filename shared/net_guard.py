"""Shared SSRF guards for outbound HTTP built from user or operator input.

Two separate questions matter for Prewise, and conflating them is what makes an
SSRF bug:

``is_loopback_target``  Does every address this host resolves to stay on this
                        machine? Only then may user *content* (scanned emails,
                        messages, operator context) be sent to it.
``assert_global_target`` Does every address this host resolves to sit in public
                        address space? Anything else can reach cloud metadata
                        services, container networks and intranet hosts.

Both resolve DNS and inspect *every* returned record, because a hostname that
returns one public and one private address is still an SSRF primitive.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

__all__ = [
    "SSRFBlocked",
    "resolved_addresses",
    "is_loopback_target",
    "assert_global_target",
    "reject_private_target",
]


class SSRFBlocked(ValueError):
    """Raised when a target resolves to an address range we refuse to contact."""


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def resolved_addresses(url: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return every IP the URL's host resolves to, as ipaddress objects."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise SSRFBlocked("URL không có hostname hợp lệ.")
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    port = parts.port or _default_port(parts.scheme.lower())
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"Không phân giải được tên miền {host}.") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise SSRFBlocked(f"Không phân giải được tên miền {host}.")
    return addresses


def is_loopback_target(url: str) -> bool:
    """True only when the host cannot leave this machine.

    A DNS name that resolves to 127.0.0.1 counts, because the traffic genuinely
    stays local. A name that resolves to a mix of loopback and routable
    addresses does not.
    """
    try:
        addresses = resolved_addresses(url)
    except SSRFBlocked:
        return False
    return bool(addresses) and all(address.is_loopback for address in addresses)


def assert_global_target(url: str) -> list[str]:
    """Reject a target unless every resolved address is publicly routable.

    Returns the resolved addresses so a caller can pin the connection to them
    and defeat DNS rebinding between validation and request.
    """
    addresses = resolved_addresses(url)
    blocked = [str(address) for address in addresses if not address.is_global]
    if blocked:
        raise SSRFBlocked(
            "Địa chỉ đích nằm trong dải nội bộ/không định tuyến công cộng: "
            + ", ".join(blocked)
        )
    return [str(address) for address in addresses]


def reject_private_target(url: str) -> None:
    """Reject a target that *resolves* into private space, tolerating DNS failure.

    Use this when validating stored configuration rather than an outbound
    request. A hostname that does not resolve right now is not an SSRF
    primitive, and refusing to save it would break legitimate setups (DNS not
    yet propagated, split-horizon resolvers, an endpoint that is temporarily
    down). The strict ``assert_global_target`` check still runs at request time,
    which is the point where resolution actually decides where bytes go.

    A literal private IP is always rejected, because no resolution is involved.
    """
    try:
        addresses = resolved_addresses(url)
    except SSRFBlocked:
        return
    blocked = [str(address) for address in addresses if not address.is_global]
    if blocked:
        raise SSRFBlocked(
            "Địa chỉ đích nằm trong dải nội bộ/không định tuyến công cộng: "
            + ", ".join(blocked)
        )
