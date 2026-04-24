"""SSRF safety checks for outbound URL access."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_ALLOWED_SCHEMES = {"http", "https"}


def is_private_url(url: str) -> bool:
    """Return True when a URL should be blocked as private/internal.

    The helper is deliberately fail-closed: parse, scheme, resolution, or
    address errors all return True (blocked).
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True

        if parsed.scheme not in _ALLOWED_SCHEMES:
            return True

        if hostname in _BLOCKED_HOSTNAMES:
            return True

        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True

        return False
    except (socket.gaierror, ValueError, OSError):
        return True

