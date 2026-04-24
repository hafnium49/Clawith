"""SSRF safety checks for outbound URL access.

This module is a first-line guard. DNS can still change between validation and
HTTP connection (TOCTOU/DNS rebinding) unless the caller also pins the
validated IPs in the transport layer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_ALLOWED_SCHEMES = {"http", "https"}


def _should_block_parsed_url(url: str) -> tuple[bool, str | None]:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return True, None

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return True, hostname

    if hostname in _BLOCKED_HOSTNAMES:
        return True, hostname

    return False, hostname


def _contains_blocked_address(infos: list[tuple]) -> bool:
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def is_private_url(url: str) -> bool:
    """Return True when a URL should be blocked as private/internal."""
    try:
        should_block, hostname = _should_block_parsed_url(url)
        if should_block or hostname is None:
            return True

        infos = socket.getaddrinfo(hostname, None)
        return _contains_blocked_address(infos)
    except (socket.gaierror, ValueError, OSError):
        return True


async def is_private_url_async(url: str) -> bool:
    """Async variant using loop-backed DNS resolution to avoid event-loop stalls."""
    try:
        should_block, hostname = _should_block_parsed_url(url)
        if should_block or hostname is None:
            return True

        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None)
        return _contains_blocked_address(infos)
    except (socket.gaierror, ValueError, OSError):
        return True
