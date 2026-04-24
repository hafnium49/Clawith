from __future__ import annotations

import asyncio
import socket

from app.services.security.ssrf import is_private_url
from app.services.security.ssrf import is_private_url_async


def test_is_private_url_blocks_localhost() -> None:
    assert is_private_url("http://localhost:8080/api")


def test_is_private_url_blocks_non_http_scheme() -> None:
    assert is_private_url("ftp://example.com/file.txt")


def test_is_private_url_allows_public_ip(monkeypatch) -> None:
    def _fake_getaddrinfo(host: str, port):
        assert host == "example.com"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert not is_private_url("https://example.com/data")


def test_is_private_url_blocks_private_ip(monkeypatch) -> None:
    def _fake_getaddrinfo(host: str, port):
        assert host == "internal.example"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.42", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert is_private_url("https://internal.example/health")


def test_is_private_url_blocks_dns_failure(monkeypatch) -> None:
    def _raise_gaierror(host: str, port):
        raise socket.gaierror("dns failed")

    monkeypatch.setattr(socket, "getaddrinfo", _raise_gaierror)
    assert is_private_url("https://example.com")


def test_is_private_url_blocks_if_any_answer_is_private(monkeypatch) -> None:
    def _fake_getaddrinfo(host: str, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert is_private_url("https://example.com")


def test_is_private_url_blocks_ipv6_loopback() -> None:
    assert is_private_url("http://[::1]/")


def test_is_private_url_blocks_malformed_url_without_hostname() -> None:
    assert is_private_url("http:///just-path")


def test_is_private_url_async_uses_async_resolver(monkeypatch) -> None:
    class _FakeLoop:
        async def getaddrinfo(self, host: str, port):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: _FakeLoop())
    assert not asyncio.run(is_private_url_async("https://example.com"))
