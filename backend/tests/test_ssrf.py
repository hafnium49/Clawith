from __future__ import annotations

import socket

from app.services.security.ssrf import is_private_url


def test_is_private_url_blocks_localhost() -> None:
    assert is_private_url("http://localhost:8080/api")


def test_is_private_url_blocks_non_http_scheme() -> None:
    assert is_private_url("file:///etc/passwd")


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

