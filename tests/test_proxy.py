from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from frozendict import frozendict

from conda_auth.constants import PROXY_AUTH_NAME
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.proxy import (
    ProxyAuthManager,
    ProxyURL,
)


@dataclass
class FakeProxyContext:
    proxy_servers: frozendict[str, object]
    _cache_: dict[str, object] = field(default_factory=dict)


@pytest.fixture
def proxy_manager():
    return ProxyAuthManager()


@pytest.mark.parametrize(
    "proxy_key",
    (
        "http",
        "https",
        "https://repo.example.com",
    ),
)
def test_validate_proxy_key_accepts_conda_proxy_server_keys(proxy_manager, proxy_key):
    proxy_manager.validate_key(proxy_key)


@pytest.mark.parametrize(
    "proxy_key",
    (
        "",
        "://proxy.example.com",
        "https://",
    ),
)
def test_validate_proxy_key_rejects_invalid_keys(proxy_manager, proxy_key):
    with pytest.raises(CondaAuthError, match="Proxy key must be a scheme"):
        proxy_manager.validate_key(proxy_key)


@pytest.mark.parametrize(
    "proxy_url",
    (
        "http://proxy.example.com:8080",
        "https://proxy.example.com",
    ),
)
def test_validate_proxy_url_accepts_proxy_urls(proxy_url):
    ProxyURL(proxy_url).validate()


@pytest.mark.parametrize(
    "proxy_url",
    (
        "proxy.example.com:8080",
        "http://",
        "socks5://proxy.example.com:1080",
        "http://user:password@proxy.example.com:8080",
        "http://proxy.example.com:8080/path",
    ),
)
def test_validate_proxy_url_rejects_invalid_urls(proxy_url):
    with pytest.raises(CondaAuthError, match="Proxy URL"):
        ProxyURL(proxy_url).validate()


def test_create_proxy_record(proxy_manager):
    record = proxy_manager.create_record(
        "http",
        "http://proxy.example.com:8080",
        "user",
        "password",
    )

    assert record == CredentialRecord(
        target="proxy:http:http://proxy.example.com:8080",
        auth_type=PROXY_AUTH_NAME,
        username="user",
        password="password",
    )


@pytest.mark.parametrize(
    ("proxy_url", "expected"),
    (
        ("http://proxy.example.com", "http://proxy.example.com:80"),
        ("http://proxy.example.com:8080", "http://proxy.example.com:8080"),
        ("https://PROXY.example.com", "https://proxy.example.com:443"),
        ("http://[::1]:8080", "http://[::1]:8080"),
    ),
)
def test_proxy_url_origin_normalizes_proxy_url(proxy_url, expected):
    assert ProxyURL(proxy_url).origin == expected


@pytest.mark.parametrize(
    ("proxy_url", "expected"),
    (
        ("http://proxy.example.com:8080", False),
        ("http://user:password@proxy.example.com:8080", True),
        ("http://user@proxy.example.com:8080", True),
    ),
)
def test_proxy_url_has_credentials(proxy_url, expected):
    assert ProxyURL(proxy_url).has_credentials is expected


def test_add_credentials_adds_stored_credentials(proxy_manager):
    def get_credential(target):
        assert target == proxy_manager.target("http", "http://proxy.example.com:8080")
        return proxy_manager.create_record(
            "http",
            "http://proxy.example.com:8080",
            "user",
            "password",
        )

    proxy_servers = proxy_manager.add_credentials(
        {"http": "http://proxy.example.com:8080"},
        credential_getter=get_credential,
    )

    assert proxy_servers == {"http": "http://user:password@proxy.example.com:8080"}


def test_add_credentials_quotes_username_and_password(proxy_manager):
    proxy_servers = proxy_manager.add_credentials(
        {"http": "http://proxy.example.com:8080"},
        credential_getter=lambda target: proxy_manager.create_record(
            "http",
            "http://proxy.example.com:8080",
            "user/name",
            "p@ss word",
        ),
    )

    assert proxy_servers == {"http": "http://user%2Fname:p%40ss%20word@proxy.example.com:8080"}


def test_add_credentials_preserves_existing_credentials(proxy_manager):
    def get_credential(target):
        raise AssertionError("existing proxy auth should not read credential storage")

    proxy_servers = proxy_manager.add_credentials(
        {"http": "http://existing:secret@proxy.example.com:8080"},
        credential_getter=get_credential,
    )

    assert proxy_servers == {"http": "http://existing:secret@proxy.example.com:8080"}


def test_add_credentials_ignores_missing_credentials(proxy_manager):
    proxy_servers = proxy_manager.add_credentials(
        {"http": "http://proxy.example.com:8080"},
        credential_getter=lambda target: None,
    )

    assert proxy_servers == {"http": "http://proxy.example.com:8080"}


def test_add_credentials_preserves_unmanaged_entries(proxy_manager):
    proxy_servers = proxy_manager.add_credentials(
        {
            "http": "http://proxy.example.com:8080",
            "https": None,
        },
        credential_getter=lambda target: None,
    )

    assert proxy_servers == {
        "http": "http://proxy.example.com:8080",
        "https": None,
    }


def test_add_credentials_does_not_apply_credentials_to_changed_url(
    proxy_manager,
):
    def get_credential(target):
        assert target == proxy_manager.target("http", "http://new-proxy.example.com:8080")
        return None

    proxy_servers = proxy_manager.add_credentials(
        {"http": "http://new-proxy.example.com:8080"},
        credential_getter=get_credential,
    )

    assert proxy_servers == {"http": "http://new-proxy.example.com:8080"}


def test_apply_to_context_updates_conda_context(monkeypatch):
    fake_context = FakeProxyContext(
        proxy_servers=frozendict({"http": "http://proxy.example.com:8080"})
    )
    cache_cleared = []

    class FakeCondaSession:
        @staticmethod
        def cache_clear():
            cache_cleared.append(True)

    proxy_manager = ProxyAuthManager()
    monkeypatch.setattr("conda_auth.proxy.context", fake_context)
    monkeypatch.setattr("conda_auth.proxy.CondaSession", FakeCondaSession)

    proxy_manager.apply_to_context(
        credential_getter=lambda target: proxy_manager.create_record(
            "http",
            "http://proxy.example.com:8080",
            "user",
            "password",
        )
    )

    assert fake_context._cache_["proxy_servers"] == frozendict(
        {"http": "http://user:password@proxy.example.com:8080"}
    )
    assert cache_cleared == [True]


def test_redact_proxy_url_removes_embedded_credentials():
    assert ProxyURL("http://user:password@proxy.example.com:8080").redacted() == (
        "http://proxy.example.com:8080"
    )
