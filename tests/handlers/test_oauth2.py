from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
from conda.models.channel import Channel

from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.oauth2 import (
    OAUTH2_NAME,
    OAuth2AuthHandler,
    OAuth2Manager,
    manager,
)
from conda_auth.oauth2_client import OAuthClient, OAuthLoginConfig, validate_oauth_endpoint_url
from conda_auth.storage import storage


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    context = manager._context
    yield
    manager._context = context
    manager.cache_clear()


@dataclass
class FakeResponse:
    body: dict[str, object]
    ok: bool = True

    def json(self):
        return self.body


def test_oauth_handler_refreshes_expired_access_token(
    monkeypatch,
    keyring,
    context_factory,
    request_factory,
):
    """Expired OAuth access tokens are refreshed before request auth is applied."""
    keyring(None)
    target = "https://repo.example.com/private"
    storage.set_credential(
        CredentialRecord(
            target=target,
            auth_type=OAUTH2_NAME,
            username="oauth2",
            access_token="old-access-token",
            refresh_token="refresh-token",
            expires_at=int(time.time()) - 1,
            token_endpoint="https://idp.example.com/token",
            revocation_endpoint="https://idp.example.com/revoke",
            client_id="client",
        )
    )
    context = context_factory([{"channel": target, "auth": OAUTH2_NAME, "auth_target": target}])
    monkeypatch.setattr(manager, "_context", context)

    def post(url, data, auth=None, headers=None, timeout=None):
        assert url == "https://idp.example.com/token"
        assert data["grant_type"] == "refresh_token"
        assert auth is None
        return FakeResponse({"access_token": "new-access-token", "expires_in": 3600})

    monkeypatch.setattr("conda_auth.oauth2_client.requests.post", post)

    request = request_factory()
    handler = OAuth2AuthHandler(target)
    handler(request)

    assert request.headers == {"Authorization": "Bearer new-access-token"}
    stored = storage.get_credential(target)
    assert stored is not None
    assert stored.access_token == "new-access-token"
    assert stored.refresh_token == "refresh-token"


def test_oauth_handler_does_not_overwrite_authorization_header(
    monkeypatch,
    keyring,
    context_factory,
    request_factory,
):
    """Existing Authorization headers are preserved."""
    target = "https://repo.example.com/private"
    keyring(None)
    storage.set_credential(
        CredentialRecord(
            target=target,
            auth_type=OAUTH2_NAME,
            username="oauth2",
            access_token="access-token",
        )
    )
    context = context_factory([{"channel": target, "auth": OAUTH2_NAME, "auth_target": target}])
    monkeypatch.setattr(manager, "_context", context)
    request = request_factory(headers={"Authorization": "Bearer existing"})

    handler = OAuth2AuthHandler(target)
    handler(request)

    assert request.headers == {"Authorization": "Bearer existing"}


@pytest.mark.parametrize(
    "url",
    (
        "https://idp.example.com",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ),
    ids=("https", "localhost", "ipv4-loopback", "ipv6-loopback"),
)
def test_oauth_endpoint_validation_allows_secure_or_loopback_urls(url):
    validate_oauth_endpoint_url(url, "issuer URL")


@pytest.mark.parametrize(
    "url",
    (
        "http://idp.example.com",
        "ftp://idp.example.com",
        "idp.example.com",
    ),
    ids=("remote-http", "ftp", "scheme-less"),
)
def test_oauth_endpoint_validation_rejects_insecure_urls(url):
    with pytest.raises(CondaAuthError, match="must use HTTPS or loopback HTTP"):
        validate_oauth_endpoint_url(url, "issuer URL")


@pytest.mark.parametrize(
    "endpoint_key",
    (
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "revocation_endpoint",
    ),
)
def test_oauth_metadata_rejects_insecure_discovered_endpoint(endpoint_key):
    metadata = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "device_authorization_endpoint": "https://idp.example.com/device",
        "revocation_endpoint": "https://idp.example.com/revoke",
    }
    metadata[endpoint_key] = f"http://idp.example.com/{endpoint_key}"

    with pytest.raises(CondaAuthError, match=endpoint_key):
        OAuthClient(
            OAuthLoginConfig("https://idp.example.com", "client"),
            metadata,
        )


def test_oauth_refresh_rejects_insecure_token_endpoint(monkeypatch):
    def post(url, data, auth=None, headers=None, timeout=None):
        raise AssertionError(f"Unexpected request to {url}")

    monkeypatch.setattr("conda_auth.oauth2_client.requests.post", post)

    with pytest.raises(CondaAuthError, match="token endpoint"):
        OAuthClient.refresh_record(
            CredentialRecord(
                target="https://repo.example.com/private",
                auth_type=OAUTH2_NAME,
                username="oauth2",
                access_token="old-access-token",
                refresh_token="refresh-token",
                expires_at=int(time.time()) - 1,
                token_endpoint="http://idp.example.com/token",
                client_id="client",
            )
        )


def test_oauth_manager_api():
    oauth_manager = OAuth2Manager()
    channel = Channel("https://repo.example.com/private")

    assert oauth_manager.get_keyring_id(channel) == (
        "conda-auth::oauth2::https://repo.example.com/private"
    )
    assert oauth_manager.get_auth_type() == OAUTH2_NAME
    assert oauth_manager.get_auth_class() is OAuth2AuthHandler
    assert oauth_manager.get_config_parameters() == (
        "oauth_issuer_url",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_flow",
        "oauth_scopes",
        "oauth_redirect_uri",
        "user_agent",
    )


@pytest.mark.parametrize(
    "record",
    (
        None,
        CredentialRecord("target", "token", access_token="access"),
        CredentialRecord("target", OAUTH2_NAME),
    ),
    ids=("missing", "wrong-auth-type", "missing-access-token"),
)
def test_oauth_manager_rejects_missing_credentials(
    monkeypatch,
    record,
):
    oauth_manager = OAuth2Manager()
    monkeypatch.setattr(
        oauth_manager,
        "get_credential_record",
        lambda channel, settings: record,
    )

    with pytest.raises(CondaAuthError, match="OAuth credential not found"):
        oauth_manager.fetch_secret(Channel("tester"), {}, use_cache=False)


def test_oauth_manager_rejects_refresh_without_access_token(monkeypatch):
    oauth_manager = OAuth2Manager()
    record = CredentialRecord("tester", OAUTH2_NAME, access_token="access")
    monkeypatch.setattr(
        oauth_manager,
        "get_credential_record",
        lambda channel, settings: record,
    )
    monkeypatch.setattr(
        "conda_auth.handlers.oauth2.refresh_oauth_record",
        lambda stored: CredentialRecord("tester", OAUTH2_NAME),
    )

    with pytest.raises(CondaAuthError, match="OAuth credential not found"):
        oauth_manager.fetch_secret(Channel("tester"), {}, use_cache=False)


def test_oauth_manager_removes_and_revokes_credential(monkeypatch):
    oauth_manager = OAuth2Manager()
    record = CredentialRecord("tester", OAUTH2_NAME, access_token="access")
    calls = []
    monkeypatch.setattr(
        oauth_manager,
        "get_credential_record",
        lambda channel, settings: record,
    )
    monkeypatch.setattr(
        "conda_auth.handlers.oauth2.revoke_oauth_record",
        lambda stored: calls.append(("revoke", stored)),
    )
    monkeypatch.setattr(
        oauth_manager,
        "delete_credential_record",
        lambda channel, settings: calls.append(("delete", channel.canonical_name, settings)),
    )

    oauth_manager.remove_secret(Channel("tester"), {"auth_target": "tester"})

    assert calls == [
        ("revoke", record),
        ("delete", "tester", {"auth_target": "tester"}),
    ]


def test_oauth_manager_removes_missing_credential(monkeypatch):
    oauth_manager = OAuth2Manager()
    calls = []
    monkeypatch.setattr(
        oauth_manager,
        "get_credential_record",
        lambda channel, settings: None,
    )
    monkeypatch.setattr(
        oauth_manager,
        "delete_credential_record",
        lambda channel, settings: calls.append((channel.canonical_name, settings)),
    )

    oauth_manager.remove_secret(Channel("tester"), {})

    assert calls == [("tester", {})]


def test_oauth_handler_requires_access_token(monkeypatch):
    monkeypatch.setattr(manager, "get_secret", lambda channel: (None, None))

    with pytest.raises(CondaAuthError, match="Unable to find OAuth credential"):
        OAuth2AuthHandler("tester")
