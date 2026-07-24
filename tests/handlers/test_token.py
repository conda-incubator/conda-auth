from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel

from conda_auth.constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.token import (
    TOKEN_NAME,
    TOKEN_PARAM_NAME,
    USERNAME,
    TokenAuthHandler,
    TokenAuthManager,
    manager,
)
from conda_auth.storage.keyring import KeyringStorage


def store_custom_token_credential(
    channel: str,
    token: str,
    *,
    token_header: str,
    token_template: str,
) -> None:
    KeyringStorage().set_credential(
        CredentialRecord(
            target=channel,
            auth_type=TOKEN_NAME,
            username=USERNAME,
            token=token,
            token_header=token_header,
            token_template=token_template,
        )
    )


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    context = manager._context
    yield
    manager._context = context
    manager.cache_clear()


@pytest.mark.parametrize(
    "settings",
    ({}, {TOKEN_PARAM_NAME: 1}),
    ids=("missing", "non-string"),
)
def test_token_auth_manager_rejects_missing_or_invalid_token(keyring, settings):
    """Missing and invalid tokens raise an auth error."""
    channel = Channel("tester")

    keyring(None)

    with pytest.raises(CondaAuthError, match="Token not found"):
        manager.store(channel, settings)


@pytest.mark.parametrize(
    ("channel_name", "settings"),
    (
        ("tester", {TOKEN_PARAM_NAME: "token"}),
        (
            "http://repo.example.com/private",
            {
                TOKEN_PARAM_NAME: "token",
                AUTH_ALLOW_PLAINTEXT_HTTP_PARAM: True,
            },
        ),
    ),
    ids=("secure", "explicit-plaintext-http"),
)
def test_token_auth_manager_with_token(keyring, channel_name, settings):
    """Valid tokens are cached for supported transports."""
    token = settings[TOKEN_PARAM_NAME]
    channel = Channel(channel_name)

    keyring(None)

    manager.store(channel, settings)

    assert manager._cache == {channel.canonical_name: (USERNAME, token)}


def test_token_legacy_operations_require_keyring(mocker):
    mock_storage = mocker.patch("conda_auth.handlers.token.storage")
    mock_storage.backend = object()
    token_manager = TokenAuthManager()
    channel = Channel("tester")

    assert token_manager.migrate_legacy_credential_record(channel, None, "tester") is None
    token_manager.delete_legacy_credential_record(channel, None, "tester")


def test_token_legacy_migration_uses_auth_target(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[("conda-auth::token::shared", USERNAME)] = "secret"

    record = TokenAuthManager().migrate_legacy_credential_record(
        Channel("tester"),
        None,
        "shared",
    )

    assert record == CredentialRecord(
        target="shared",
        auth_type=TOKEN_NAME,
        username=USERNAME,
        token="secret",
    )


def test_token_auth_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a token that exists works.
    """
    secret = "secret"
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    keyring_mock, _ = keyring(secret)

    manager.remove_secret(channel, settings)

    assert keyring_mock.delete_password_calls == [
        ("conda-auth::credential::tester", "credential"),
        ("conda-auth::token::tester", USERNAME),
    ]


def test_token_auth_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that removing a missing token is best-effort.
    """
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    keyring_mock, _ = keyring(None)

    manager.remove_secret(channel, settings)

    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


def test_token_auth_handler_with_bearer_token(mocker, keyring):
    """
    Test to make sure the default token handler uses a bearer header.
    """
    channel_name = "http://localhost"
    token = "token"
    channel = Channel(channel_name)

    context = mocker.MagicMock()
    context.channel_settings = [{"channel": channel.canonical_name, "auth": TOKEN_NAME}]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    auth_handler = TokenAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": f"Bearer {token}"}
    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::http://localhost", "credential"),
        ("conda-auth::token::http://localhost", USERNAME),
    ]
    keyring_mock.set_password.assert_not_called()


def test_token_auth_handler_sets_custom_token_header(
    monkeypatch, keyring, context_factory, request_factory
):
    """Stored token metadata controls the header name and value template."""
    channel_name = "channel"
    token = "token"
    channel = Channel(channel_name)

    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring(None)
    store_custom_token_credential(
        channel.canonical_name,
        token,
        token_header="X-Auth",
        token_template="Token {token}",
    )

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"X-Auth": "Token token"}


def test_token_auth_handler_does_not_overwrite_custom_token_header(
    monkeypatch, keyring, context_factory, request_factory
):
    """Existing custom token headers are preserved."""
    channel_name = "channel"
    channel = Channel(channel_name)

    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring(None)
    store_custom_token_credential(
        channel.canonical_name,
        "token",
        token_header="X-Auth",
        token_template="Token {token}",
    )

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory(headers={"X-Auth": "existing"}))

    assert request.headers == {"X-Auth": "existing"}


def test_token_auth_handler_cache_reuses_keyring_secret(mocker, keyring):
    """
    Test to make sure request-time auth loading only reads keyring once per channel.
    """
    channel_name = "http://localhost"
    token = "token"
    channel = Channel(channel_name)

    context = mocker.MagicMock()
    context.channel_settings = [{"channel": channel.canonical_name, "auth": TOKEN_NAME}]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    TokenAuthHandler(channel_name)
    TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::http://localhost", "credential"),
        ("conda-auth::token::http://localhost", USERNAME),
    ]
    keyring_mock.set_password.assert_not_called()


@pytest.mark.parametrize(
    ("channel_name", "message"),
    (
        ("http://example.com/private-channel", "insecure HTTP channel"),
        ("ftp://example.com/private-channel", "unsupported channel scheme"),
        ("s3://bucket/private-channel", "unsupported channel scheme"),
        ("file:///tmp/private-channel", "unsupported channel scheme"),
    ),
    ids=("remote-http", "ftp", "s3", "file"),
)
def test_token_auth_handler_rejects_unsupported_transports_before_keyring(
    monkeypatch, keyring, context_factory, channel_name, message
):
    """Unsupported transports never receive token credentials."""
    context = context_factory([{"channel": channel_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring("token")

    with pytest.raises(CondaAuthError, match=message):
        TokenAuthHandler(channel_name)

    keyring_mock.get_password.assert_not_called()
    keyring_mock.set_password.assert_not_called()


def test_token_auth_handler_allows_plaintext_http_when_configured(
    monkeypatch, keyring, context_factory, request_factory
):
    """Explicitly configured plaintext HTTP channels can receive token credentials."""
    channel_name = "http://example.com/private-channel"
    token = "token"

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "auth_allow_plaintext_http": "True"}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"Authorization": f"Bearer {token}"}
    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::http://example.com/private-channel", "credential"),
        ("conda-auth::token::http://example.com/private-channel", USERNAME),
    ]
    keyring_mock.set_password.assert_not_called()


def test_token_auth_handler_no_token_available_error():
    """
    Test to make sure that we raise an error when no token can be found in the application's
    cache
    """
    channel_name = "http://localhost"

    with pytest.raises(
        CondaError,
        match=f"Unable to find authorization token for requests with channel {channel_name}",
    ):
        TokenAuthHandler(channel_name)


def test_token_auth_manager_get_auth_class():
    """
    Simple test to make sure we get the expected type back from the ``get_auth_class``
    method
    """
    assert manager.get_auth_class() is TokenAuthHandler


def test_token_auth_manager_get_auth_type():
    """
    Simple test to make sure we get the expected value back from the ``get_auth_type``
    method
    """
    assert manager.get_auth_type() == TOKEN_NAME


def test_token_auth_manager_get_secret_loads_from_channel_settings(keyring):
    """
    Test to make sure get_secret loads credentials from matching channel settings.
    """
    channel = "channel"
    token = "token"

    context = MagicMock()
    context.channels = (channel,)
    context.channel_settings = [
        {
            "channel": channel,
            "auth": TOKEN_NAME,
        }
    ]
    keyring(token)

    token_manager = TokenAuthManager(context)

    assert token_manager.get_secret(channel) == (USERNAME, token)
    assert token_manager._cache == {channel: (USERNAME, token)}
