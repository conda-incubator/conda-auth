from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel
from keyring.errors import PasswordDeleteError

from conda_auth.constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.token import (
    TOKEN_NAME,
    TOKEN_PARAM_NAME,
    USERNAME,
    TokenAuthHandler,
    TokenAuthManager,
    is_anaconda_dot_org,
    manager,
)


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    context = manager._context
    yield
    manager._context = context
    manager.cache_clear()


@pytest.mark.parametrize(
    "channel_name,expected",
    (
        ("conda-forge", True),
        ("http://localhost", False),
        ("https://notanaconda.org/channel", False),
        ("https://anaconda.org.evil.example/channel", False),
        ("<unknown>", False),
    ),
)
def test_is_anaconda_dot_org(channel_name, expected):
    """
    Tests the ``is_anaconda_dot_org`` function
    """
    assert is_anaconda_dot_org(channel_name) == expected


@pytest.mark.parametrize(
    "settings",
    ({}, {TOKEN_PARAM_NAME: 1}),
    ids=("missing", "non-string"),
)
def test_token_auth_manager_rejects_missing_or_invalid_token(keyring, settings):
    """
    Test to make sure missing and invalid tokens are rejected.
    """
    channel = Channel("tester")

    # setup mocks
    keyring(None)

    # run code under test
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

    # setup mocks
    keyring(None)

    # run code under test
    manager.store(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (USERNAME, token)}


def test_basic_auth_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mock, _ = keyring(secret)

    # run code under test
    manager.remove_secret(channel, settings)

    # make assertions
    keyring_mock.delete_password.assert_called_once()


def test_basic_auth_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mock, _ = keyring(secret)
    message = "Secret not found."
    keyring_mock.delete_password.side_effect = PasswordDeleteError(message)

    # make assertions
    with pytest.raises(CondaAuthError, match=f"Unable to remove secret: {message}"):
        manager.remove_secret(channel, settings)


def test_token_auth_handler_with_anaconda_dot_org_token(mocker, keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``TokenAuthHandler``
    using the anaconda.org formatted token
    """
    channel_name = "channel"
    token = "token"
    channel = Channel(channel_name)

    # setup mocks
    context = mocker.MagicMock()
    context.channel_settings = [{"channel": channel.canonical_name, "auth": TOKEN_NAME}]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    auth_handler = TokenAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": f"token {token}"}
    keyring_mock.get_password.assert_called_once()
    keyring_mock.set_password.assert_not_called()


def test_token_auth_handler_with_bearer_token(mocker, keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``TokenAuthHandler``
    using a bearer token.
    """
    channel_name = "http://localhost"
    token = "token"
    channel = Channel(channel_name)

    # setup mocks
    context = mocker.MagicMock()
    context.channel_settings = [{"channel": channel.canonical_name, "auth": TOKEN_NAME}]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    auth_handler = TokenAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": f"Bearer {token}"}
    keyring_mock.get_password.assert_called_once()
    keyring_mock.set_password.assert_not_called()


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

    keyring_mock.get_password.assert_called_once()
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

    # Transport validation happens before reading the configured keyring token.
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

    # The opt-in is read from channel_settings at request-auth time.
    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "auth_allow_plaintext_http": "True"}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(token)

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"Authorization": f"Bearer {token}"}
    keyring_mock.get_password.assert_called_once_with(
        "conda-auth::token::http://example.com/private-channel", USERNAME
    )
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

    # setup mocks
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
