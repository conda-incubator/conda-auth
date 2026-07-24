from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel
from requests.auth import HTTPBasicAuth

from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import (
    HTTP_BASIC_AUTH_NAME,
    PASSWORD_PARAM_NAME,
    USERNAME_PARAM_NAME,
    BasicAuthHandler,
    BasicAuthManager,
    manager,
)
from conda_auth.handlers.token import TOKEN_NAME


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    context = manager._context
    yield
    manager._context = context
    manager.cache_clear()


def test_basic_auth_manager_no_previous_secret(keyring):
    """
    Test to make sure when there is no password set, we are able to set a new
    password via the ``getpass`` function.
    """
    settings = {
        "username": "admin",
    }
    channel = Channel("tester")

    # setup mocks
    keyring(None)

    # run code under test
    with pytest.raises(CondaAuthError, match="Password not found"):
        manager.store(channel, settings)


def test_basic_auth_manager_no_secret_or_username(keyring):
    """
    Test to make sure when there is no password or username set, we raise the correct
    exception.
    """
    settings = {}
    channel = Channel("tester")

    # setup mocks
    keyring(None)

    # run code under test
    with pytest.raises(CondaAuthError, match="Username not found"):
        manager.store(channel, settings)


@pytest.mark.parametrize(
    ("settings", "message"),
    (
        ({USERNAME_PARAM_NAME: 1}, "Username not found"),
        (
            {USERNAME_PARAM_NAME: "admin", PASSWORD_PARAM_NAME: 1},
            "Password not found",
        ),
    ),
    ids=("username", "password"),
)
def test_basic_auth_manager_rejects_non_string_credentials(keyring, settings, message):
    keyring(None)

    with pytest.raises(CondaAuthError, match=message):
        manager.store(Channel("tester"), settings)


def test_basic_auth_manager_uses_stored_username():
    record = CredentialRecord(
        target="tester",
        auth_type=HTTP_BASIC_AUTH_NAME,
        username="admin",
        password="secret",
    )

    assert BasicAuthManager().get_username({}, record) == "admin"


@pytest.mark.parametrize(
    "settings",
    (None, {USERNAME_PARAM_NAME: "admin"}),
    ids=("missing-settings", "non-keyring-backend"),
)
def test_basic_auth_legacy_operations_require_keyring(mocker, settings):
    mock_storage = mocker.patch("conda_auth.handlers.basic_auth.storage")
    mock_storage.backend = object()
    auth_manager = BasicAuthManager()
    channel = Channel("tester")

    assert auth_manager.migrate_legacy_credential_record(channel, settings, "tester") is None
    auth_manager.delete_legacy_credential_record(channel, settings, "tester")


def test_basic_auth_legacy_migration_uses_auth_target(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[("conda-auth::http-basic::shared", "admin")] = "secret"

    record = BasicAuthManager().migrate_legacy_credential_record(
        Channel("tester"),
        {USERNAME_PARAM_NAME: "admin"},
        "shared",
    )

    assert record == CredentialRecord(
        target="shared",
        auth_type=HTTP_BASIC_AUTH_NAME,
        username="admin",
        password="secret",
    )


def test_basic_auth_manager_with_previous_secret(keyring):
    """
    Test to make sure when there is a password set, we retrieve it and set the
    cache object appropriately.
    """
    secret = "secret"
    settings = {
        "username": "admin",
    }
    channel = Channel("tester")

    # setup mocks
    keyring(secret)

    # run code under test
    manager.store(channel, settings)
    assert manager.fetch_secret(channel, settings) == ("admin", secret)

    # make assertions
    assert manager._cache == {channel.canonical_name: ("admin", secret)}


def test_basic_auth_manager_get_secret_cache_exists(keyring):
    """
    Test to make sure that everything works as expected when a cache entry
    already exists for a credential set.
    """
    secret = "secret"
    username = "admin"
    channel = Channel("tester")
    manager._cache = {channel.canonical_name: (username, secret)}

    # setup mocks
    keyring_mock, _ = keyring(secret)

    # run code under test
    assert manager.get_secret(channel.canonical_name) == (username, secret)

    # make assertions
    assert manager._cache == {channel.canonical_name: (username, secret)}
    keyring_mock.get_password.assert_not_called()


def test_basic_auth_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "username": "username",
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mock, _ = keyring(secret)

    # run code under test
    manager.remove_secret(channel, settings)

    # make assertions
    assert keyring_mock.delete_password_calls == [
        ("conda-auth::credential::tester", "credential"),
        ("conda-auth::http-basic::tester", "username"),
    ]


def test_basic_auth_manager_remove_existing_secret_no_username(keyring):
    """
    Test that structured credentials can be removed without legacy username metadata.
    """
    secret = "secret"
    settings = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mock, _ = keyring(secret)

    # run code under test
    manager.remove_secret(channel, settings)

    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


def test_basic_auth_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    settings = {
        "username": "username",
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mock, _ = keyring(None)
    keyring_mock.delete_password_side_effect = None

    # make assertions
    manager.remove_secret(channel, settings)
    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


def test_basic_auth_handler(mocker, keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``BasicAuthHandler``
    """
    channel_name = "channel"
    password = "password"
    username = "username"

    # setup mocks
    context = mocker.MagicMock()
    context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(password)

    auth_handler = BasicAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    expected_request = MagicMock()
    expected_request.headers = {}
    HTTPBasicAuth(username, password)(expected_request)

    assert request.headers == expected_request.headers
    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::channel", "credential"),
        ("conda-auth::http-basic::channel", username),
    ]
    keyring_mock.set_password.assert_not_called()


def test_basic_auth_handler_preserves_existing_authorization(
    monkeypatch,
    context_factory,
    request_factory,
):
    channel = Channel("tester")
    manager._cache = {channel.canonical_name: ("username", "password")}
    monkeypatch.setattr(manager, "_context", context_factory())
    request = request_factory(headers={"Authorization": "Bearer existing"})

    result = BasicAuthHandler(channel.canonical_name)(request)

    assert result is request
    assert request.headers == {"Authorization": "Bearer existing"}


def test_basic_auth_handler_equals_methods(mocker, keyring):
    """
    Test to make sure that we can instantiate multiple ``BasicAuthHandler`` objects and then
    compare the two objects
    """
    channel_name_one = "channel_two"
    channel_name_two = "channel_two"
    password = "password"
    username = "username"
    channel_one = Channel(channel_name_one)
    channel_two = Channel(channel_name_two)

    # setup mocks
    context = mocker.MagicMock()
    context.channel_settings = [
        {
            "channel": channel_one.canonical_name,
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": username,
        },
        {
            "channel": channel_two.canonical_name,
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": username,
        },
    ]
    mocker.patch.object(manager, "_context", context)
    keyring(password)

    auth_handler_one = BasicAuthHandler(channel_name_one)
    auth_handler_two = BasicAuthHandler(channel_name_two)

    assert (auth_handler_one == auth_handler_two) is True
    assert (auth_handler_one != auth_handler_two) is False


def test_basic_auth_handler_cache_reuses_keyring_secret(mocker, keyring):
    """
    Test to make sure request-time auth loading only reads keyring once per channel.
    """
    channel_name = "channel"
    username = "username"
    password = "password"

    context = mocker.MagicMock()
    context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    mocker.patch.object(manager, "_context", context)
    keyring_mock, _ = keyring(password)

    BasicAuthHandler(channel_name)
    BasicAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::channel", "credential"),
        ("conda-auth::http-basic::channel", username),
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
def test_basic_auth_handler_rejects_unsupported_transports_before_keyring(
    monkeypatch, keyring, context_factory, channel_name, message
):
    """Unsupported transports never receive basic auth credentials."""
    username = "username"

    # Transport validation happens before reading the configured keyring secret.
    context = context_factory(
        [{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring("password")

    with pytest.raises(CondaAuthError, match=message):
        BasicAuthHandler(channel_name)

    keyring_mock.get_password.assert_not_called()
    keyring_mock.set_password.assert_not_called()


def test_basic_auth_handler_allows_plaintext_http_when_configured(
    monkeypatch, keyring, context_factory, request_factory
):
    """Explicitly configured plaintext HTTP channels can receive basic auth."""
    channel_name = "http://example.com/private-channel"
    username = "username"
    password = "password"

    # The opt-in is read from channel_settings at request-auth time.
    context = context_factory(
        [
            {
                "channel": channel_name,
                "auth": HTTP_BASIC_AUTH_NAME,
                "username": username,
                "auth_allow_plaintext_http": "True",
            }
        ]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(password)

    auth_handler = BasicAuthHandler(channel_name)
    request = auth_handler(request_factory())

    expected_request = request_factory()
    HTTPBasicAuth(username, password)(expected_request)

    assert request.headers == expected_request.headers
    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::http://example.com/private-channel", "credential"),
        ("conda-auth::http-basic::http://example.com/private-channel", username),
    ]
    keyring_mock.set_password.assert_not_called()


def test_basic_auth_handler_partial_cache_error():
    """
    Test to make sure partial cached credentials are rejected.
    """
    channel_name = "channel"
    manager._cache = {channel_name: ("username", None)}

    with pytest.raises(
        CondaError,
        match=f"Unable to find user credentials for requests with channel {channel_name}",
    ):
        BasicAuthHandler(channel_name)


def test_basic_auth_handler_no_credentials_available_error():
    """
    Test to make sure that we raise an error when no credentials can be found in the application's
    cache
    """
    channel_name = "http://localhost"

    with pytest.raises(
        CondaError,
        match=f"Unable to find user credentials for requests with channel {channel_name}",
    ):
        BasicAuthHandler(channel_name)


def test_token_auth_manager_get_auth_class():
    """
    Simple test to make sure we get the expected type back from the ``get_auth_class``
    method
    """
    assert manager.get_auth_class() is BasicAuthHandler


def test_token_auth_manager_get_auth_type():
    """
    Simple test to make sure we get the expected value back from the ``get_auth_type``
    method
    """
    assert manager.get_auth_type() == HTTP_BASIC_AUTH_NAME


def test_basic_auth_manager_get_secret_loads_from_channel_settings(keyring):
    """
    Test to make sure get_secret loads credentials from matching channel settings.
    """
    channel = "channel"
    username = "username"
    password = "password"

    # setup mocks
    context = MagicMock()
    context.channels = (channel,)
    context.channel_settings = [
        {"channel": channel, "auth": TOKEN_NAME},
        {"channel": channel, "auth": HTTP_BASIC_AUTH_NAME, "username": username},
    ]
    keyring(password)

    auth_manager = BasicAuthManager(context)

    assert auth_manager.get_secret(channel) == (username, password)
    assert auth_manager._cache == {channel: (username, password)}


@pytest.mark.parametrize(
    ("configured_channel", "channel_name", "expected"),
    (
        ("conda-forge", "conda-forge", True),
        ("https://repo.example.com/private", "https://repo.example.com/private", True),
        ("https://repo.example.com/*", "https://repo.example.com/private", True),
        ("http://repo.example.com/*", "https://repo.example.com/private", False),
        ("*", "https://repo.example.com/private", False),
    ),
    ids=("named-exact", "url-exact", "url-pattern", "scheme-mismatch", "schemeless-glob"),
)
def test_basic_auth_manager_channel_matches_like_conda(configured_channel, channel_name, expected):
    """Channel matching follows conda's auth-handler lookup rules."""
    auth_manager = BasicAuthManager()

    assert auth_manager.channel_matches(configured_channel, Channel(channel_name)) is expected


def test_basic_auth_manager_get_channel_settings_uses_last_matching_setting():
    """Matching settings use conda's last-match-wins behavior."""
    channel_name = "https://repo.example.com/private"
    context = MagicMock()
    context.channel_settings = [
        {
            "channel": channel_name,
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": "exact",
        },
        {
            "channel": 1,
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": "invalid",
        },
        {
            "channel": "https://repo.example.com/*",
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": "wildcard",
        },
        {
            "channel": "*",
            "auth": HTTP_BASIC_AUTH_NAME,
            "username": "schemeless",
        },
    ]
    auth_manager = BasicAuthManager(context)

    assert auth_manager.get_channel_settings(Channel(channel_name)) == {
        "channel": "https://repo.example.com/*",
        "auth": HTTP_BASIC_AUTH_NAME,
        "username": "wildcard",
    }
