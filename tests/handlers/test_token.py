from unittest.mock import MagicMock

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel
from keyring.errors import PasswordDeleteError

from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.token import (
    is_anaconda_dot_org,
    manager,
    USERNAME,
    TOKEN_NAME,
    TokenAuthHandler,
    TokenAuthManager,
)


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    manager.cache_clear()


@pytest.mark.parametrize(
    "channel_name,expected", (("conda-forge", True), ("http://localhost", False))
)
def test_is_anaconda_dot_org(channel_name, expected):
    """
    Tests the ``is_anaconda_dot_org`` function
    """
    assert is_anaconda_dot_org(channel_name) == expected


def test_token_auth_manager_no_token(mocker, keyring):
    """
    Test to make sure when there is no token set, an exception is raised
    """
    token = "token"
    settings = {}
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.token.input")
    input_mock.return_value = token
    keyring(None)

    # run code under test
    with pytest.raises(CondaAuthError, match="Token not found"):
        manager.store(channel, settings)


def test_token_auth_manager_with_token(keyring):
    """
    Test to make sure when there is a token set, we are able to set a new token via the ``input``
    function.
    """
    token = "token"
    settings = {"token": token}
    channel = Channel("tester")

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


def test_token_auth_handler_with_anaconda_dot_org_token(keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``TokenAuthHandler``
    using the anaconda.org formatted token
    """
    channel_name = "channel"
    token = "token"
    channel = Channel(channel_name)

    # setup mocks
    keyring(None)

    manager.store(channel, {"token": token})

    auth_handler = TokenAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": f"token {token}"}


def test_token_auth_handler_with_bearer_token(keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``TokenAuthHandler``
    using a bearer token.
    """
    channel_name = "http://localhost"
    token = "token"
    channel = Channel(channel_name)

    # setup mocks
    keyring(None)

    manager.store(channel, {"token": token})

    auth_handler = TokenAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": f"Bearer {token}"}


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


def test_token_auth_manager_hook_action(keyring):
    """
    Test to make sure we can successfully call the ``hook_action`` method for the
    ``TokenAuthManager``.
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
    token_manager.hook_action("create")

    assert token_manager._cache == {channel: (USERNAME, token)}
