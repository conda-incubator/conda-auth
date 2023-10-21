from unittest.mock import MagicMock

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel
from keyring.errors import PasswordDeleteError
from requests.auth import _basic_auth_str

from conda_auth.handlers.basic_auth import (
    manager,
    BasicAuthHandler,
    HTTP_BASIC_AUTH_NAME,
    BasicAuthManager,
)
from conda_auth.exceptions import CondaAuthError


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
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

    # make assertions
    assert manager._cache == {channel.canonical_name: ("admin", secret)}


def test_basic_auth_manager_cache_exists(keyring):
    """
    Test to make sure that everything works as expected when a cache entry
    already exists for a credential set.
    """
    secret = "secret"
    username = "admin"
    settings = {
        "username": username,
    }
    channel = Channel("tester")
    manager._cache = {channel.canonical_name: (username, secret)}

    # setup mocks
    keyring_mock = keyring(secret)

    # run code under test
    manager.store(channel, settings)

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
    keyring_mocks = keyring(secret)

    # run code under test
    manager.remove_secret(channel, settings)

    # make assertions
    keyring_mocks.delete_password.assert_called_once()


def test_basic_auth_manager_remove_existing_secret_no_username(keyring):
    """
    Test to make sure that when removing a password that exist it fails when no username is present
    """
    secret = "secret"
    settings = {}
    channel = Channel("tester")

    # setup mocks
    keyring(secret)

    # run code under test
    with pytest.raises(CondaAuthError, match="Username not found"):
        manager.remove_secret(channel, settings)


def test_basic_auth_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "username": "username",
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    message = "Secret not found."
    keyring_mocks.delete_password.side_effect = PasswordDeleteError(message)

    # run code under test

    # make assertions
    with pytest.raises(CondaAuthError, match=f"Unable to remove secret: {message}"):
        manager.remove_secret(channel, settings)


def test_basic_auth_handler(keyring):
    """
    Test to make sure that we can successfully instantiate and call the ``BasicAuthHandler``
    """
    channel_name = "channel"
    password = "password"
    username = "username"
    channel = Channel(channel_name)

    # setup mocks
    keyring(None)

    manager.store(channel, {"username": username, "password": password})

    auth_handler = BasicAuthHandler(channel_name)

    request = MagicMock()
    request.headers = {}

    request = auth_handler(request)

    assert request.headers == {"Authorization": _basic_auth_str(username, password)}


def test_basic_auth_handler_equals_methods(keyring):
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
    keyring(None)

    manager.store(channel_one, {"username": username, "password": password})
    manager.store(channel_two, {"username": username, "password": password})

    auth_handler_one = BasicAuthHandler(channel_name_one)
    auth_handler_two = BasicAuthHandler(channel_name_two)

    assert (auth_handler_one == auth_handler_two) is True
    assert (auth_handler_one != auth_handler_two) is False


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


def test_basic_auth_manager_hook_action(keyring):
    """
    Test to make sure we can successfully call the ``hook_action`` method for the
    ``BasicAuthManager``.
    """
    channel = "channel"
    username = "username"
    password = "password"

    # setup mocks
    context = MagicMock()
    context.channels = (channel,)
    context.channel_settings = [
        {"channel": channel, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    keyring(password)

    token_manager = BasicAuthManager(context)
    token_manager.hook_action("create")

    assert token_manager._cache == {channel: (username, password)}
