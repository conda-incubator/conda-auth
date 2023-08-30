from unittest.mock import MagicMock

import pytest
from keyring.errors import PasswordDeleteError
from conda.models.channel import Channel

from conda_auth.handlers import BasicAuthManager
from conda_auth.exceptions import CondaAuthError
from conda_auth.constants import LOGOUT_ERROR_MESSAGE


def test_basic_auth_manager_no_previous_secret(session, keyring, getpass):
    """
    Test to make sure when there is no password set, we are able to set a new
    password via the ``getpass`` function.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-basic-auth",
        "username": "admin",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    getpass_mock = getpass(secret)
    keyring(None)
    context_mock = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context_mock, cache)
    basic_auth.authenticate(channel, settings)

    # make assertions
    assert cache == {"tester": ("admin", secret)}
    getpass_mock.assert_called_once()


def test_basic_auth_manager_no_secret_or_username(mocker, session, keyring, getpass):
    """
    Test to make sure when there is no password or username set, we are able to provide a
    password via the ``getpass`` function and a username via the ``input`` function.
    """
    username = "admin"
    secret = "secret"
    settings = {
        "auth": "conda-auth-basic-auth",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.basic_auth.input")
    input_mock.return_value = username
    getpass_mock = getpass(secret)
    keyring(None)
    context_mock = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context_mock, cache)
    basic_auth.authenticate(channel, settings)

    # make assertions
    assert cache == {"tester": (username, secret)}
    getpass_mock.assert_called_once()


def test_basic_auth_manager_with_previous_secret(session, keyring, getpass):
    """
    Test to make sure when there is a password set, we retrieve it and set the
    cache object appropriately.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-basic-auth",
        "username": "admin",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    getpass_mock = getpass(secret)
    keyring(secret)
    context_mock = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context_mock, cache)
    basic_auth.authenticate(channel, settings)

    # make assertions
    assert cache == {"tester": ("admin", secret)}
    getpass_mock.assert_not_called()


def test_basic_auth_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-basic-auth",
        "username": "username",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    context = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context, cache)
    basic_auth.remove_secrets(channel, settings)

    # make assertions
    keyring_mocks.basic.delete_password.assert_called_once()


def test_basic_auth_manager_remove_existing_secret_no_username(mocker, keyring):
    """
    Test to make sure that removing a password that exist works when no username
    is present in the settings file.
    """
    secret = "secret"
    username = "username"
    settings = {
        "auth": "conda-auth-basic-auth",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    input_mock = mocker.patch("conda_auth.handlers.basic_auth.input")
    input_mock.return_value = username
    context = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context, cache)
    basic_auth.remove_secrets(channel, settings)

    # make assertions
    input_mock.assert_called_once()
    keyring_mocks.basic.delete_password.assert_called_once()


def test_basic_auth_manager_remove_non_existing_secret(mocker, keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-basic-auth",
        "username": "username",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    message = "Secret not found."
    keyring_mocks.basic.delete_password.side_effect = PasswordDeleteError(message)
    context = MagicMock()

    # run code under test
    basic_auth = BasicAuthManager(context, cache)

    # make assertions
    with pytest.raises(CondaAuthError, match=f"{LOGOUT_ERROR_MESSAGE} {message}"):
        basic_auth.remove_secrets(channel, settings)
