from unittest.mock import MagicMock

import pytest
from keyring.errors import PasswordDeleteError
from conda.models.channel import Channel

from conda_auth.handlers import OAuth2Manager
from conda_auth.handlers.oauth2 import USERNAME
from conda_auth.exceptions import CondaAuthError
from conda_auth.constants import LOGOUT_ERROR_MESSAGE


def test_oauth2_manager_no_previous_secret(mocker, session, keyring):
    """
    Test to make sure when there is no password set, we are able to set a new
    password via the ``getpass`` function.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-oauth2",
        "login_url": "http://localhost",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    input_mock.return_value = secret
    keyring(None)
    context_mock = MagicMock()

    # run code under test
    oauth = OAuth2Manager(context_mock, cache)
    oauth.authenticate(channel, settings)

    # make assertions
    assert oauth._cache == {channel.canonical_name: (USERNAME, secret)}


def test_oauth2_manager_no_login_url_present(mocker, session, keyring):
    """
    Test to make sure we raise the appropriate exception when the ``login_url`` setting
    is not present in our configuration.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-oauth2",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    input_mock.return_value = secret
    keyring(None)
    context_mock = MagicMock()

    # run code under test
    oauth2 = OAuth2Manager(context_mock, cache)

    with pytest.raises(
        CondaAuthError, match='`login_url` is not set for channel "tester"'
    ):
        oauth2.authenticate(channel, settings)


def test_oauth2_manager_with_previous_secret(mocker, session, keyring):
    """
    Test to make sure when there is a secret set, we retrieve it and set the
    cache object appropriately.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-oauth2",
        "login_url": "http://localhost",
    }
    channel = Channel("tester")
    cache = {channel.canonical_name: (USERNAME, secret)}

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    keyring(secret)
    context_mock = MagicMock()

    # run code under test
    oauth2 = OAuth2Manager(context_mock, cache)
    oauth2.authenticate(channel, settings)

    # make assertions
    assert oauth2._cache == {channel.canonical_name: (USERNAME, secret)}
    input_mock.assert_not_called()


def test_oauth2_manager_cache_exists(session, keyring, getpass):
    """
    Test to make sure that everything works as expected when a cache entry
    already exists for a credential set.
    """
    secret = "secret"
    username = "admin"
    settings = {
        "auth": "conda-auth-oauth2",
        "login_url": "http://localhost",
    }
    channel = Channel("tester")
    cache = {channel.canonical_name: (username, secret)}

    # setup mocks
    getpass_mock = getpass(secret)
    keyring_mock = keyring(secret)
    context_mock = MagicMock()

    # run code under test
    oauth2 = OAuth2Manager(context_mock, cache)
    oauth2.authenticate(channel, settings)

    # make assertions
    assert oauth2._cache == {channel.canonical_name: (username, secret)}
    getpass_mock.assert_not_called()
    keyring_mock.basic.get_password.assert_not_called()


def test_oauth2_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-oauth2",
        "login_url": "http://localhost",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    context = MagicMock()

    # run code under test
    oauth2 = OAuth2Manager(context, cache)
    oauth2.remove_secret(channel, settings)

    # make assertions
    keyring_mocks.oauth2.delete_password.assert_called_once()


def test_oauth2_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "auth": "conda-auth-oauth2",
        "login_url": "http://localhost",
    }
    cache = {}
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    message = "Secret not found."
    keyring_mocks.oauth2.delete_password.side_effect = PasswordDeleteError(message)
    context = MagicMock()

    # run code under test
    oauth2 = OAuth2Manager(context, cache)

    # make assertions
    with pytest.raises(CondaAuthError, match=f"{LOGOUT_ERROR_MESSAGE} {message}"):
        oauth2.remove_secret(channel, settings)
