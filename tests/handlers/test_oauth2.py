import pytest
from keyring.errors import PasswordDeleteError
from conda.models.channel import Channel

from conda_auth.handlers.oauth2 import USERNAME, manager, OAUTH2_NAME
from conda_auth.exceptions import CondaAuthError
from conda_auth.constants import LOGOUT_ERROR_MESSAGE


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    manager._cache = {}


def test_oauth2_manager_no_previous_secret(mocker, session, keyring):
    """
    Test to make sure when there is no password set, we are able to set a new
    password via the ``getpass`` function.
    """
    secret = "secret"
    settings = {
        "auth": OAUTH2_NAME,
        "login_url": "http://localhost",
    }
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    input_mock.return_value = secret
    keyring(None)
    mocker.patch("conda_auth.handlers.oauth2.context")

    # run code under test
    manager.authenticate(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (USERNAME, secret)}


def test_oauth2_manager_no_login_url_present(mocker, session, keyring):
    """
    Test to make sure we raise the appropriate exception when the ``login_url`` setting
    is not present in our configuration.
    """
    secret = "secret"
    settings = {
        "auth": OAUTH2_NAME,
    }
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    input_mock.return_value = secret
    keyring(None)
    mocker.patch("conda_auth.handlers.oauth2.context")

    with pytest.raises(
        CondaAuthError, match='`login_url` is not set for channel "tester"'
    ):
        manager.authenticate(channel, settings)


def test_oauth2_manager_with_previous_secret(mocker, session, keyring):
    """
    Test to make sure when there is a secret set, we retrieve it and set the
    cache object appropriately.
    """
    secret = "secret"
    settings = {
        "auth": OAUTH2_NAME,
        "login_url": "http://localhost",
    }
    channel = Channel("tester")
    manager._cache = {channel.canonical_name: (USERNAME, secret)}

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.oauth2.input")
    keyring(secret)
    mocker.patch("conda_auth.handlers.oauth2.context")

    # run code under test
    manager.authenticate(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (USERNAME, secret)}
    input_mock.assert_not_called()


def test_oauth2_manager_cache_exists(session, keyring, getpass, mocker):
    """
    Test to make sure that everything works as expected when a cache entry
    already exists for a credential set.
    """
    secret = "secret"
    username = "admin"
    settings = {
        "auth": OAUTH2_NAME,
        "login_url": "http://localhost",
    }
    channel = Channel("tester")
    manager._cache = {channel.canonical_name: (username, secret)}

    # setup mocks
    getpass_mock = getpass(secret)
    keyring_mock = keyring(secret)
    mocker.patch("conda_auth.handlers.oauth2.context")

    # run code under test
    manager.authenticate(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (username, secret)}
    getpass_mock.assert_not_called()
    keyring_mock.basic.get_password.assert_not_called()


def test_oauth2_manager_remove_existing_secret(keyring, mocker):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "auth": OAUTH2_NAME,
        "login_url": "http://localhost",
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    mocker.patch("conda_auth.handlers.oauth2.context")

    # run code under test
    manager.remove_secret(channel, settings)

    # make assertions
    keyring_mocks.oauth2.delete_password.assert_called_once()


def test_oauth2_manager_remove_non_existing_secret(keyring, mocker):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "auth": OAUTH2_NAME,
        "login_url": "http://localhost",
    }
    channel = Channel("tester")

    # setup mocks
    keyring_mocks = keyring(secret)
    message = "Secret not found."
    keyring_mocks.oauth2.delete_password.side_effect = PasswordDeleteError(message)
    mocker.patch("conda_auth.handlers.oauth2.context")

    # make assertions
    with pytest.raises(CondaAuthError, match=f"{LOGOUT_ERROR_MESSAGE} {message}"):
        manager.remove_secret(channel, settings)
