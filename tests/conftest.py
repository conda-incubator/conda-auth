from unittest.mock import MagicMock
from typing import NamedTuple

import pytest


class KeyringMocks(NamedTuple):
    oauth: MagicMock
    basic: MagicMock
    base: MagicMock


@pytest.fixture
def keyring(mocker):
    """
    Used to mock keyring for the duration of our tests
    """

    def _keyring(secret):
        oauth = mocker.patch("conda_auth.handlers.oauth2.keyring")
        basic = mocker.patch("conda_auth.handlers.basic_auth.keyring")
        base = mocker.patch("conda_auth.handlers.base.keyring")

        oauth.get_password.return_value = secret
        basic.get_password.return_value = secret

        return KeyringMocks(oauth, basic, base)

    return _keyring


@pytest.fixture
def session(mocker):
    """
    Used to mock the get_session function from conda to mock network requests
    """
    session_mock = mocker.patch("conda_auth.handlers.base.get_session")

    return session_mock


@pytest.fixture
def getpass(mocker):
    """
    Used to return a factor function to configure the value that getpass returns
    """

    def _getpass(secret):
        getpass_mock = mocker.patch("conda_auth.handlers.basic_auth.getpass")
        getpass_mock.return_value = secret
        return getpass_mock

    return _getpass
