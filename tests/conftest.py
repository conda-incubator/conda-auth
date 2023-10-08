from unittest.mock import MagicMock
from typing import NamedTuple

import pytest
from click.testing import CliRunner


class KeyringMocks(NamedTuple):
    basic: MagicMock
    token: MagicMock
    base: MagicMock


@pytest.fixture
def keyring(mocker):
    """
    Used to mock keyring for the duration of our tests
    """

    def _keyring(secret):
        token = mocker.patch("conda_auth.handlers.token.keyring")
        basic = mocker.patch("conda_auth.handlers.basic_auth.keyring")
        base = mocker.patch("conda_auth.handlers.base.keyring")

        basic.get_password.return_value = secret
        token.get_password.return_value = secret

        return KeyringMocks(basic, token, base)

    return _keyring


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


@pytest.fixture
def runner():
    """
    CLI test runner used for all tests
    """
    yield CliRunner()


@pytest.fixture
def condarc(mocker):
    """
    Mocks the CondaRC object
    """
    condarc_mock = mocker.patch("conda_auth.cli.CondaRC")

    return condarc_mock
