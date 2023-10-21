import pytest
from click.testing import CliRunner


@pytest.fixture
def keyring(mocker):
    """
    Used to mock keyring for the duration of our tests
    """

    def _keyring(secret):
        keyring_storage = mocker.patch("conda_auth.storage.keyring.keyring")
        keyring_storage.get_password.return_value = secret

        return keyring_storage

    return _keyring


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
