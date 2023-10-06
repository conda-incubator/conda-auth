import pytest
from conda.models.channel import Channel

from conda_auth.handlers.token import is_anaconda_dot_org, manager, USERNAME, TOKEN_NAME


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    manager._cache = {}


@pytest.mark.parametrize(
    "channel_name,expected", (("conda-forge", True), ("http://localhost", False))
)
def test_is_anaconda_dot_org(channel_name, expected):
    """
    Tests the ``is_anaconda_dot_org`` function
    """
    assert is_anaconda_dot_org(channel_name) == expected


def test_token_auth_manager_no_token(mocker, session, keyring):
    """
    Test to make sure when there is no token set, we are able to set a new token via the ``input``
    function.
    """
    token = "token"
    settings = {
        "auth": TOKEN_NAME,
    }
    channel = Channel("tester")

    # setup mocks
    input_mock = mocker.patch("conda_auth.handlers.token.input")
    input_mock.return_value = token
    keyring(None)

    # run code under test
    manager.authenticate(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (USERNAME, token)}


def test_token_auth_manager_with_token(session, keyring):
    """
    Test to make sure when there is a token set, we are able to set a new token via the ``input``
    function.
    """
    token = "token"
    settings = {"auth": TOKEN_NAME, "token": token}
    channel = Channel("tester")

    # setup mocks
    keyring(None)

    # run code under test
    manager.authenticate(channel, settings)

    # make assertions
    assert manager._cache == {channel.canonical_name: (USERNAME, token)}
