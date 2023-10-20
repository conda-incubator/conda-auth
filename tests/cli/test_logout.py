from conda_auth.cli import auth, SUCCESSFUL_LOGOUT_MESSAGE
from conda_auth.constants import PLUGIN_NAME
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME
from conda_auth.exceptions import CondaAuthError


def test_logout_of_active_session(mocker, runner, keyring):
    """
    Logs out of currently active session; this essentially just removes the "keyring" entry
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    keyring_mocks = keyring(secret)
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]

    # run command
    result = runner.invoke(auth, ["logout", channel_name])

    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert result.exit_code == 0

    # Make sure the delete password call was invoked correctly
    assert keyring_mocks.basic.delete_password.mock_calls == [
        mocker.call(f"{PLUGIN_NAME}::{HTTP_BASIC_AUTH_NAME}::{channel_name}", username)
    ]


def test_logout_of_non_existing_session(mocker, runner, keyring):
    """
    Logs out of currently active session; this essentially just removes the "keyring" entry
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    keyring(None)
    mock_context.channel_settings = []

    # run command
    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Unable to find information about logged in session." in exception.message
