from conda_auth.cli import group, SUCCESSFUL_LOGIN_MESSAGE
from conda_auth.condarc import CondaRCError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME
from conda_auth.exceptions import CondaAuthError, InvalidCredentialsError
from conda_auth.handlers.base import INVALID_CREDENTIALS_ERROR_MESSAGE


def test_login_no_options_basic_auth(mocker, runner, session, keyring, condarc):
    """
    Runs the login command with no additional CLI options defined (e.g. --username)
    """
    secret = "password"
    channel_name = "tester"

    # setup mocks
    keyring(secret)
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": "user"}
    ]
    mock_getpass = mocker.patch("conda_auth.handlers.basic_auth.getpass")
    mock_getpass.return_value = secret

    # run command
    result = runner.invoke(group, ["login", channel_name])

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_with_options_basic_auth(mocker, runner, session, keyring, condarc):
    """
    Runs the login command with CLI options defined (e.g. --username)
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    keyring(None)

    # run command
    result = runner.invoke(
        group, ["login", channel_name, "--username", "test", "--password", "test"]
    )

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_with_invalid_auth_type(mocker, runner, session, keyring, condarc):
    """
    Runs the login command when there is an invalid auth type configured in settings
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": "does-not-exist"}
    ]
    keyring(None)

    # run command
    result = runner.invoke(group, ["login", channel_name])
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1
    assert exc_type == CondaAuthError
    assert "Invalid authentication type." in exception.message


def test_login_with_non_existent_channel(mocker, runner, session, keyring, condarc):
    """
    Runs the login command for a channel that is not present in the settings file
    """
    channel_name = "tester"
    secret = "password"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    mock_getpass = mocker.patch("conda_auth.handlers.basic_auth.getpass")
    mock_getpass.return_value = secret
    keyring(None)

    # run command
    result = runner.invoke(group, ["login", channel_name], input="user")

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_succeeds_error_returned_when_updating_condarc(
    mocker, runner, session, keyring, condarc
):
    """
    Test the case where the login runs successfully but an error is returned when trying to update
    the condarc file.
    """
    channel_name = "tester"
    secret = "password"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    mock_getpass = mocker.patch("conda_auth.handlers.basic_auth.getpass")
    mock_getpass.return_value = secret
    keyring(None)
    condarc().save.side_effect = CondaRCError("Could not save file")

    # run command
    result = runner.invoke(group, ["login", channel_name], input="user")
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save file" == exception.message


def test_login_exceed_max_login_retries(mocker, runner, session, keyring, condarc):
    """
    Test the case where the login runs successfully but an error is returned when trying to update
    the condarc file.
    """
    channel_name = "tester"

    # setup mocks
    mocker.patch("conda_auth.cli.context")
    mock_manager = mocker.patch("conda_auth.cli.get_auth_manager")
    mock_type = "http-basic"
    mock_auth_manager = mocker.MagicMock()
    mock_auth_manager.authenticate.side_effect = InvalidCredentialsError(
        INVALID_CREDENTIALS_ERROR_MESSAGE
    )
    mock_manager.return_value = (mock_type, mock_auth_manager)

    # run command
    result = runner.invoke(group, ["login", channel_name], input="user")
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Max attempts reached" in exception.message
