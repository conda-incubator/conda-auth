from conda_auth.cli import group, SUCCESSFUL_LOGIN_MESSAGE
from conda_auth.condarc import CondaRCError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME
from conda_auth.exceptions import CondaAuthError


def test_login_no_options_basic_auth(mocker, runner, keyring, condarc):
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


def test_login_with_options_basic_auth(mocker, runner, keyring, condarc):
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


def test_login_with_invalid_auth_type(mocker, runner, keyring, condarc):
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


def test_login_with_non_existent_channel(mocker, runner, keyring, condarc):
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
    mocker, runner, keyring, condarc
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


def test_login_with_token(mocker, runner, keyring, condarc):
    """
    Test successful login with token
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    keyring(None)

    result = runner.invoke(group, ["login", channel_name, "--token", "token"])

    assert result.exit_code == 0
