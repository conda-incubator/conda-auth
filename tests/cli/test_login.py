from conda_auth.cli import group
from conda_auth.exceptions import CondaAuthError


def test_login_no_options_basic_auth(mocker, runner, session, keyring, condarc):
    """
    Runs the login command with no additional CLI options defined (e.g. --username)
    """
    secret = "password"
    channel_name = "tester"

    keyring(secret)
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": "http-basic", "username": "user"}
    ]
    mock_getpass = mocker.patch("conda_auth.handlers.basic_auth.getpass")
    mock_getpass.return_value = secret

    result = runner.invoke(group, ["login", channel_name])

    assert result.exit_code == 0
    assert result.output == ""


def test_login_with_options_basic_auth(mocker, runner, session, keyring, condarc):
    """
    Runs the login command with CLI options defined (e.g. --username)
    """
    channel_name = "tester"
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [{"channel": channel_name, "auth": "http-basic"}]

    keyring(None)

    result = runner.invoke(
        group, ["login", channel_name, "--username", "test", "--password", "test"]
    )

    assert result.exit_code == 0
    assert result.output == ""


def test_login_with_invalid_auth_type(mocker, runner, session, keyring, condarc):
    """
    Runs the login command when there is an invalid auth type configured in settings
    """
    channel_name = "tester"
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": "does-not-exist"}
    ]

    keyring(None)

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
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    mock_getpass = mocker.patch("conda_auth.handlers.basic_auth.getpass")
    mock_getpass.return_value = secret

    keyring(None)

    result = runner.invoke(group, ["login", channel_name], input="user")

    assert result.exit_code == 0
    assert result.output == ""
