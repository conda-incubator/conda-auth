from conda_auth.cli import auth, SUCCESSFUL_LOGIN_MESSAGE
from conda_auth.condarc import CondaRCError
from conda_auth.exceptions import CondaAuthError


def test_login_basic_auth_no_options(runner, keyring, condarc):
    """
    Runs the login command with no additional CLI options defined (e.g. --username)
    """
    username = "user"
    secret = "password"
    channel_name = "tester"

    # setup mocks
    keyring(None)

    # run command
    result = runner.invoke(
        auth, ["login", channel_name, "--basic"], input=f"{username}\n{secret}"
    )

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_with_options_basic_auth(runner, keyring, condarc):
    """
    Runs the login command with CLI options defined (e.g. --username)
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)

    # run command
    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "test", "--password", "test"],
    )

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_with_invalid_auth_type(runner, keyring, condarc):
    """
    Runs the login command when there is an invalid auth type configured in settings
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)

    # run command
    result = runner.invoke(auth, ["login", channel_name])
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 2
    assert exc_type == SystemExit
    assert "Error: Missing option 'basic' / 'token'." in result.stdout


def test_login_succeeds_error_returned_when_updating_condarc(runner, keyring, condarc):
    """
    Test the case where the login runs successfully but an error is returned when trying to update
    the condarc file.
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)
    condarc().save.side_effect = CondaRCError("Could not save file")

    # run command
    result = runner.invoke(
        auth, ["login", channel_name, "--basic"], input="user\npassword"
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save file" == exception.message


def test_login_token(mocker, runner, keyring, condarc):
    """
    Test successful login with token
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = []
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--token", "token"])

    assert result.exit_code == 0


def test_login_token_no_options(runner, keyring, condarc):
    """
    Test successful login with token without the value being supplied at the command line
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--token"], input="token\n")

    assert result.exit_code == 0
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output
