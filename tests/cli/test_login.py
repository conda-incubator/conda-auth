import json

import pytest
from conda.exceptions import CondaError

from conda_auth.cli import SUCCESSFUL_LOGIN_MESSAGE, auth
from conda_auth.exceptions import CondaAuthError


def test_login_basic_auth_no_options(mocker, runner, keyring, condarc):
    """
    Runs the login command with no additional CLI options defined (e.g. --username)
    """
    username = "user"
    secret = "password"
    channel_name = "tester"

    # setup mocks
    keyring(None)
    mocker.patch("conda_auth.cli.prompt_text", return_value=username)
    mocker.patch("conda_auth.cli.prompt_secret", return_value=secret)

    # run command
    result = runner.invoke(auth, ["login", channel_name, "--basic"])

    assert result.exit_code == 0, result.output
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

    assert result.exit_code == 0, result.output
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

    assert result.exit_code == 2, result.output
    assert exc_type is SystemExit
    assert "error: Missing option 'basic' / 'token'." in result.output


def test_login_error_when_updating_condarc_does_not_store_secret(runner, keyring, condarc):
    """
    Test the case where the login runs successfully but an error is returned when trying to update
    the condarc file.
    """
    channel_name = "tester"

    # Make condarc persistence fail before the keyring write can happen.
    keyring_mock, _ = keyring(None)
    condarc.__exit__.side_effect = CondaError("Could not save file")

    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "user", "--password", "password"],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save file" == exception.message
    keyring_mock.set_password.assert_not_called()


def test_login_error_when_storing_secret_removes_condarc_settings(runner, keyring, condarc):
    """
    Test the case where the condarc update succeeds but storing credentials fails.
    """
    channel_name = "tester"

    keyring_mock, _ = keyring(None)
    # If storing the secret fails, the condarc entry must be rolled back.
    keyring_mock.set_password.side_effect = CondaAuthError("Could not save secret")

    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "user", "--password", "password"],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save secret" == exception.message
    assert condarc.content == {"channel_settings": []}


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

    assert result.exit_code == 0, result.output


def test_login_token_json(runner, keyring, condarc):
    """
    Test successful login with token and JSON output.
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--token", "token", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "message": SUCCESSFUL_LOGIN_MESSAGE,
    }


def test_login_token_no_options(mocker, runner, keyring, condarc):
    """
    Test successful login with token without the value being supplied at the command line
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)
    mocker.patch("conda_auth.cli.prompt_secret", return_value="token")

    result = runner.invoke(auth, ["login", channel_name, "--token"])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_error_when_storing_secret_and_rollback_fails(mocker, runner, keyring, condarc):
    """
    Test the case where storing credentials fails AND the subsequent attempt to roll back
    the condarc settings also fails. The rollback error should be silently swallowed and the
    original exception from save_credentials should still be raised.
    """
    channel_name = "tester"

    keyring_mock, _ = keyring(None)
    original_error = CondaAuthError("Could not save secret")
    keyring_mock.set_password.side_effect = original_error

    # The rollback config raises an error when exiting the context manager.
    rollback_config = mocker.MagicMock()
    rollback_config.__enter__.return_value = rollback_config
    rollback_config.__exit__.side_effect = CondaError("Could not roll back settings")
    rollback_config.content = {}

    # First call (update) returns the normal condarc; second call (rollback) raises on exit.
    mocker.patch(
        "conda_auth.cli.ConfigurationFile.from_user_condarc",
        side_effect=[condarc, rollback_config],
    )

    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "user", "--password", "password"],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save secret" == exception.message


@pytest.mark.parametrize(
    "option,message",
    (
        ("--username", "Option 'username' cannot be used with 'token'"),
        ("--password", "Option 'password' cannot be used with 'token'"),
    ),
)
def test_login_token_rejects_basic_auth_options(runner, keyring, condarc, option, message):
    """
    Test to make sure token login rejects options meant for basic auth.
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)

    result = runner.invoke(
        auth,
        ["login", channel_name, "--token", "token", option, "value"],
    )
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 2, result.output
    assert exc_type is SystemExit
    assert exception.code == 2
    assert f"error: {message}" in result.output
