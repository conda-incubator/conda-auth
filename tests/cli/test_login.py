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


@pytest.mark.parametrize(
    ("args", "message"),
    (
        (["login", "tester"], "Missing option 'basic' / 'token'."),
        (["login", "tester", "--json"], "Missing option 'basic' / 'token'."),
        (
            ["login", "tester", "--token", "token", "--username", "user", "--json"],
            "Option 'username' cannot be used with 'token'",
        ),
        (
            ["login", "tester", "--token", "token", "--password", "password", "--json"],
            "Option 'password' cannot be used with 'token'",
        ),
    ),
    ids=("missing-auth", "missing-auth-json", "token-username-json", "token-password-json"),
)
def test_login_validation_errors_raise_conda_error(runner, keyring, condarc, args, message):
    """
    Runs the login command with invalid parsed options.
    """
    # Parsed semantic validation should let conda format errors, including JSON.
    keyring_mock, _ = keyring(None)

    result = runner.invoke(auth, args)
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1, result.output
    assert exc_type == CondaAuthError
    assert exception.message == message
    assert result.output == ""
    keyring_mock.set_password.assert_not_called()
    assert condarc.content == {}


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


@pytest.mark.parametrize(
    ("rollback_error", "message"),
    (
        (None, "Could not save secret"),
        (
            CondaError("Could not roll back settings"),
            "Could not save secret. Failed to roll back channel settings: "
            "Could not roll back settings",
        ),
    ),
    ids=("rollback-succeeds", "rollback-fails"),
)
def test_login_error_when_storing_secret_reports_rollback(
    runner,
    keyring,
    condarc,
    rollback_error,
    message,
):
    """Report credential storage errors and any rollback failure."""
    keyring_mock, _ = keyring(None)
    keyring_mock.set_password.side_effect = CondaAuthError("Could not save secret")
    if rollback_error is not None:
        condarc.__exit__.side_effect = [None, rollback_error]

    result = runner.invoke(
        auth,
        ["login", "tester", "--basic", "--username", "user", "--password", "password"],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type is CondaAuthError
    assert exception.message == message
    assert condarc.content == {"channel_settings": []}
    if rollback_error is not None:
        assert exception.__cause__ is keyring_mock.set_password.side_effect


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

    assert result.exit_code == 1, result.output
    assert exc_type is CondaAuthError
    assert exception.message == message
    assert result.output == ""
