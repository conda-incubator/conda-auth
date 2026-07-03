import json

import pytest
from conda.exceptions import CondaError
from keyring.errors import PasswordDeleteError

from conda_auth.cli import SUCCESSFUL_LOGOUT_MESSAGE, auth
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME, manager
from conda_auth.handlers.token import TOKEN_NAME
from conda_auth.handlers.token import manager as token_manager


def test_logout_of_active_session(mocker, runner, keyring, condarc):
    """
    Logs out of currently active session; this essentially just removes the "keyring" entry
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring_mock, _ = keyring(secret)
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    manager._cache = {channel_name: (username, secret)}
    condarc.content = {
        "channel_settings": [
            {
                "channel": channel_name,
                "auth": HTTP_BASIC_AUTH_NAME,
                "username": username,
                "ssl_verify": False,
            },
            {"channel": "other", "auth": "token"},
        ]
    }

    # run command
    result = runner.invoke(auth, ["logout", channel_name])

    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert result.exit_code == 0, result.output

    assert keyring_mock.delete_password_calls == [
        ("conda-auth::credential::tester", "credential"),
        ("conda-auth::http-basic::tester", username),
    ]
    assert channel_name not in manager._cache
    assert condarc.content == {
        "channel_settings": [
            {"channel": channel_name, "ssl_verify": False},
            {"channel": "other", "auth": "token"},
        ]
    }


def test_logout_of_active_session_json(mocker, runner, keyring, condarc):
    """
    Logs out of currently active session with JSON output.
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring(secret)
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    condarc.content = {
        "channel_settings": [
            {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
        ]
    }

    # run command
    result = runner.invoke(auth, ["logout", channel_name, "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "message": SUCCESSFUL_LOGOUT_MESSAGE,
    }


def test_logout_does_not_remove_secret_when_condarc_update_fails(mocker, runner, keyring, condarc):
    """
    Fails before removing the keyring secret if the condarc update fails.
    """
    channel_name = "tester"
    username = "user"

    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring_mock, _ = keyring("password")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    condarc.content = {
        "channel_settings": [
            {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
        ]
    }
    condarc.__exit__.side_effect = CondaError("Could not save file")

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save file" == exception.message
    keyring_mock.delete_password.assert_not_called()


@pytest.mark.parametrize(
    ("args", "json_output"),
    (
        (["logout", "tester"], False),
        (["logout", "tester", "--json"], True),
    ),
    ids=("text", "json"),
)
def test_logout_succeeds_when_keyring_delete_is_denied(
    monkeypatch, runner, keyring, condarc, context_factory, args, json_output
):
    channel_name = "tester"

    keyring_mock, _ = keyring("secret-token")
    keyring_mock.delete_password_side_effect = PasswordDeleteError(
        "Can't delete password in keychain: (-25244, 'Unknown Error')"
    )
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory([{"channel": channel_name, "auth": TOKEN_NAME}]),
    )
    condarc.content = {"channel_settings": [{"channel": channel_name, "auth": TOKEN_NAME}]}
    monkeypatch.setattr(token_manager, "_cache", {channel_name: ("token", "secret-token")})

    with pytest.warns(RuntimeWarning) as warnings:
        result = runner.invoke(auth, args)

    assert result.exit_code == 0, result.output
    warning_messages = [str(warning.message) for warning in warnings]
    assert any(
        "Unable to delete credential for 'tester'" in message for message in warning_messages
    )
    assert any(
        "Unable to delete legacy credential for 'tester'" in message
        for message in warning_messages
    )
    if json_output:
        assert json.loads(result.stdout) == {
            "success": True,
            "message": SUCCESSFUL_LOGOUT_MESSAGE,
        }
    else:
        assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert keyring_mock.delete_password_calls == [
        (f"conda-auth::credential::{channel_name}", "credential"),
        (f"conda-auth::{TOKEN_NAME}::{channel_name}", "token"),
    ]
    assert channel_name not in token_manager._cache
    assert condarc.content == {"channel_settings": []}


def test_logout_refuses_when_auth_settings_are_not_in_user_condarc(
    mocker, runner, keyring, condarc
):
    channel_name = "tester"
    username = "user"

    # Active auth can come from system or environment config, not just the user condarc.
    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring_mock, _ = keyring("password")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
    ]
    condarc.content = {"channel_settings": [{"channel": channel_name, "ssl_verify": False}]}

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "configuration source where they are defined" in exception.message
    keyring_mock.delete_password.assert_not_called()
    assert condarc.content == {
        "channel_settings": [{"channel": channel_name, "ssl_verify": False}]
    }


def test_logout_of_non_existing_session(mocker, runner, keyring):
    """
    Logs out of currently active session; this essentially just removes the "keyring" entry
    """
    channel_name = "tester"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring(None)
    mock_context.channel_settings = []

    # run command
    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Unable to find information about logged in session." in exception.message
