import json

import pytest
from conda.exceptions import CondaError

from conda_auth.cli import SUCCESSFUL_LOGOUT_MESSAGE, auth
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME, manager
from conda_auth.handlers.oauth2 import OAUTH2_NAME
from conda_auth.handlers.token import TOKEN_NAME
from conda_auth.storage import storage


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


def test_logout_preserves_auth_settings_outside_user_condarc(
    monkeypatch,
    runner,
    keyring,
    condarc,
    context_factory,
):
    channel_name = "tester"
    username = "user"

    keyring(None)
    storage.set_credential(
        CredentialRecord(
            target=channel_name,
            auth_type=HTTP_BASIC_AUTH_NAME,
            username=username,
            password="password",
        )
    )
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory(
            [{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}]
        ),
    )
    condarc.content = {"channel_settings": [{"channel": channel_name, "ssl_verify": False}]}

    result = runner.invoke(auth, ["logout", channel_name])

    assert result.exit_code == 0, result.output
    assert storage.get_credential(channel_name) is None
    condarc.__enter__.assert_not_called()
    assert condarc.content == {
        "channel_settings": [{"channel": channel_name, "ssl_verify": False}]
    }


def test_logout_reports_missing_external_credential(
    monkeypatch,
    runner,
    keyring,
    condarc,
    context_factory,
):
    channel_name = "tester"
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory([{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME}]),
    )
    condarc.content = {"channel_settings": [{"channel": channel_name, "ssl_verify": False}]}

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1, result.output
    assert exc_type is CondaAuthError
    assert "No stored credential" in exception.message
    condarc.__enter__.assert_not_called()
    assert condarc.content == {
        "channel_settings": [{"channel": channel_name, "ssl_verify": False}]
    }


@pytest.mark.parametrize(
    "record",
    (
        CredentialRecord(
            target="tester",
            auth_type=HTTP_BASIC_AUTH_NAME,
            username="user",
            password="password",
        ),
        CredentialRecord(target="tester", auth_type=TOKEN_NAME, token="token"),
        CredentialRecord(target="tester", auth_type=OAUTH2_NAME, access_token="token"),
    ),
    ids=("basic", "token", "oauth2"),
)
def test_logout_removes_orphaned_credential(mocker, runner, keyring, condarc, record):
    mock_context = mocker.patch("conda_auth.cli.channel.context")
    keyring(None)
    mock_context.channel_settings = []
    storage.set_credential(record)

    result = runner.invoke(auth, ["logout", record.target])

    assert result.exit_code == 0, result.output
    assert storage.get_credential(record.target) is None
    condarc.__enter__.assert_not_called()


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
