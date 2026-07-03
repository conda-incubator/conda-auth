from __future__ import annotations

import json

import pytest
from conda.exceptions import CondaError
from keyring.errors import PasswordDeleteError

from conda_auth.cli import auth
from conda_auth.constants import SUCCESSFUL_LOGOUT_MESSAGE
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME, manager
from conda_auth.handlers.oauth2 import OAUTH2_NAME
from conda_auth.handlers.token import TOKEN_NAME
from conda_auth.handlers.token import manager as token_manager
from conda_auth.storage import storage


def test_logout_of_active_session(monkeypatch, runner, keyring, condarc, context_factory):
    """
    Logs out of currently active session. This essentially just removes the "keyring" entry
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # CLI logout reads session metadata from conda's active context.
    keyring_mock, _ = keyring(secret)
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory(
            [{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}]
        ),
    )
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
    manager._cache = {channel_name: (username, secret)}

    result = runner.invoke(auth, ["logout", channel_name])

    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert result.exit_code == 0, result.output

    # The keyring secret is removed after the condarc entry is removed.
    assert keyring_mock.delete_password_calls == [
        (f"conda-auth::credential::{channel_name}", "credential")
    ]
    assert channel_name not in manager._cache
    assert condarc.content == {
        "channel_settings": [
            {"channel": channel_name, "ssl_verify": False},
            {"channel": "other", "auth": "token"},
        ]
    }


def test_logout_of_active_session_json(monkeypatch, runner, keyring, condarc, context_factory):
    """
    Logs out of currently active session with JSON output.
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # JSON output follows the same logout path with a different renderer.
    keyring(secret)
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory(
            [{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}]
        ),
    )
    condarc.content = {
        "channel_settings": [
            {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
        ]
    }

    result = runner.invoke(auth, ["logout", channel_name, "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "message": SUCCESSFUL_LOGOUT_MESSAGE,
    }


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

    with pytest.warns(RuntimeWarning, match="Unable to delete credential for 'tester'"):
        result = runner.invoke(auth, args)

    assert result.exit_code == 0, result.output
    if json_output:
        assert json.loads(result.stdout) == {
            "success": True,
            "message": SUCCESSFUL_LOGOUT_MESSAGE,
        }
    else:
        assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert keyring_mock.delete_password_calls == [
        (f"conda-auth::credential::{channel_name}", "credential")
    ]
    assert channel_name not in token_manager._cache
    assert condarc.content == {"channel_settings": []}


def test_logout_token_file_session_does_not_touch_keyring(
    monkeypatch, runner, keyring, condarc, context_factory
):
    channel_name = "tester"

    keyring_mock, _ = keyring(None)
    settings = {
        "channel": channel_name,
        "auth": TOKEN_NAME,
        "token_file": "/run/secrets/conda_auth_secret",
    }
    monkeypatch.setattr("conda_auth.cli.channel.context", context_factory([settings]))
    condarc.content = {"channel_settings": [settings]}
    monkeypatch.setattr(token_manager, "_cache", {channel_name: ("token", "secret-token")})

    result = runner.invoke(auth, ["logout", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert keyring_mock.delete_password_calls == []
    assert channel_name not in token_manager._cache
    assert condarc.content == {"channel_settings": []}


def test_logout_does_not_remove_secret_when_condarc_update_fails(
    monkeypatch, runner, keyring, condarc, context_factory
):
    """
    Fails before removing the keyring secret if the condarc update fails.
    """
    channel_name = "tester"
    username = "user"

    # Condarc failures must stop before deleting the persisted secret.
    keyring_mock, _ = keyring("password")
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory(
            [{"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}]
        ),
    )
    condarc.content = {
        "channel_settings": [
            {"channel": channel_name, "auth": HTTP_BASIC_AUTH_NAME, "username": username}
        ]
    }
    condarc.exit_side_effect = CondaError("Could not save file")

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save file" == exception.message
    assert keyring_mock.delete_password_calls == []


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
    assert condarc.enter_calls == 0
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
    assert condarc.enter_calls == 0
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
def test_logout_removes_orphaned_credential(
    monkeypatch, runner, keyring, condarc, context_factory, record
):
    keyring(None)
    monkeypatch.setattr("conda_auth.cli.channel.context", context_factory())
    storage.set_credential(record)

    result = runner.invoke(auth, ["logout", record.target])

    assert result.exit_code == 0, result.output
    assert storage.get_credential(record.target) is None
    assert condarc.enter_calls == 0


def test_logout_of_non_existing_session(monkeypatch, runner, keyring, context_factory):
    """
    Logs out of currently active session. This essentially just removes the "keyring" entry
    """
    channel_name = "tester"

    # Empty channel settings means there is no known session to remove.
    keyring(None)
    monkeypatch.setattr("conda_auth.cli.channel.context", context_factory())

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Unable to find information about logged in session." in exception.message
