import json

from conda.exceptions import CondaError

from conda_auth.cli import SUCCESSFUL_LOGOUT_MESSAGE, auth
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME, manager


def test_logout_of_active_session(mocker, runner, keyring, condarc):
    """
    Logs out of currently active session; this essentially just removes the "keyring" entry
    """
    channel_name = "tester"
    secret = "password"
    username = "user"

    # setup mocks
    mock_context = mocker.patch("conda_auth.cli.context")
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
            # username is a credential key → removed; auth type is a config
            # key → preserved so the next login can auto-detect the auth type.
            {"channel": channel_name, "ssl_verify": False, "auth": HTTP_BASIC_AUTH_NAME},
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
    mock_context = mocker.patch("conda_auth.cli.context")
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

    mock_context = mocker.patch("conda_auth.cli.context")
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


def test_logout_matches_channel_with_trailing_slash_in_external_condarc(
    mocker, runner, keyring, condarc
):
    """
    Regression test: when auth config is supplied by a package-installed
    condarc.d file whose ``channel`` value has a trailing slash (e.g.
    ``https://repo.example.com:8443/``), ``conda auth logout
    https://repo.example.com:8443`` must still find the settings entry and
    succeed.

    Before the fix, logout used strict equality
    ``settings.get("channel") == channel.canonical_name`` which failed when
    the stored channel value had a trailing slash that the canonical form does
    not.
    """
    from conda_auth.credentials import CredentialRecord

    channel_canonical = "https://repo.example.com:8443"
    channel_with_slash = "https://repo.example.com:8443/"

    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {
            "channel": channel_with_slash,   # trailing slash, as in the recipe file
            "auth": "oauth2",
            "oauth_client_id": "WzUtPJoAaz3HcVPp9IDDlRyX",
            "oauth_flow": "device-code",
        }
    ]

    condarc.content = {}

    stored_record = CredentialRecord(
        target=channel_canonical,
        auth_type="oauth2",
        username="oauth2",
        access_token="tok",
        token_endpoint=f"{channel_canonical}/token",
        client_id="WzUtPJoAaz3HcVPp9IDDlRyX",
    )
    keyring_mock, _ = keyring(None)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=stored_record)

    result = runner.invoke(auth, ["logout", channel_canonical])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output


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


# ---------------------------------------------------------------------------
# Logout when config lives in a package-installed condarc, not user condarc
# ---------------------------------------------------------------------------


def test_logout_succeeds_when_config_is_in_external_condarc(mocker, runner, keyring, condarc):
    """
    Regression test: when auth config was supplied by a package-installed
    condarc.d file (so login correctly skipped writing to ~/.condarc), logout
    must still succeed by removing the keyring credential.

    Before the fix, logout raised:
      "Unable to remove authentication settings from the user condarc."
    because remove_channel_settings found nothing in ~/.condarc and returned
    False, and logout treated that as an unrecoverable error regardless of
    whether a keyring credential existed.
    """
    from conda_auth.credentials import CredentialRecord

    channel_name = "https://repo.example.com"
    oauth_client_id = "WzUtPJoAaz3HcVPp9IDDlRyX"

    # Auth config comes from an external source (e.g. condarc.d package).
    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {
            "channel": channel_name,
            "auth": "oauth2",
            "oauth_client_id": oauth_client_id,
            "oauth_flow": "device-code",
        }
    ]

    # User condarc has no entry for this channel (login skipped writing it).
    condarc.content = {}

    # Keyring does have a credential from the earlier login.
    stored_record = CredentialRecord(
        target=channel_name,
        auth_type="oauth2",
        username="oauth2",
        access_token="tok",
        token_endpoint=f"{channel_name}/token",
        client_id=oauth_client_id,
    )
    keyring_mock, _ = keyring(None)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=stored_record)

    result = runner.invoke(auth, ["logout", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    # User condarc should remain effectively untouched (an empty channel_settings
    # list written back by remove_channel_settings is equivalent to no entry).
    assert condarc.content.get("channel_settings", []) == []


def test_logout_refuses_when_no_user_condarc_entry_and_no_keyring_credential(
    mocker, runner, keyring, condarc
):
    """
    When there is no auth entry in the user condarc AND no credential in the
    keyring, logout should still raise an error — there is no active session
    to log out of via the user condarc path.
    """
    channel_name = "https://repo.example.com"

    mock_context = mocker.patch("conda_auth.cli.context")
    mock_context.channel_settings = [
        {"channel": channel_name, "auth": "oauth2"}
    ]

    # User condarc has no entry and keyring has no credential.
    condarc.content = {}
    keyring(None)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)

    result = runner.invoke(auth, ["logout", channel_name])
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "configuration source where they are defined" in exception.message
