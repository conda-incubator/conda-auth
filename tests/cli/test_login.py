import json
import time

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel

from conda_auth.cli import SUCCESSFUL_LOGIN_MESSAGE, _find_channel_settings, auth
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.storage import storage


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
        (
            ["login", "tester"],
            "Missing option 'basic' / 'token' / 'oauth2'.",
        ),
        (
            ["login", "tester", "--json"],
            "Missing option 'basic' / 'token' / 'oauth2'.",
        ),
        (
            ["login", "tester", "--token", "token", "--username", "user", "--json"],
            "Option 'username' cannot be used with 'token' or 'oauth2'",
        ),
        (
            ["login", "tester", "--token", "token", "--password", "password", "--json"],
            "Option 'password' cannot be used with 'token' or 'oauth2'",
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


@pytest.mark.parametrize(
    "args",
    (
        ["login", "http://example.com/private-channel", "--basic"],
        ["login", "http://example.com/private-channel", "--token"],
    ),
    ids=("basic", "token"),
)
def test_login_rejects_plaintext_http_before_reading_secrets(
    monkeypatch, runner, keyring, condarc, args
):
    """
    Refuses to collect or store credentials for remote plaintext HTTP channels.
    """

    def fail_prompt(prompt):
        raise AssertionError(f"Prompted for {prompt!r}")

    # Transport validation happens before interactive secret prompts.
    keyring_mock, _ = keyring(None)
    monkeypatch.setattr("conda_auth.cli.prompt_text", fail_prompt)
    monkeypatch.setattr("conda_auth.cli.prompt_secret", fail_prompt)

    result = runner.invoke(auth, args)
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1, result.output
    assert exc_type == CondaAuthError
    assert "insecure HTTP channel" in exception.message
    keyring_mock.get_password.assert_not_called()
    keyring_mock.set_password.assert_not_called()
    assert condarc.content == {}


@pytest.mark.parametrize(
    ("args", "expected_settings", "expected_record"),
    (
        (
            [
                "login",
                "http://example.com/private-channel",
                "--basic",
                "--username",
                "user",
                "--password",
                "password",
                "--allow-plaintext-http",
            ],
            {
                "channel": "http://example.com/private-channel",
                "auth": "http-basic",
                "auth_target": "http://example.com/private-channel",
                "auth_allow_plaintext_http": True,
            },
            {
                "target": "http://example.com/private-channel",
                "auth_type": "http-basic",
                "username": "user",
                "password": "password",
            },
        ),
        (
            [
                "login",
                "http://example.com/private-channel",
                "--token",
                "token",
                "--allow-plaintext-http",
            ],
            {
                "channel": "http://example.com/private-channel",
                "auth": "token",
                "auth_target": "http://example.com/private-channel",
                "auth_allow_plaintext_http": True,
            },
            {
                "target": "http://example.com/private-channel",
                "auth_type": "token",
                "username": "token",
                "token": "token",
            },
        ),
    ),
    ids=("basic", "token"),
)
def test_login_allows_plaintext_http_when_explicit(
    runner, keyring, condarc, args, expected_settings, expected_record
):
    """
    Persists explicit plaintext HTTP opt-in with the channel auth settings.
    """
    keyring(None)

    result = runner.invoke(auth, args)

    assert result.exit_code == 0, result.output
    assert condarc.content == {"channel_settings": [expected_settings]}
    target = expected_settings["channel"]
    stored_record = storage.get_credential(target)
    assert stored_record is not None
    assert stored_record.to_dict() | expected_record == stored_record.to_dict()


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
    # After rollback, auth_target (credential) is stripped but auth type is
    # preserved so a subsequent login can still auto-detect the auth type.
    assert condarc.content == {
        "channel_settings": [{"channel": "tester", "auth": "http-basic"}]
    }
    if rollback_error is not None:
        assert exception.__cause__ is keyring_mock.set_password.side_effect


def test_login_error_when_storing_secret_preserves_non_auth_settings(runner, keyring, condarc):
    channel_name = "tester"

    # Rolling back auth settings must not remove other channel-scoped conda settings.
    keyring_mock, _ = keyring(None)
    keyring_mock.set_password.side_effect = CondaAuthError("Could not save secret")
    condarc.content = {"channel_settings": [{"channel": channel_name, "ssl_verify": False}]}

    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "user", "--password", "password"],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save secret" == exception.message
    # ssl_verify (non-auth key) is preserved; auth type is also kept (config
    # key, not a credential); only auth_target was stripped as a credential.
    assert condarc.content == {
        "channel_settings": [
            {"channel": channel_name, "ssl_verify": False, "auth": "http-basic"}
        ]
    }


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


def test_login_oauth_json_routes_interactive_output_to_stderr(
    monkeypatch, runner, keyring, condarc
):
    keyring(None)

    def perform_oauth_login(config):
        print("Open this URL to authenticate", file=config.output_stream)
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="access-token",
            token_endpoint="https://repo.example.com/token",
            client_id=config.client_id,
        )

    monkeypatch.setattr("conda_auth.cli.perform_oauth_login", perform_oauth_login)

    result = runner.invoke(
        auth,
        [
            "login",
            "https://repo.example.com/private",
            "--oauth2",
            "--oauth-client-id",
            "client",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "success": True,
        "message": SUCCESSFUL_LOGIN_MESSAGE,
    }
    assert result.stderr == "Open this URL to authenticate\n"


def test_login_token_no_options(monkeypatch, runner, keyring, condarc):
    """
    Test successful login with token without the value being supplied at the command line
    """
    channel_name = "tester"

    # setup mocks
    keyring(None)
    monkeypatch.setattr("conda_auth.cli.prompt_secret", lambda prompt: "token")

    result = runner.invoke(auth, ["login", channel_name, "--token"])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


@pytest.mark.parametrize(
    "option,message",
    (
        ("--username", "Option 'username' cannot be used with 'token' or 'oauth2'"),
        ("--password", "Option 'password' cannot be used with 'token' or 'oauth2'"),
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


# ---------------------------------------------------------------------------
# Already-logged-in guard
# ---------------------------------------------------------------------------


def _make_oauth_record(channel_name, expires_at=None):
    """Return a minimal OAuth CredentialRecord for testing the guard."""
    return CredentialRecord(
        target=channel_name,
        auth_type="oauth2",
        username="oauth2",
        access_token="tok",
        token_endpoint="https://example.com/token",
        client_id="client",
        expires_at=expires_at,
    )


def _make_basic_record(channel_name):
    """Return a minimal basic-auth CredentialRecord for testing the guard."""
    return CredentialRecord(
        target=channel_name,
        auth_type="http-basic",
        username="user",
        password="pass",
    )


def test_login_already_logged_in_oauth_valid_token_raises(mocker, runner, keyring, condarc):
    """
    Login should error when a valid (non-expired) OAuth token already exists.
    """
    channel_name = "https://repo.example.com/private"
    future = int(time.time()) + 3600
    record = _make_oauth_record(channel_name, expires_at=future)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=record)
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--oauth2", "--oauth-client-id", "c"])
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1
    assert exc_type is CondaAuthError
    assert "Already logged in" in exception.message
    assert "conda auth logout" in exception.message


def test_login_already_logged_in_oauth_expired_token_proceeds(mocker, runner, keyring, condarc):
    """
    Login should proceed when the stored OAuth token is already expired.
    """
    channel_name = "https://repo.example.com/private"
    past = int(time.time()) - 3600
    record = _make_oauth_record(channel_name, expires_at=past)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=record)

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="new-tok",
            token_endpoint="https://repo.example.com/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    result = runner.invoke(
        auth,
        ["login", channel_name, "--oauth2", "--oauth-client-id", "client"],
    )

    assert result.exit_code == 0, result.output


def test_login_already_logged_in_basic_record_raises(mocker, runner, keyring, condarc):
    """
    Login should error when a basic-auth credential already exists (no expiry concept).
    """
    channel_name = "tester"
    record = _make_basic_record(channel_name)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=record)
    keyring(None)

    result = runner.invoke(
        auth, ["login", channel_name, "--basic", "--username", "u", "--password", "p"]
    )
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1
    assert exc_type is CondaAuthError
    assert "Already logged in" in exception.message
    assert "conda auth logout" in exception.message


def test_login_no_existing_credential_proceeds(mocker, runner, keyring, condarc):
    """
    Login should proceed normally when no credential exists in the keyring.
    """
    channel_name = "tester"
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    keyring(None)

    result = runner.invoke(
        auth, ["login", channel_name, "--basic", "--username", "u", "--password", "p"]
    )

    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# _find_channel_settings helper
# ---------------------------------------------------------------------------


def test_find_channel_settings_returns_matching_entry(mocker):
    """Returns the first entry whose 'channel' matches canonical_name."""
    channel = Channel("https://repo.example.com/private")
    settings_entry = {"channel": channel.canonical_name, "auth": "oauth2"}
    mocker.patch("conda_auth.cli.context.channel_settings", [settings_entry])

    result = _find_channel_settings(channel)

    assert result == settings_entry


def test_find_channel_settings_returns_none_when_no_match(mocker):
    """Returns None when no entry matches the channel."""
    channel = Channel("https://repo.example.com/private")
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [{"channel": "https://other.example.com", "auth": "oauth2"}],
    )

    result = _find_channel_settings(channel)

    assert result is None


def test_find_channel_settings_returns_none_for_empty_list(mocker):
    """Returns None when channel_settings is empty."""
    channel = Channel("https://repo.example.com/private")
    mocker.patch("conda_auth.cli.context.channel_settings", [])

    result = _find_channel_settings(channel)

    assert result is None


def test_find_channel_settings_returns_first_match(mocker):
    """Returns the first matching entry when multiple entries exist for the same channel."""
    channel = Channel("https://repo.example.com/private")
    first = {"channel": channel.canonical_name, "auth": "oauth2"}
    second = {"channel": channel.canonical_name, "auth": "basic"}
    mocker.patch("conda_auth.cli.context.channel_settings", [first, second])

    result = _find_channel_settings(channel)

    assert result == first


# ---------------------------------------------------------------------------
# Auth type auto-detection from channel_settings
# ---------------------------------------------------------------------------


def test_login_infers_oauth2_from_channel_settings(mocker, runner, keyring, condarc):
    """
    When no auth type flag is given and channel_settings has auth: oauth2,
    the login command should proceed as OAuth2.
    """
    channel_name = "https://repo.example.com/private"
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [{"channel": channel_name, "auth": "oauth2", "oauth_client_id": "client"}],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="tok",
            token_endpoint="https://repo.example.com/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_infers_basic_from_channel_settings(mocker, runner, keyring, condarc):
    """
    When no auth type flag is given and channel_settings has auth: http-basic,
    the login command should proceed as basic auth.
    """
    channel_name = "tester"
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [{"channel": channel_name, "auth": "http-basic"}],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    mocker.patch("conda_auth.cli.prompt_text", return_value="user")
    mocker.patch("conda_auth.cli.prompt_secret", return_value="pass")
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_infers_token_from_channel_settings(mocker, runner, keyring, condarc):
    """
    When no auth type flag is given and channel_settings has auth: token,
    the login command should proceed as token auth and prompt.
    """
    channel_name = "tester"
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [{"channel": channel_name, "auth": "token"}],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    mocker.patch("conda_auth.cli.prompt_secret", return_value="mytoken")
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_explicit_flag_overrides_channel_settings(mocker, runner, keyring, condarc):
    """
    An explicit auth type flag on the CLI takes precedence over channel_settings.
    Passing --basic when channel_settings says oauth2 should run basic auth.
    """
    channel_name = "tester"
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [{"channel": channel_name, "auth": "oauth2"}],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    keyring(None)

    result = runner.invoke(
        auth, ["login", channel_name, "--basic", "--username", "u", "--password", "p"]
    )

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


def test_login_no_channel_settings_match_still_requires_flag(mocker, runner, keyring, condarc):
    """
    When no channel_settings entry matches and no flag is given, the error is raised.
    """
    mocker.patch("conda_auth.cli.context.channel_settings", [])
    keyring(None)

    result = runner.invoke(auth, ["login", "tester"])
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1
    assert exc_type is CondaAuthError
    assert "Missing option" in exception.message


# ---------------------------------------------------------------------------
# _find_channel_settings: URL variation matching
# ---------------------------------------------------------------------------


def test_find_channel_settings_matches_root_url_no_path(mocker):
    """
    A root URL with a non-standard port (e.g. https://repo.example.com:8443)
    must be matched even though it has no path component.
    This is a regression test for the original strict-equality implementation
    which required the stored 'channel' value to equal canonical_name exactly.
    """
    channel = Channel("https://repo.example.com:8443")
    settings_entry = {
        "channel": "https://repo.example.com:8443",
        "auth": "oauth2",
        "oauth_client_id": "test-client",
    }
    mocker.patch("conda_auth.cli.context.channel_settings", [settings_entry])

    result = _find_channel_settings(channel)

    assert result == settings_entry


def test_find_channel_settings_matches_trailing_slash(mocker):
    """
    An entry stored with a trailing slash matches the canonical URL without one.
    """
    channel = Channel("https://repo.example.com:8443")
    settings_entry = {
        "channel": "https://repo.example.com:8443/",
        "auth": "oauth2",
        "oauth_client_id": "test-client",
    }
    mocker.patch("conda_auth.cli.context.channel_settings", [settings_entry])

    result = _find_channel_settings(channel)

    assert result == settings_entry


# ---------------------------------------------------------------------------
# Login → logout → login cycle (auto-detection survives logout)
# ---------------------------------------------------------------------------


def test_login_oauth2_survives_logout_cycle(mocker, runner, keyring, condarc):
    """
    After a successful OAuth2 login and subsequent logout, running
    ``conda auth login <url>`` again (without --oauth2) must still succeed
    because the auth type and OAuth config keys are preserved through logout.

    This is the primary regression test for the two bugs fixed in this change:
    1. _find_channel_settings now uses URL-aware matching.
    2. remove_channel_settings preserves auth-config keys through logout.
    """
    channel_name = "https://repo.example.com:8443"
    oauth_client_id = "WzUtPJoAaz3HcVPp9IDDlRyX"

    # Simulate the state AFTER a logout: auth_target has been stripped by
    # remove_channel_settings, but auth type + OAuth config survive.
    post_logout_settings = [
        {
            "channel": channel_name,
            "auth": "oauth2",
            "oauth_client_id": oauth_client_id,
            "oauth_flow": "device-code",
        }
    ]
    mocker.patch("conda_auth.cli.context.channel_settings", post_logout_settings)
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="tok",
            token_endpoint=f"{channel_name}/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    # No --oauth2 flag — auto-detection must infer it from channel_settings.
    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output


# ---------------------------------------------------------------------------
# Login skips writing to user condarc when config already exists elsewhere
# ---------------------------------------------------------------------------


def test_login_does_not_write_to_user_condarc_when_config_exists_elsewhere(
    mocker, runner, keyring, condarc
):
    """
    Regression test: when auth configuration for a channel already exists in
    another config source (e.g. a package-installed condarc.d file) but NOT in
    the user condarc, login should NOT write a new entry to ~/.condarc.

    Writing a duplicate, incomplete entry to ~/.condarc would shadow the richer
    external config (which has oauth_client_id, oauth_flow, etc.) because
    ~/.condarc takes precedence over $PREFIX/etc/conda/condarc.d/*.yaml.  On
    the next login after a logout this causes the OAuth flow to fail or run
    with missing parameters.
    """
    channel_name = "https://repo.example.com"
    oauth_client_id = "WzUtPJoAaz3HcVPp9IDDlRyX"

    # Simulate: config is present in a package-installed condarc.d file
    # (merged into context.channel_settings), but the user condarc is empty.
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [
            {
                "channel": channel_name,
                "auth": "oauth2",
                "oauth_client_id": oauth_client_id,
                "oauth_flow": "device-code",
            }
        ],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    condarc.content = {}  # user condarc starts empty

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="tok",
            token_endpoint=f"{channel_name}/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output
    # The user condarc must remain untouched — no duplicate entry written.
    assert condarc.content == {}


def test_login_writes_to_user_condarc_when_no_config_exists_elsewhere(
    mocker, runner, keyring, condarc
):
    """
    Counterpart to the above: when there is no existing auth entry anywhere
    (neither in the user condarc nor in any other config source), login should
    write the entry to the user condarc as normal.
    """
    channel_name = "https://repo.example.com"

    # No channel_settings anywhere — user must supply the auth type via flag.
    mocker.patch("conda_auth.cli.context.channel_settings", [])
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    condarc.content = {}

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="tok",
            token_endpoint=f"{channel_name}/token",
            client_id="explicit-client-id",
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    result = runner.invoke(
        auth,
        ["login", channel_name, "--oauth2", "--oauth-client-id", "explicit-client-id"],
    )

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output
    # Entry should have been written to the user condarc.
    assert condarc.content.get("channel_settings") is not None
    written = condarc.content["channel_settings"]
    assert len(written) == 1
    assert written[0]["channel"] == channel_name
    assert written[0]["auth"] == "oauth2"


def test_login_writes_to_user_condarc_when_user_condarc_already_has_entry(
    mocker, runner, keyring, condarc
):
    """
    When the user condarc already has an existing entry for the channel (e.g.
    from a previous login/logout cycle that left auth-config keys behind), login
    should update that entry in place as normal — not skip the write.
    """
    channel_name = "https://repo.example.com"
    oauth_client_id = "WzUtPJoAaz3HcVPp9IDDlRyX"

    # Context has the entry (coming from user condarc post-logout state).
    mocker.patch(
        "conda_auth.cli.context.channel_settings",
        [
            {
                "channel": channel_name,
                "auth": "oauth2",
                "oauth_client_id": oauth_client_id,
                "oauth_flow": "device-code",
            }
        ],
    )
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    # User condarc already has the entry (post-logout: auth_target stripped,
    # but auth type + OAuth config keys preserved).
    condarc.content = {
        "channel_settings": [
            {
                "channel": channel_name,
                "auth": "oauth2",
                "oauth_client_id": oauth_client_id,
                "oauth_flow": "device-code",
            }
        ]
    }

    def fake_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="tok",
            token_endpoint=f"{channel_name}/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output
    # The existing user condarc entry should be updated (auth_target written back).
    written = condarc.content.get("channel_settings", [])
    assert len(written) == 1
    assert written[0]["channel"] == channel_name
    assert written[0]["auth"] == "oauth2"
    assert written[0].get("auth_target") == channel_name


def test_login_logout_login_cycle_with_external_config(mocker, runner, keyring, condarc):
    """
    Full regression test for the bug: login → logout → login when auth config
    lives in a package-installed condarc.d file (not in the user condarc).

    Before the fix:
      1. First login wrote an incomplete entry to ~/.condarc.
      2. Logout stripped auth_target, leaving {channel, auth: oauth2} in ~/.condarc.
      3. Second login read the incomplete ~/.condarc entry (higher precedence),
         missing oauth_client_id/oauth_flow — OAuth flow failed or used wrong params.

    After the fix:
      1. First login detects the external config and skips writing to ~/.condarc.
      2. Logout finds no entry in ~/.condarc but finds keyring credentials;
         it removes the keyring secret and succeeds.
      3. Second login again reads the full config from the external source and
         succeeds with the correct OAuth parameters.
    """
    from conda_auth.cli import SUCCESSFUL_LOGOUT_MESSAGE, logout
    from conda_auth.credentials import CredentialRecord as CR
    import json as _json

    channel_name = "https://repo.example.com"
    oauth_client_id = "WzUtPJoAaz3HcVPp9IDDlRyX"

    # The full OAuth2 config lives in a package-installed condarc.d file.
    # It is always present in context.channel_settings throughout the test.
    external_settings = [
        {
            "channel": channel_name,
            "auth": "oauth2",
            "oauth_client_id": oauth_client_id,
            "oauth_flow": "device-code",
        }
    ]
    mocker.patch("conda_auth.cli.context.channel_settings", external_settings)

    keyring_mock, _ = keyring(None)

    call_count = {"n": 0}

    def fake_oauth_login(config):
        call_count["n"] += 1
        # Verify the correct OAuth config was passed both times.
        assert config.client_id == oauth_client_id, (
            f"Expected client_id={oauth_client_id!r}, got {config.client_id!r} "
            f"on call #{call_count['n']}"
        )
        return CR(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token=f"tok-{call_count['n']}",
            token_endpoint=f"{channel_name}/token",
            client_id=config.client_id,
        )

    mocker.patch("conda_auth.cli.perform_oauth_login", side_effect=fake_oauth_login)

    # ── First login ────────────────────────────────────────────────────────
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)
    condarc.content = {}

    result = runner.invoke(auth, ["login", channel_name])
    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output

    # The user condarc must remain empty — no duplicate entry.
    assert condarc.content == {}, (
        "login() must not write to the user condarc when auth config exists elsewhere; "
        f"got: {condarc.content}"
    )

    # ── Logout ─────────────────────────────────────────────────────────────
    # Simulate the stored credential in keyring so logout can find it.
    stored_record = CR(
        target=channel_name,
        auth_type="oauth2",
        username="oauth2",
        access_token="tok-1",
        token_endpoint=f"{channel_name}/token",
        client_id=oauth_client_id,
    )
    mocker.patch(
        "conda_auth.cli.storage.get_credential", return_value=stored_record
    )

    result = runner.invoke(auth, ["logout", channel_name])
    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output

    # User condarc still empty after logout (an empty channel_settings list is
    # equivalent — remove_channel_settings always writes the (empty) list back).
    assert condarc.content.get("channel_settings", []) == []

    # ── Second login ───────────────────────────────────────────────────────
    mocker.patch("conda_auth.cli.storage.get_credential", return_value=None)

    result = runner.invoke(auth, ["login", channel_name])
    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output

    # Both logins should have used the correct client_id from the external config.
    assert call_count["n"] == 2
