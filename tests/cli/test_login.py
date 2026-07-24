import json

import pytest
from conda.exceptions import CondaError

from conda_auth.cli import SUCCESSFUL_LOGIN_MESSAGE, auth
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.token import TOKEN_NAME, USERNAME, TokenAuthManager
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
        (
            ["login", "tester", "--basic", "--header", "X-Auth", "--json"],
            "Token header options can only be used with 'token'",
        ),
        (
            ["login", "tester", "--oauth2", "--header-template", "Token {token}", "--json"],
            "Token header options can only be used with 'token'",
        ),
    ),
    ids=(
        "missing-auth",
        "missing-auth-json",
        "token-username-json",
        "token-password-json",
        "basic-token-header-json",
        "oauth2-token-template-json",
    ),
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
    assert condarc.content == {"channel_settings": []}
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
    assert condarc.content == {
        "channel_settings": [{"channel": channel_name, "ssl_verify": False}]
    }


def test_login_does_not_verify_without_verify_option(monkeypatch, runner, keyring, condarc):
    channel_name = "tester"
    keyring(None)

    def verify_credentials(channel, record):
        raise AssertionError("Credential verification should be opt-in")

    monkeypatch.setattr("conda_auth.cli.verify_channel_credentials", verify_credentials)

    result = runner.invoke(
        auth,
        ["login", channel_name, "--basic", "--username", "user", "--password", "password"],
    )

    assert result.exit_code == 0, result.output


def test_login_verify_uses_stored_record(monkeypatch, runner, keyring, condarc):
    channel_name = "https://repo.example.com/private-channel"
    keyring(None)
    verification_calls = []

    def verify_credentials(channel, record):
        verification_calls.append((channel, record))

    monkeypatch.setattr("conda_auth.cli.verify_channel_credentials", verify_credentials)

    result = runner.invoke(
        auth,
        [
            "login",
            channel_name,
            "--token",
            "token",
            "--header",
            "X-Auth",
            "--token-template",
            "Token {token}",
            "--verify",
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(verification_calls) == 1
    channel, record = verification_calls[0]
    assert channel.canonical_name == channel_name
    assert record.target == channel_name
    assert record.auth_type == TOKEN_NAME
    assert record.token == "token"
    assert record.token_header == "X-Auth"
    assert record.token_template == "Token {token}"


def test_login_verify_failure_removes_credential_and_auth_settings(
    monkeypatch, runner, keyring, condarc
):
    channel_name = "tester"
    keyring(None)

    def verify_credentials(channel, record):
        raise CondaAuthError("Could not verify credentials")

    monkeypatch.setattr("conda_auth.cli.verify_channel_credentials", verify_credentials)

    result = runner.invoke(
        auth,
        [
            "login",
            channel_name,
            "--basic",
            "--username",
            "user",
            "--password",
            "password",
            "--verify",
        ],
    )
    exc_type, exception, _ = result.exc_info

    assert result.exit_code == 1, result.output
    assert exc_type == CondaAuthError
    assert exception.message == "Could not verify credentials"
    assert condarc.content == {"channel_settings": []}
    assert storage.get_credential(channel_name) is None


def test_login_verify_failure_removes_config_before_credential(
    monkeypatch, runner, keyring, condarc
):
    channel_name = "tester"
    keyring(None)
    events = []

    def verify_credentials(channel, record):
        raise CondaAuthError("Could not verify credentials")

    def remove_settings(config, channel):
        events.append("remove-settings")
        config.content["channel_settings"] = []
        return True

    delete_credential = storage.delete_credential

    def delete_record(target):
        events.append("delete-credential")
        delete_credential(target)

    monkeypatch.setattr("conda_auth.cli.verify_channel_credentials", verify_credentials)
    monkeypatch.setattr("conda_auth.cli.remove_channel_settings", remove_settings)
    monkeypatch.setattr("conda_auth.cli.storage.delete_credential", delete_record)

    result = runner.invoke(
        auth,
        [
            "login",
            channel_name,
            "--basic",
            "--username",
            "user",
            "--password",
            "password",
            "--verify",
        ],
    )

    assert result.exit_code == 1, result.output
    assert events == ["remove-settings", "delete-credential"]


def test_login_verify_failure_revokes_oauth_record(monkeypatch, runner, keyring, condarc):
    channel_name = "https://repo.example.com/private"
    keyring(None)
    revoked = []

    def perform_oauth_login(config):
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="access-token",
            refresh_token="refresh-token",
            token_endpoint="https://idp.example.com/token",
            revocation_endpoint="https://idp.example.com/revoke",
            client_id="client",
        )

    def verify_credentials(channel, record):
        raise CondaAuthError("Could not verify credentials")

    def revoke_record(record):
        revoked.append(record)

    monkeypatch.setattr("conda_auth.cli.perform_oauth_login", perform_oauth_login)
    monkeypatch.setattr("conda_auth.cli.verify_channel_credentials", verify_credentials)
    monkeypatch.setattr("conda_auth.cli.revoke_oauth_record", revoke_record)

    result = runner.invoke(
        auth,
        [
            "login",
            channel_name,
            "--oauth2",
            "--oauth-client-id",
            "client",
            "--verify",
        ],
    )

    assert result.exit_code == 1, result.output
    assert len(revoked) == 1
    assert revoked[0].access_token == "access-token"
    assert storage.get_credential(channel_name) is None


def test_login_token(monkeypatch, runner, keyring, condarc, context_factory):
    """
    Test successful login with token
    """
    channel_name = "tester"

    # setup mocks
    monkeypatch.setattr("conda_auth.cli.context", context_factory())
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--token", "token"])

    assert result.exit_code == 0, result.output


def test_login_token_can_be_loaded_by_fresh_auth_manager(
    runner, keyring, condarc, context_factory
):
    """Token login persists enough state for later conda network commands."""
    channel_name = "https://repo.example.com/private-channel"
    token = "token"
    keyring(None)

    result = runner.invoke(auth, ["login", channel_name, "--token", token])
    assert result.exit_code == 0, result.output

    # A later conda command starts with an empty process cache and reads settings
    # from the conda context built from the user's condarc.
    context = context_factory(
        condarc.content["channel_settings"],
        channels=(channel_name,),
    )
    token_manager = TokenAuthManager(context)

    assert token_manager.get_secret(channel_name) == (USERNAME, token)
    assert token_manager._cache == {channel_name: (USERNAME, token)}
    assert condarc.content["channel_settings"] == [
        {
            "channel": channel_name,
            "auth": TOKEN_NAME,
            "auth_target": channel_name,
        }
    ]


def test_login_token_persists_custom_header_config(runner, keyring, condarc, context_factory):
    """Custom token header metadata is stored with the token credential."""
    channel_name = "https://repo.example.com/private-channel"
    token = "token"
    keyring(None)

    result = runner.invoke(
        auth,
        [
            "login",
            channel_name,
            "--token",
            token,
            "--header",
            "X-Auth",
            "--token-template",
            "Token {token}",
        ],
    )
    assert result.exit_code == 0, result.output

    record = storage.get_credential(channel_name)
    assert record is not None
    assert record.token == token
    assert record.token_header == "X-Auth"
    assert record.token_template == "Token {token}"

    context = context_factory(condarc.content["channel_settings"], channels=(channel_name,))
    token_manager = TokenAuthManager(context)

    assert token_manager.get_secret(channel_name) == (USERNAME, token)
    assert token_manager.get_header_config(channel_name) == ("X-Auth", "Token {token}")


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
