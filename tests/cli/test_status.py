import json

import pytest
from conda.models.channel import Channel

from conda_auth.cli import auth
from conda_auth.cli.status import channel_matches, get_status_targets
from conda_auth.credentials import CredentialRecord
from conda_auth.storage.keyring import KeyringStorage


def test_status_lists_configured_stored_credentials(monkeypatch, runner, keyring, context_factory):
    """
    Status lists records that are both configured and present in storage.
    """
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory([{"channel": "tester", "auth": "token", "auth_target": "tester"}]),
    )
    KeyringStorage().set_credential(
        CredentialRecord(
            target="tester",
            auth_type="token",
            username="token",
            token="secret-token",
        )
    )

    result = runner.invoke(auth, ["status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "credentials": [{"target": "tester", "auth_type": "token", "username": "token"}],
    }


def test_status_does_not_list_unconfigured_storage_records(
    monkeypatch, runner, keyring, context_factory
):
    """
    Status derives listable targets from conda auth config, not secret enumeration.
    """
    keyring(None)
    monkeypatch.setattr("conda_auth.cli.status.context", context_factory())
    KeyringStorage().set_credential(
        CredentialRecord(target="tester", auth_type="token", token="secret-token")
    )

    result = runner.invoke(auth, ["status"])

    assert result.exit_code == 0, result.output
    assert result.output == "No credentials stored\n"


def test_status_skips_configured_credentials_without_stored_record(
    monkeypatch, runner, keyring, context_factory
):
    """
    Configured auth without an available secret is not reported as stored.
    """
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory([{"channel": "tester", "auth": "token", "auth_target": "tester"}]),
    )

    result = runner.invoke(auth, ["status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"success": True, "credentials": []}


def test_status_explicit_target_matches_configured_auth_target(
    monkeypatch, runner, keyring, context_factory
):
    """
    Explicit status can resolve records through a configured auth_target.
    """
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory(
            [
                {
                    "channel": "https://example.com/private/*",
                    "auth": "token",
                    "auth_target": "https://example.com/private",
                }
            ]
        ),
    )
    KeyringStorage().set_credential(
        CredentialRecord(
            target="https://example.com/private",
            auth_type="token",
            username="token",
            token="secret-token",
        )
    )

    result = runner.invoke(auth, ["status", "https://example.com/private/osx-arm64"])

    assert result.exit_code == 0, result.output
    assert result.output == "https://example.com/private: token\n"
def test_status_targets_skip_invalid_settings(monkeypatch, context_factory):
    """
    Status ignores unrelated and malformed channel settings.
    """
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory(
            [
                None,
                {"channel": "unconfigured"},
                {"channel": 1, "auth": "token"},
                {"channel": "tester", "auth": "token", "auth_target": 1},
            ]
        ),
    )

    assert get_status_targets() == ("tester",)


@pytest.mark.parametrize(
    ("configured_channel", "channel_name", "expected"),
    (
        ("tester", "tester", True),
        ("http://repo.example.com/*", "https://repo.example.com/private", False),
        ("https://repo.example.com/*", "https://repo.example.com/private", True),
        ("https://other.example.com/*", "https://repo.example.com/private", False),
    ),
    ids=("exact", "scheme-mismatch", "pattern-match", "pattern-mismatch"),
)
def test_status_channel_matching(configured_channel, channel_name, expected):
    """
    Status uses the same exact, scheme, and URL pattern matching as auth loading.
    """
    assert channel_matches(configured_channel, Channel(channel_name)) is expected


def test_status_displays_credential_expiration(
    monkeypatch,
    runner,
    keyring,
    context_factory,
):
    """
    Text status includes an OAuth access token expiration time when available.
    """
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory([{"channel": "tester", "auth": "oauth2", "auth_target": "tester"}]),
    )
    KeyringStorage().set_credential(
        CredentialRecord(
            target="tester",
            auth_type="oauth2",
            access_token="secret-token",
            expires_at=3600,
        )
    )

    result = runner.invoke(auth, ["status"])

    assert result.exit_code == 0, result.output
    assert result.output == "tester: oauth2 expires_at=3600\n"


def test_oauth_login_uses_explicit_endpoint_options(monkeypatch, runner, keyring, condarc):
    """Generic OAuth login uses caller-supplied endpoint configuration."""
    keyring(None)
    seen = {}

    def perform_oauth_login(config):
        seen["config"] = config
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="access-token",
            refresh_token="refresh-token",
            token_endpoint="https://idp.example.com/token",
            revocation_endpoint="https://idp.example.com/revoke",
            client_id=config.client_id,
            issuer_url=config.issuer_url,
            scopes=config.scopes,
        )

    monkeypatch.setattr("conda_auth.cli.channel.perform_oauth_login", perform_oauth_login)

    result = runner.invoke(
        auth,
        [
            "login",
            "https://repo.example.com/private",
            "--oauth2",
            "--oauth-issuer-url",
            "https://idp.example.com",
            "--oauth-client-id",
            "client-id",
            "--oauth-scope",
            "channel:read",
            "--oauth-flow",
            "device-code",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["config"].issuer_url == "https://idp.example.com"
    assert seen["config"].client_id == "client-id"
    assert seen["config"].flow == "device-code"
    assert seen["config"].scopes == ("channel:read",)
    assert condarc.content == {
        "channel_settings": [
            {
                "channel": "https://repo.example.com/private",
                "auth": "oauth2",
                "auth_target": "https://repo.example.com/private",
            }
        ]
    }
