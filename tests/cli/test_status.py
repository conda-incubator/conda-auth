from __future__ import annotations

import json

import pytest
from conda.models.channel import Channel

from conda_auth.cli import auth
from conda_auth.cli.status import channel_matches, get_status_targets
from conda_auth.credentials import CredentialRecord
from conda_auth.storage import storage


def test_status_json_lists_redacted_configured_credentials(
    monkeypatch, runner, keyring, condarc, context_factory
):
    """Status uses configured auth targets and does not expose stored token values."""
    keyring(None)

    login_result = runner.invoke(auth, ["login", "tester", "--token", "secret-token"])
    assert login_result.exit_code == 0, login_result.output
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory(condarc.content["channel_settings"]),
    )

    result = runner.invoke(auth, ["status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "credentials": [
            {
                "target": "tester",
                "auth_type": "token",
                "username": "token",
            }
        ],
    }
    assert "secret-token" not in result.output


def test_status_text_handles_empty_storage(runner, keyring, context_factory, monkeypatch):
    """Text status output handles missing configured credentials."""
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory([{"channel": "tester", "auth": "token", "auth_target": "tester"}]),
    )

    result = runner.invoke(auth, ["status"])

    assert result.exit_code == 0, result.output
    assert result.output == "No credentials stored\n"


def test_status_lists_configured_token_file_without_keyring(
    runner, keyring, context_factory, monkeypatch
):
    """Status can report file-backed token auth without enumerating keyring secrets."""
    keyring_mock, _ = keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory(
            [
                {
                    "channel": "tester",
                    "auth": "token",
                    "auth_target": "tester",
                    "token_file": "/run/secrets/conda_auth_secret",
                }
            ]
        ),
    )

    result = runner.invoke(auth, ["status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "credentials": [
            {
                "target": "tester",
                "auth_type": "token",
                "source": "token_file",
            }
        ],
    }
    assert "secret-token" not in result.output
    assert keyring_mock.get_password_calls == []


def test_status_does_not_list_unconfigured_credentials(
    runner, keyring, monkeypatch, context_factory
):
    """Storage records are hidden from status when no auth setting references them."""
    keyring(None)
    storage.set_credential(
        CredentialRecord(
            target="tester",
            auth_type="token",
            username="token",
            token="secret-token",
        )
    )
    monkeypatch.setattr("conda_auth.cli.status.context", context_factory())

    result = runner.invoke(auth, ["status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"success": True, "credentials": []}


def test_status_explicit_target_uses_matching_configured_auth_target(
    runner, keyring, monkeypatch, context_factory
):
    """Explicit status targets can resolve to a configured wildcard auth target."""
    keyring(None)
    storage.set_credential(
        CredentialRecord(
            target="https://repo.example.com/*",
            auth_type="token",
            username="token",
            token="secret-token",
        )
    )
    monkeypatch.setattr(
        "conda_auth.cli.status.context",
        context_factory(
            [
                {
                    "channel": "https://repo.example.com/*",
                    "auth": "token",
                    "auth_target": "https://repo.example.com/*",
                }
            ]
        ),
    )

    result = runner.invoke(auth, ["status", "https://repo.example.com/private", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "success": True,
        "credentials": [
            {
                "target": "https://repo.example.com/*",
                "auth_type": "token",
                "username": "token",
            }
        ],
    }


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
    storage.set_credential(
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
