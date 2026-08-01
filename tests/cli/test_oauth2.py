from __future__ import annotations

from io import StringIO

import pytest
from conda.models.channel import Channel

from conda_auth.cli.oauth2 import build_oauth_login_config, ensure_url_scheme
from conda_auth.exceptions import CondaAuthError
from conda_auth.oauth2_client import OAuthLoginConfig


@pytest.mark.parametrize(
    ("target", "expected"),
    (
        ("idp.example.com", "https://idp.example.com"),
        ("https://idp.example.com", "https://idp.example.com"),
        ("http://localhost:8080", "http://localhost:8080"),
    ),
    ids=("bare-host", "https", "loopback-http"),
)
def test_ensure_url_scheme(target, expected):
    assert ensure_url_scheme(target) == expected


def test_build_oauth_login_config_uses_channel_defaults():
    config = build_oauth_login_config(
        Channel("https://repo.example.com/private"),
        {"oauth_client_id": "client"},
    )

    assert config == OAuthLoginConfig(
        issuer_url="https://repo.example.com/private",
        client_id="client",
    )


def test_build_oauth_login_config_uses_explicit_options():
    output = StringIO()

    config = build_oauth_login_config(
        Channel("https://repo.example.com/private"),
        {
            "oauth_issuer_url": "idp.example.com",
            "oauth_client_id": "client",
            "oauth_client_secret": "secret",
            "oauth_flow": "device-code",
            "oauth_scopes": ["openid", "offline_access"],
            "oauth_redirect_uri": "http://localhost:8765/callback",
            "user_agent": "conda-auth-test",
            "oauth_output_stream": output,
        },
    )

    assert config == OAuthLoginConfig(
        issuer_url="https://idp.example.com",
        client_id="client",
        client_secret="secret",
        flow="device-code",
        scopes=("openid", "offline_access"),
        redirect_uri="http://localhost:8765/callback",
        user_agent="conda-auth-test",
        output_stream=output,
    )


@pytest.mark.parametrize(
    ("options", "message"),
    (
        ({"oauth_issuer_url": 1, "oauth_client_id": "client"}, "issuer URL not found"),
        ({"oauth_client_id": 1}, "client ID not found"),
        ({"oauth_client_id": "client", "oauth_flow": 1}, "flow must be text"),
        (
            {"oauth_client_id": "client", "oauth_client_secret": 1},
            "client secret must be text",
        ),
        (
            {"oauth_client_id": "client", "oauth_redirect_uri": 1},
            "redirect URI must be text",
        ),
        ({"oauth_client_id": "client", "user_agent": 1}, "user agent must be text"),
        (
            {"oauth_client_id": "client", "oauth_output_stream": object()},
            "output stream must be file-like",
        ),
    ),
    ids=(
        "issuer",
        "client-id",
        "flow",
        "client-secret",
        "redirect-uri",
        "user-agent",
        "output-stream",
    ),
)
def test_build_oauth_login_config_rejects_invalid_options(options, message):
    with pytest.raises(CondaAuthError, match=message):
        build_oauth_login_config(Channel("https://repo.example.com/private"), options)


# ---------------------------------------------------------------------------
# channel_settings fallback
# ---------------------------------------------------------------------------

_CHANNEL = Channel("https://repo.example.com/private")
_SETTINGS = {
    "channel": "https://repo.example.com/private",
    "auth": "oauth2",
    "oauth_client_id": "settings-client",
    "oauth_issuer_url": "https://idp.example.com",
    "oauth_flow": "device-code",
    "oauth_scopes": ["openid", "offline_access"],
    "oauth_redirect_uri": "http://localhost:9000/cb",
    "user_agent": "my-agent",
}


def test_build_oauth_login_config_reads_all_params_from_settings():
    """All OAuth params can be sourced entirely from channel_settings."""
    config = build_oauth_login_config(_CHANNEL, {}, channel_settings=_SETTINGS)

    assert config == OAuthLoginConfig(
        issuer_url="https://idp.example.com",
        client_id="settings-client",
        flow="device-code",
        scopes=("openid", "offline_access"),
        redirect_uri="http://localhost:9000/cb",
        user_agent="my-agent",
    )


def test_build_oauth_login_config_cli_overrides_settings():
    """A CLI-supplied value takes precedence over channel_settings for each param."""
    config = build_oauth_login_config(
        _CHANNEL,
        {
            "oauth_client_id": "cli-client",
            "oauth_flow": "auth-code",
        },
        channel_settings=_SETTINGS,
    )

    assert config.client_id == "cli-client"
    assert config.flow == "auth-code"
    # Non-overridden params still come from settings
    assert config.issuer_url == "https://idp.example.com"
    assert config.scopes == ("openid", "offline_access")


def test_build_oauth_login_config_empty_scopes_list_falls_back_to_settings():
    """An empty list from argparse append default should fall back to channel_settings scopes."""
    config = build_oauth_login_config(
        _CHANNEL,
        {"oauth_client_id": "c", "oauth_scopes": []},
        channel_settings={**_SETTINGS, "oauth_scopes": ["profile"]},
    )

    assert config.scopes == ("profile",)


def test_build_oauth_login_config_missing_client_id_improved_error():
    """Missing client_id from both CLI and settings raises with a helpful message."""
    with pytest.raises(CondaAuthError, match="channel_settings"):
        build_oauth_login_config(_CHANNEL, {}, channel_settings={"channel": "x"})


def test_build_oauth_login_config_cli_only_still_works():
    """Existing CLI-only usage is unchanged when channel_settings is not provided."""
    config = build_oauth_login_config(
        _CHANNEL,
        {"oauth_client_id": "client"},
    )

    assert config == OAuthLoginConfig(
        issuer_url="https://repo.example.com/private",
        client_id="client",
    )
