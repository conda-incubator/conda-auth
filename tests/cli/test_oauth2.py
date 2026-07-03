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
