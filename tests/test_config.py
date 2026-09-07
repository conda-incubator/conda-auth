import pytest
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import yaml

from conda_auth.cli.config import (
    get_updated_channel_settings,
    remove_channel_settings,
    update_channel_settings,
    update_proxy_server,
)
from conda_auth.exceptions import CondaAuthError

CONDARC_CONTENT = """
channels:
- defaults
channel_settings:
"""


def test_get_updated_channel_settings_preserves_existing_channel_settings():
    channel_settings = [
        {
            "channel": "tester",
            "auth": "token",
            "token_header": "X-Auth",
            "token_template": "Token {token}",
            "ssl_verify": False,
        },
        {"channel": "other", "auth": "token"},
    ]

    assert get_updated_channel_settings(
        channel_settings,
        "tester",
        "http-basic",
        "username",
    ) == [
        {
            "channel": "tester",
            "ssl_verify": False,
            "auth": "http-basic",
            "auth_target": "tester",
            "username": "username",
        },
        {"channel": "other", "auth": "token"},
    ]


def test_get_updated_channel_settings_persists_non_secret_token_file_settings():
    channel_settings = [{"channel": "tester", "ssl_verify": False}]

    assert get_updated_channel_settings(
        channel_settings,
        "tester",
        "token",
        settings={
            "token": "secret-token",
            "token_file": "/run/secrets/conda_auth_secret",
            "token_header": "X-Auth",
            "token_template": "Token {token}",
        },
    ) == [
        {
            "channel": "tester",
            "ssl_verify": False,
            "auth": "token",
            "auth_target": "tester",
            "token_file": "/run/secrets/conda_auth_secret",
            "token_header": "X-Auth",
            "token_template": "Token {token}",
        },
    ]


def test_get_updated_channel_settings_updates_last_exact_channel():
    channel_settings = [
        {"channel": "tester", "auth": "token", "description": "older"},
        {"channel": "tester", "ssl_verify": False},
    ]

    assert get_updated_channel_settings(channel_settings, "tester", "http-basic", "username") == [
        {"channel": "tester", "auth": "token", "description": "older"},
        {
            "channel": "tester",
            "ssl_verify": False,
            "auth": "http-basic",
            "auth_target": "tester",
            "username": "username",
        },
    ]


@pytest.mark.parametrize(
    ("auth_type", "public_settings", "secret_settings"),
    (
        (
            "oauth2",
            {"oauth_client_id": "client", "oauth_flow": "device-code"},
            {"oauth_client_secret": "must-not-survive"},
        ),
        (
            "token",
            {"token_header": "X-Auth", "token_template": "Token {token}"},
            {"token": "must-not-survive"},
        ),
    ),
    ids=("oauth2", "token"),
)
def test_get_updated_channel_settings_preserves_same_type_public_config(
    auth_type,
    public_settings,
    secret_settings,
):
    channel_settings = [
        {
            "channel": "https://repo.example.com",
            "auth": auth_type,
            **public_settings,
            **secret_settings,
            "ssl_verify": False,
        }
    ]

    assert get_updated_channel_settings(
        channel_settings,
        "https://repo.example.com",
        auth_type,
    ) == [
        {
            "channel": "https://repo.example.com",
            "auth": auth_type,
            "auth_target": "https://repo.example.com",
            **public_settings,
            "ssl_verify": False,
        }
    ]


def test_update_non_existing_condarc_file(tmp_path):
    channel = "tester"
    username = "username"
    auth_type = "http-basic"
    condarc_path = tmp_path / ".condarc"

    with ConfigurationFile(path=condarc_path) as config:
        update_channel_settings(config, channel, auth_type, username)

    assert yaml.read(path=condarc_path) == {
        "channel_settings": [
            {
                "channel": channel,
                "username": username,
                "auth": auth_type,
                "auth_target": channel,
            }
        ]
    }


def test_update_existing_condarc_file(tmp_path):
    channel = "tester"
    username = "username"
    auth_type = "http-basic"
    condarc_path = tmp_path / ".condarc"
    condarc_path.write_text(CONDARC_CONTENT)

    with ConfigurationFile(path=condarc_path) as config:
        update_channel_settings(config, channel, auth_type, username)

    assert yaml.read(path=condarc_path) == {
        "channel_settings": [
            {
                "channel": channel,
                "username": username,
                "auth": auth_type,
                "auth_target": channel,
            }
        ],
        "channels": ["defaults"],
    }


def test_update_channel_settings_requires_list():
    config = ConfigurationFile(content={"channel_settings": "tester"})

    with pytest.raises(CondaAuthError, match="Expected 'channel_settings' to be a list"):
        update_channel_settings(config, "tester", "token")


def test_remove_channel_settings():
    config = ConfigurationFile(
        content={
            "channel_settings": [
                {"channel": "tester", "auth": "token"},
                {"channel": "other", "auth": "token"},
            ]
        }
    )

    assert remove_channel_settings(config, "tester") is True

    assert config.content == {
        "channel_settings": [
            {"channel": "other", "auth": "token"},
        ]
    }


def test_remove_channel_settings_preserves_non_auth_settings():
    config = ConfigurationFile(
        content={
            "channel_settings": [
                {
                    "channel": "tester",
                    "auth": "token",
                    "auth_allow_plaintext_http": True,
                    "token_file": "/run/secrets/conda_auth_secret",
                    "token_header": "X-Auth",
                    "token_template": "Token {token}",
                    "ssl_verify": False,
                },
                {"channel": "other", "auth": "token"},
            ]
        }
    )

    assert remove_channel_settings(config, "tester") is True

    assert config.content == {
        "channel_settings": [
            {"channel": "tester", "ssl_verify": False},
            {"channel": "other", "auth": "token"},
        ]
    }


def test_remove_channel_settings_reports_when_no_auth_settings_removed():
    config = ConfigurationFile(
        content={"channel_settings": [{"channel": "tester", "ssl_verify": False}]}
    )

    assert remove_channel_settings(config, "tester") is False

    assert config.content == {"channel_settings": [{"channel": "tester", "ssl_verify": False}]}


@pytest.mark.parametrize(
    ("settings_func", "args"),
    (
        (update_channel_settings, ("tester", "token")),
        (remove_channel_settings, ("tester",)),
    ),
    ids=("update", "remove"),
)
def test_channel_settings_helpers_require_list(settings_func, args):
    # Both helpers reject malformed channel_settings before mutating content.
    config = ConfigurationFile(content={"channel_settings": "tester"})

    with pytest.raises(CondaAuthError, match="Expected 'channel_settings' to be a list"):
        settings_func(config, *args)


@pytest.mark.parametrize(
    "proxy_servers",
    ("http://proxy.example.com:8080", ["http://proxy.example.com:8080"]),
    ids=("string", "list"),
)
def test_update_proxy_server_requires_mapping(proxy_servers):
    config = ConfigurationFile(content={"proxy_servers": proxy_servers})

    with pytest.raises(CondaAuthError, match="Expected 'proxy_servers' to be a mapping"):
        update_proxy_server(config, "http", "http://proxy.example.com:8080")
