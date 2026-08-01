import pytest
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import yaml

from conda_auth.cli import (
    get_updated_channel_settings,
    remove_channel_settings,
    update_channel_settings,
)
from conda_auth.exceptions import CondaAuthError

CONDARC_CONTENT = """
channels:
- defaults
channel_settings:
"""


def test_get_updated_channel_settings_preserves_existing_channel_settings():
    channel_settings = [
        {"channel": "tester", "auth": "token", "ssl_verify": False},
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
    """
    Logout strips credential keys (auth_target, token, etc.) but preserves
    auth-configuration keys (auth type, oauth_client_id, etc.) so that the
    next ``conda auth login`` can auto-detect the auth type.
    """
    config = ConfigurationFile(
        content={
            "channel_settings": [
                # Realistic post-login entry: auth type + session state.
                {"channel": "tester", "auth": "token", "auth_target": "tester"},
                {"channel": "other", "auth": "token", "auth_target": "other"},
            ]
        }
    )

    assert remove_channel_settings(config, "tester") is True

    # auth_target is removed (credential), but auth type is preserved so that
    # the next login can detect the auth type automatically.
    assert config.content == {
        "channel_settings": [
            {"channel": "tester", "auth": "token"},
            {"channel": "other", "auth": "token", "auth_target": "other"},
        ]
    }


def test_remove_channel_settings_preserves_non_auth_settings():
    """
    Non-auth keys (e.g. ssl_verify) and auth-config keys are preserved; only
    credential keys are stripped on logout.
    """
    config = ConfigurationFile(
        content={
            "channel_settings": [
                {
                    "channel": "tester",
                    "auth": "token",
                    "auth_target": "tester",
                    "ssl_verify": False,
                },
                {"channel": "other", "auth": "token", "auth_target": "other"},
            ]
        }
    )

    assert remove_channel_settings(config, "tester") is True

    assert config.content == {
        "channel_settings": [
            # auth stays (config key), auth_target gone (credential key).
            {"channel": "tester", "auth": "token", "ssl_verify": False},
            {"channel": "other", "auth": "token", "auth_target": "other"},
        ]
    }


def test_remove_channel_settings_removes_entry_with_only_channel_key():
    """
    An entry that would be reduced to just {channel: ...} after stripping
    credential keys is removed entirely.
    """
    config = ConfigurationFile(
        content={
            "channel_settings": [
                # Entry with only credential keys (no config keys like auth).
                {"channel": "tester", "auth_target": "tester"},
            ]
        }
    )

    assert remove_channel_settings(config, "tester") is True

    assert config.content == {"channel_settings": []}


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


def test_remove_channel_settings_preserves_oauth_config_keys():
    """
    OAuth configuration keys (oauth_client_id, oauth_flow, etc.) survive
    logout so that a subsequent ``conda auth login`` can auto-detect the auth
    type and OAuth parameters without requiring the user to pass flags again.
    """
    config = ConfigurationFile(
        content={
            "channel_settings": [
                {
                    "channel": "https://repo.example.com",
                    "auth": "oauth2",
                    "auth_target": "https://repo.example.com",
                    "oauth_client_id": "my-client-id",
                    "oauth_flow": "device-code",
                    "oauth_scopes": ["openid", "offline_access"],
                }
            ]
        }
    )

    assert remove_channel_settings(config, "https://repo.example.com") is True

    # auth_target is removed (credential); auth type and OAuth config survive.
    assert config.content == {
        "channel_settings": [
            {
                "channel": "https://repo.example.com",
                "auth": "oauth2",
                "oauth_client_id": "my-client-id",
                "oauth_flow": "device-code",
                "oauth_scopes": ["openid", "offline_access"],
            }
        ]
    }


def test_get_updated_channel_settings_preserves_oauth_config_keys():
    """
    A re-login preserves OAuth config keys written by the user (or a resource
    handler) so they are not accidentally wiped on the first successful login.
    """
    existing = [
        {
            "channel": "https://repo.example.com",
            "auth": "oauth2",
            "oauth_client_id": "my-client-id",
            "oauth_flow": "device-code",
        }
    ]

    result = get_updated_channel_settings(
        existing,
        "https://repo.example.com",
        "oauth2",
        auth_target="https://repo.example.com",
    )

    # oauth_client_id and oauth_flow survive the login round-trip.
    assert result == [
        {
            "channel": "https://repo.example.com",
            "auth": "oauth2",
            "oauth_client_id": "my-client-id",
            "oauth_flow": "device-code",
            "auth_target": "https://repo.example.com",
        }
    ]
