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
