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


def test_get_updated_channel_settings_replaces_existing_channel():
    channel_settings = [
        {"channel": "tester", "auth": "token"},
        {"channel": "other", "auth": "token"},
    ]

    assert get_updated_channel_settings(
        channel_settings,
        "tester",
        "http-basic",
        "username",
    ) == [
        {"channel": "other", "auth": "token"},
        {"channel": "tester", "auth": "http-basic", "username": "username"},
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

    remove_channel_settings(config, "tester")

    assert config.content == {
        "channel_settings": [
            {"channel": "other", "auth": "token"},
        ]
    }


def test_remove_channel_settings_requires_list():
    config = ConfigurationFile(content={"channel_settings": "tester"})

    with pytest.raises(CondaAuthError, match="Expected 'channel_settings' to be a list"):
        remove_channel_settings(config, "tester")
