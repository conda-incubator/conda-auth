from unittest.mock import MagicMock

import pytest
from ruamel.yaml.error import YAMLError

from conda_auth.condarc import CondaRC, CondaRCError, yaml


CONDARC_CONTENT = """
channels:
- defaults
channel_settings:
"""


def test_update_non_existing_condarc_file(tmp_path):
    """
    Make sure that the condarc file can be updated even when it first doesn't exist
    """
    channel = "tester"
    username = "username"
    auth_type = "http-basic"
    condarc_path = tmp_path / ".condarc"

    condarc = CondaRC(condarc_path)
    condarc.update_channel_settings(channel, auth_type, username)
    condarc.save()

    condarc_dict = yaml.load(condarc_path.read_text())

    assert condarc_dict == {
        "channel_settings": [
            {
                "channel": channel,
                "username": username,
                "auth": auth_type,
            }
        ]
    }


def test_update_existing_condarc_file(tmp_path):
    """
    Make sure that the condarc file can be updated even when it does exist

    TODO:
        It might be nice to expand this test in the future with some more condarc
        file states via a pytest.parameters decorator.
    """
    channel = "tester"
    username = "username"
    auth_type = "http-basic"
    condarc_path = tmp_path / ".condarc"
    condarc_path.write_text(CONDARC_CONTENT)

    condarc = CondaRC(condarc_path)
    condarc.update_channel_settings(channel, auth_type, username)
    condarc.save()

    condarc_dict = yaml.load(condarc_path.read_text())

    assert condarc_dict == {
        "channel_settings": [
            {
                "channel": channel,
                "username": username,
                "auth": auth_type,
            }
        ],
        "channels": ["defaults"],
    }


def test_error_while_reading_condarc_file():
    """
    Testing to make sure the appropriate error is raised when an OSError occurs
    """
    error_message = "Not allowed to read"
    mock_path = MagicMock()
    mock_path.open.side_effect = PermissionError(error_message)

    with pytest.raises(CondaRCError, match=error_message):
        CondaRC(mock_path)


def test_error_parsing_yaml(mocker, tmp_path):
    """
    Testing to make sure the appropriate error is raised when an YAMLError occurs
    """
    error_message = "Parse error"
    condarc_path = tmp_path / ".condarc"
    mock_yaml = mocker.patch("conda_auth.condarc.yaml")
    mock_yaml.load.side_effect = YAMLError(error_message)

    with pytest.raises(CondaRCError, match=error_message):
        CondaRC(condarc_path)


def test_error_saving_condarc(mocker, tmp_path):
    """
    Testing to make sure the appropriate error is raised when an OSError occurs on file save
    """
    error_message = "Not allowed to write"
    condarc_path = tmp_path / ".condarc"
    condarc_path.touch()
    mock_path = MagicMock()
    mock_path.open.side_effect = [
        condarc_path.open("r"),
        PermissionError(error_message),
    ]

    with pytest.raises(CondaRCError, match=error_message):
        condarc = CondaRC(mock_path)
        condarc.save()
