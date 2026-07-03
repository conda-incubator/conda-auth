import pytest

from conda_auth.cli import auth
from conda_auth.cli.channel import get_auth_manager, prompt_secret, prompt_text
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers import (
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
    basic_auth_manager,
    token_auth_manager,
)


def test_auth_wrapper(runner):
    """
    Test to make sure the ``auth_wrapper`` function works.

    It is run with no arguments which will print the help message.
    """
    result = runner.invoke(auth, [])

    assert result.exit_code == 0, result.output
    assert "Commands for handling authentication within conda" in result.output


def test_prompt_text_uses_input(monkeypatch):
    """
    Test to make sure the text prompt delegates to the standard input function.
    """
    monkeypatch.setattr("builtins.input", lambda prompt: f"value for {prompt}")

    assert prompt_text("Username: ") == "value for Username: "


def test_prompt_secret_uses_getpass(mocker):
    """
    Test to make sure the secret prompt delegates to getpass.
    """
    getpass_mock = mocker.patch("conda_auth.cli.channel.getpass", return_value="secret")

    assert prompt_secret("Password: ") == "secret"
    getpass_mock.assert_called_once_with("Password: ")


@pytest.mark.parametrize(
    "kwargs,expected",
    (
        ({"basic": True}, (HTTP_BASIC_AUTH_NAME, basic_auth_manager)),
        ({"token": "token"}, (TOKEN_NAME, token_auth_manager)),
    ),
)
def test_get_auth_manager_from_cli_options(kwargs, expected):
    """
    Test to make sure CLI auth options map to the expected auth manager.
    """
    assert get_auth_manager(**kwargs) == expected


@pytest.mark.parametrize(
    "kwargs,message",
    (
        ({}, "Missing authentication type."),
        (
            {"auth": "unknown"},
            "Invalid authentication type.",
        ),
    ),
)
def test_get_auth_manager_rejects_invalid_configuration(kwargs, message):
    """
    Test to make sure missing and unknown auth settings raise useful errors.
    """
    with pytest.raises(CondaAuthError, match=message):
        get_auth_manager(**kwargs)
