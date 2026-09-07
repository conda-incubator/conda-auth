from __future__ import annotations

import json
from argparse import Namespace
from dataclasses import dataclass, field

import pytest
from conda.common.serialize import yaml
from conda.exceptions import CondaError

from conda_auth.cli import auth
from conda_auth.cli.proxy import auth_proxy_command
from conda_auth.constants import (
    PROXY_AUTH_NAME,
    SUCCESSFUL_LOGIN_MESSAGE,
    SUCCESSFUL_LOGOUT_MESSAGE,
)
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.proxy import ProxyAuthManager
from conda_auth.storage import storage


@dataclass
class FakeProxyContext:
    proxy_servers: dict[str, object] = field(default_factory=dict)


proxy_manager = ProxyAuthManager()


@pytest.mark.parametrize(
    ("proxy_command", "message"),
    (
        (None, "Missing proxy command"),
        ("unknown", "Unknown proxy command: unknown"),
    ),
    ids=("missing", "unknown"),
)
def test_proxy_command_rejects_invalid_subcommands(proxy_command, message):
    with pytest.raises(CondaAuthError, match=message):
        auth_proxy_command(Namespace(proxy_command=proxy_command))


def test_proxy_login_stores_credentials_and_proxy_config(runner, keyring, condarc):
    keyring(None)

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--proxy-url",
            "http://proxy.example.com:8080",
            "--username",
            "user",
            "--password",
            "password",
        ],
    )

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGIN_MESSAGE in result.output
    assert condarc.content == {"proxy_servers": {"http": "http://proxy.example.com:8080"}}
    assert storage.get_credential(
        proxy_manager.target("http", "http://proxy.example.com:8080")
    ) == CredentialRecord(
        target="proxy:http:http://proxy.example.com:8080",
        auth_type=PROXY_AUTH_NAME,
        username="user",
        password="password",
    )


@pytest.mark.parametrize(
    ("provided_args", "expected_prompt", "expected_username", "expected_password"),
    (
        (("--password", "password"), "Proxy username: ", "prompted-user", "password"),
        (("--username", "user"), "Proxy password: ", "user", "prompted-password"),
    ),
    ids=("username", "password"),
)
def test_proxy_login_prompts_for_missing_credentials(
    monkeypatch,
    runner,
    keyring,
    condarc,
    provided_args,
    expected_prompt,
    expected_username,
    expected_password,
):
    keyring(None)
    prompts = []

    def prompt_username(prompt):
        prompts.append(prompt)
        return "prompted-user"

    def prompt_password(prompt):
        prompts.append(prompt)
        return "prompted-password"

    monkeypatch.setattr("builtins.input", prompt_username)
    monkeypatch.setattr("conda_auth.cli.proxy.getpass", prompt_password)

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--proxy-url",
            "http://proxy.example.com:8080",
            *provided_args,
        ],
    )

    assert result.exit_code == 0, result.output
    assert prompts == [expected_prompt]
    record = storage.get_credential(proxy_manager.target("http", "http://proxy.example.com:8080"))
    assert record is not None
    assert record.username == expected_username
    assert record.password == expected_password


def test_proxy_login_uses_existing_proxy_config(monkeypatch, runner, keyring, condarc):
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.proxy.context",
        FakeProxyContext(proxy_servers={"http": "http://proxy.example.com:8080"}),
    )

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--username",
            "user",
            "--password",
            "password",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "success": True,
        "message": SUCCESSFUL_LOGIN_MESSAGE,
    }
    assert condarc.content == {}
    record = storage.get_credential(proxy_manager.target("http", "http://proxy.example.com:8080"))
    assert record is not None
    assert record.password == "password"


def test_proxy_login_requires_proxy_url(monkeypatch, runner, keyring, condarc):
    keyring(None)
    monkeypatch.setattr("conda_auth.proxy.context", FakeProxyContext())

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--username",
            "user",
            "--password",
            "password",
        ],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Missing proxy URL" in exception.message
    assert condarc.content == {}


def test_proxy_login_rejects_proxy_url_with_credentials(runner, keyring, condarc):
    keyring(None)

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--proxy-url",
            "http://user:password@proxy.example.com:8080",
            "--username",
            "user",
            "--password",
            "password",
        ],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "must not include credentials" in exception.message
    assert condarc.content == {}


@pytest.mark.parametrize(
    "previous_proxy_servers",
    (None, {"https": "http://other.example.com:8080"}),
    ids=("missing", "existing"),
)
def test_proxy_login_rolls_back_proxy_config_when_storage_fails(
    runner,
    keyring,
    condarc,
    previous_proxy_servers,
):
    keyring_mock, _ = keyring(None)
    keyring_mock.set_password_side_effect = CondaAuthError("Could not save credential")
    if previous_proxy_servers is not None:
        condarc.content = {"proxy_servers": previous_proxy_servers}
    original_content = condarc.content.copy()

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--proxy-url",
            "http://proxy.example.com:8080",
            "--username",
            "user",
            "--password",
            "password",
        ],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not save credential" in exception.message
    assert condarc.content == original_content


@pytest.mark.parametrize(
    "error_type",
    (CondaError, OSError, yaml.YAMLError),
    ids=("conda", "os", "yaml"),
)
def test_proxy_login_wraps_config_errors(monkeypatch, runner, keyring, error_type):
    keyring(None)

    def fail_to_open_config():
        raise error_type("Could not update proxy configuration")

    monkeypatch.setattr(
        "conda_auth.cli.proxy.ConfigurationFile.from_user_condarc",
        fail_to_open_config,
    )

    result = runner.invoke(
        auth,
        [
            "proxy",
            "login",
            "http",
            "--proxy-url",
            "http://proxy.example.com:8080",
            "--username",
            "user",
            "--password",
            "password",
        ],
    )
    exc_type, exception, _ = result.exc_info

    assert exc_type == CondaAuthError
    assert "Could not update proxy configuration" in exception.message


def test_proxy_logout_removes_stored_credentials(monkeypatch, runner, keyring):
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.proxy.context",
        FakeProxyContext(proxy_servers={"http": "http://proxy.example.com:8080"}),
    )
    storage.set_credential(
        CredentialRecord(
            target=proxy_manager.target("http", "http://proxy.example.com:8080"),
            auth_type=PROXY_AUTH_NAME,
            username="user",
            password="password",
        )
    )

    result = runner.invoke(auth, ["proxy", "logout", "http"])

    assert result.exit_code == 0, result.output
    assert SUCCESSFUL_LOGOUT_MESSAGE in result.output
    assert (
        storage.get_credential(proxy_manager.target("http", "http://proxy.example.com:8080"))
        is None
    )


def test_proxy_logout_accepts_explicit_proxy_url(runner, keyring):
    keyring(None)
    storage.set_credential(
        CredentialRecord(
            target=proxy_manager.target("http", "http://proxy.example.com:8080"),
            auth_type=PROXY_AUTH_NAME,
            username="user",
            password="password",
        )
    )

    result = runner.invoke(
        auth,
        [
            "proxy",
            "logout",
            "http",
            "--proxy-url",
            "http://proxy.example.com:8080",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "success": True,
        "message": SUCCESSFUL_LOGOUT_MESSAGE,
    }
    assert (
        storage.get_credential(proxy_manager.target("http", "http://proxy.example.com:8080"))
        is None
    )


def test_proxy_status_lists_configured_proxy_credentials(monkeypatch, runner, keyring):
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.proxy.context",
        FakeProxyContext(proxy_servers={"http": "http://proxy.example.com:8080"}),
    )
    storage.set_credential(
        CredentialRecord(
            target=proxy_manager.target("http", "http://proxy.example.com:8080"),
            auth_type=PROXY_AUTH_NAME,
            username="user",
            password="password",
        )
    )

    result = runner.invoke(auth, ["proxy", "status", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "success": True,
        "credentials": [
            {
                "target": "proxy:http:http://proxy.example.com:8080",
                "auth_type": PROXY_AUTH_NAME,
                "username": "user",
                "proxy_url": "http://proxy.example.com:8080",
            }
        ],
    }


def test_proxy_status_redacts_configured_proxy_url_credentials(monkeypatch, runner, keyring):
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.proxy.context",
        FakeProxyContext(proxy_servers={"http": "http://user:password@proxy.example.com:8080"}),
    )

    result = runner.invoke(auth, ["proxy", "status", "--json"])

    assert result.exit_code == 0, result.output
    assert "password" not in result.output
    assert json.loads(result.stdout) == {"success": True, "credentials": []}
