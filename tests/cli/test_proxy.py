from __future__ import annotations

import json
from dataclasses import dataclass, field

from conda_auth.cli import auth
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


def test_proxy_login_rolls_back_proxy_config_when_storage_fails(runner, keyring, condarc):
    keyring_mock, _ = keyring(None)
    keyring_mock.set_password_side_effect = CondaAuthError("Could not save credential")
    condarc.content = {"proxy_servers": {"https": "http://other.example.com:8080"}}

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
    assert condarc.content == {"proxy_servers": {"https": "http://other.example.com:8080"}}


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
        ["proxy", "logout", "http", "--proxy-url", "http://proxy.example.com:8080"],
    )

    assert result.exit_code == 0, result.output
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
