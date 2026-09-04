from __future__ import annotations

import json

import pytest

from conda_auth.handlers.token import TOKEN_FILE_ROOTS_ENV_VAR

from .auth_server import TEST_PACKAGE_NAME

pytestmark = pytest.mark.integration


def test_basic_auth_conda_search_uses_stored_credentials(conda_runner, channel_server):
    server = channel_server(mode="basic", username="user", password="pass")

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--basic",
        "--username",
        "user",
        "--password",
        "pass",
        "--json",
    )
    assert login.returncode == 0, login.stderr or login.stdout
    assert json.loads(login.stdout)["success"] is True

    search = conda_runner.run(
        "search",
        "--json",
        "--override-channels",
        "-c",
        server.url,
        TEST_PACKAGE_NAME,
    )

    assert search.returncode == 0, search.stderr or search.stdout
    assert TEST_PACKAGE_NAME in json.loads(search.stdout)
    assert any(
        record.path.endswith("repodata.json")
        and record.authorization == server.expected_basic_header
        and record.status_code == 200
        for record in server.records
    )


def test_basic_auth_login_verify_probes_channel_metadata(conda_runner, channel_server):
    server = channel_server(mode="basic", username="user", password="pass")

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--basic",
        "--username",
        "user",
        "--password",
        "pass",
        "--verify",
        "--json",
    )

    assert login.returncode == 0, login.stderr or login.stdout
    assert json.loads(login.stdout)["success"] is True
    assert any(
        record.path.endswith("repodata_shards.msgpack.zst")
        and record.authorization == server.expected_basic_header
        and record.status_code == 200
        for record in server.records
    )


def test_basic_auth_login_verify_failure_rolls_back_credentials(conda_runner, channel_server):
    server = channel_server(mode="basic", username="user", password="pass")

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--basic",
        "--username",
        "user",
        "--password",
        "wrong",
        "--verify",
        "--json",
    )

    assert login.returncode != 0
    assert any(
        record.path.endswith("repodata.json")
        and record.authorization is not None
        and record.status_code == 401
        for record in server.records
    )

    status = conda_runner.run("auth", "status", "--json")

    assert status.returncode == 0, status.stderr or status.stdout
    assert json.loads(status.stdout) == {"success": True, "credentials": []}


def test_basic_auth_conda_search_without_credentials_fails(conda_runner, channel_server):
    server = channel_server(mode="basic", username="user", password="pass")

    search = conda_runner.run(
        "search",
        "--json",
        "--override-channels",
        "-c",
        server.url,
        TEST_PACKAGE_NAME,
    )

    assert search.returncode != 0
    assert any(
        record.path.endswith("repodata.json")
        and record.authorization is None
        and record.status_code == 401
        for record in server.records
    )


def test_token_header_conda_search_uses_stored_credentials(conda_runner, channel_server):
    server = channel_server(
        mode="token",
        token="secret-token",
        token_header="X-Auth",
        token_template="Token {token}",
    )

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--token",
        "secret-token",
        "--header",
        "X-Auth",
        "--token-template",
        "Token {token}",
        "--json",
    )
    assert login.returncode == 0, login.stderr or login.stdout
    assert json.loads(login.stdout)["success"] is True

    search = conda_runner.run(
        "search",
        "--json",
        "--override-channels",
        "-c",
        server.url,
        TEST_PACKAGE_NAME,
    )

    assert search.returncode == 0, search.stderr or search.stdout
    assert TEST_PACKAGE_NAME in json.loads(search.stdout)
    assert any(
        record.path.endswith("repodata.json")
        and record.headers.get("X-Auth") == "Token secret-token"
        and record.status_code == 200
        for record in server.records
    )


def test_token_file_conda_search_works_without_keyring_backend(
    tmp_path, conda_runner, channel_server
):
    server = channel_server(mode="token", token="secret-token")
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    token_file = secret_root / "conda_auth_secret"
    token_file.write_text("secret-token\n")
    conda_runner.env["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.KeyRing"
    conda_runner.env[TOKEN_FILE_ROOTS_ENV_VAR] = str(secret_root)

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--token-file",
        str(token_file),
        "--json",
    )
    assert login.returncode == 0, login.stderr or login.stdout
    assert json.loads(login.stdout)["success"] is True

    status = conda_runner.run("auth", "status", "--json")
    assert status.returncode == 0, status.stderr or status.stdout
    assert json.loads(status.stdout) == {
        "success": True,
        "credentials": [
            {
                "target": server.url,
                "auth_type": "token",
                "source": "token_file",
            }
        ],
    }

    search = conda_runner.run(
        "search",
        "--json",
        "--override-channels",
        "-c",
        server.url,
        TEST_PACKAGE_NAME,
    )

    assert search.returncode == 0, search.stderr or search.stdout
    assert TEST_PACKAGE_NAME in json.loads(search.stdout)
    assert any(
        record.path.endswith("repodata.json")
        and record.authorization == "Bearer secret-token"
        and record.status_code == 200
        for record in server.records
    )

    logout = conda_runner.run("auth", "logout", server.url, "--json")
    assert logout.returncode == 0, logout.stderr or logout.stdout
    assert json.loads(logout.stdout)["success"] is True


def test_token_conda_env_create_uses_stored_credentials_after_login(
    tmp_path, conda_runner, channel_server
):
    server = channel_server(mode="token", token="secret-token")
    environment = tmp_path / "environment.yml"
    environment.write_text(
        "\n".join(
            (
                "channels:",
                f"  - {server.url}",
                "dependencies:",
                f"  - {TEST_PACKAGE_NAME}",
                "",
            )
        )
    )

    login = conda_runner.run(
        "auth",
        "login",
        server.url,
        "--token",
        "secret-token",
        "--json",
    )
    assert login.returncode == 0, login.stderr or login.stdout
    assert json.loads(login.stdout)["success"] is True

    create = conda_runner.run(
        "env",
        "create",
        "--file",
        str(environment),
        "--name",
        "conda-auth-token-regression",
        "--dry-run",
        "--json",
    )

    assert create.returncode == 0, create.stderr or create.stdout
    assert any(
        record.path.endswith("repodata.json")
        and record.authorization == "Bearer secret-token"
        and record.status_code == 200
        for record in server.records
    )
