from __future__ import annotations

import json

import pytest

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

