from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.integration


def fetch(url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    request = Request(url, headers=headers or {})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_basic_auth_server_requires_credentials(channel_server):
    server = channel_server(mode="basic", username="user", password="pass")

    status, body, headers = fetch(server.get_url("noarch/repodata.json"))

    assert status == 401
    assert b"no auth header received" in body
    assert headers["WWW-Authenticate"] == 'Basic realm="Test"'


def test_token_auth_server_rejects_wrong_header(channel_server):
    server = channel_server(
        mode="token",
        token="secret-token",
        token_header="X-Auth",
        token_template="Token {token}",
    )

    status, body, _ = fetch(
        server.get_url("noarch/repodata.json"),
        headers={"X-Auth": "Token wrong-token"},
    )

    assert status == 403
    assert b"not authenticated" in body


def test_auth_server_rejects_path_traversal(tmp_path, channel_server):
    (tmp_path / "outside.txt").write_text("outside")
    server = channel_server(mode="none")

    status, body, _ = fetch(server.get_url("%2e%2e/outside.txt"))

    assert status == 404
    assert b"outside" not in body
