from __future__ import annotations

from dataclasses import dataclass

import pytest
from conda.base.context import context
from conda.models.channel import Channel
from requests import Response as RequestsResponse
from requests.auth import AuthBase, HTTPBasicAuth
from requests.exceptions import ConnectionError

from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.basic_auth import HTTP_BASIC_AUTH_NAME
from conda_auth.handlers.token import TOKEN_NAME
from conda_auth.oauth2_client import OAUTH2_NAME
from conda_auth.verification import (
    ZSTD_MAGIC,
    VerificationAuth,
    build_verification_request,
    is_valid_metadata_response,
    iter_verification_urls,
    verify_channel_credentials,
)


@dataclass(frozen=True)
class Response:
    status_code: int
    body: dict[str, object] | None = None
    content: bytes = b""

    def json(self):
        if self.body is None:
            raise ValueError("not json")
        return self.body


def install_session(monkeypatch, responses):
    calls = []
    response_iter = iter(responses)

    class FakeSession:
        def __init__(self, auth):
            self.auth = auth

        def get(self, url, **kwargs):
            calls.append((url, kwargs, self.auth))
            response = next(response_iter)
            if isinstance(response, Exception):
                raise response
            return response

    monkeypatch.setattr("conda_auth.verification.CondaSession", FakeSession)
    return calls


def test_iter_verification_urls_uses_common_channel_metadata_paths():
    urls = tuple(iter_verification_urls(Channel("https://repo.example.com/private")))

    assert urls == (
        "https://repo.example.com/private/noarch/repodata_shards.msgpack.zst",
        f"https://repo.example.com/private/{context.subdir}/repodata_shards.msgpack.zst",
        "https://repo.example.com/private/noarch/repodata.json",
        f"https://repo.example.com/private/{context.subdir}/repodata.json",
        "https://repo.example.com/private/channeldata.json",
    )


def test_iter_verification_urls_skips_wildcard_targets():
    urls = tuple(iter_verification_urls(Channel("https://repo.example.com/*")))

    assert urls == ()


def test_iter_verification_urls_deduplicates_channel_urls(monkeypatch):
    channel = Channel("https://repo.example.com/private")
    monkeypatch.setattr(
        Channel,
        "urls",
        lambda self: (
            "https://repo.example.com/private/noarch",
            "https://repo.example.com/private/noarch",
        ),
    )

    assert tuple(iter_verification_urls(channel)) == (
        "https://repo.example.com/private/noarch/repodata_shards.msgpack.zst",
        "https://repo.example.com/private/noarch/repodata.json",
        "https://repo.example.com/private/channeldata.json",
    )


def test_verification_auth_applies_optional_wrapped_auth():
    request = object()
    calls = []

    class WrappedAuth(AuthBase):
        def __call__(self, r):
            calls.append(r)
            return r

    assert VerificationAuth()(request) is request
    assert VerificationAuth(WrappedAuth())(request) is request
    assert calls == [request]


@pytest.mark.parametrize(
    ("record", "expected_headers", "expected_auth"),
    (
        (
            CredentialRecord(
                target="tester",
                auth_type=HTTP_BASIC_AUTH_NAME,
                username="user",
                password="pass",
            ),
            {},
            HTTPBasicAuth("user", "pass"),
        ),
        (
            CredentialRecord(
                target="tester",
                auth_type=TOKEN_NAME,
                token="secret",
                token_header="X-Auth",
                token_template="Token {token}",
            ),
            {"X-Auth": "Token secret"},
            None,
        ),
        (
            CredentialRecord(
                target="tester",
                auth_type=OAUTH2_NAME,
                access_token="access-token",
            ),
            {"Authorization": "Bearer access-token"},
            None,
        ),
    ),
    ids=("basic", "token-header", "oauth2"),
)
def test_build_verification_request(record, expected_headers, expected_auth):
    request = build_verification_request(record)

    assert request.headers == expected_headers
    assert request.auth.auth == expected_auth
    assert request.auth.channel_name.startswith("conda-auth-verify-")


@pytest.mark.parametrize(
    ("record", "message"),
    (
        (
            CredentialRecord(
                target="tester",
                auth_type=HTTP_BASIC_AUTH_NAME,
                username="user",
            ),
            "incomplete HTTP basic credentials",
        ),
        (
            CredentialRecord(target="tester", auth_type=TOKEN_NAME),
            "missing token credentials",
        ),
        (
            CredentialRecord(target="tester", auth_type=OAUTH2_NAME),
            "missing OAuth 2.0 access token",
        ),
        (
            CredentialRecord(target="tester", auth_type="unsupported"),
            "unsupported authentication type 'unsupported'",
        ),
    ),
    ids=("basic", "token", "oauth2", "unsupported"),
)
def test_build_verification_request_rejects_invalid_records(record, message):
    with pytest.raises(CondaAuthError, match=message):
        build_verification_request(record)


@pytest.mark.parametrize(
    "url",
    (
        "https://repo.example.com/noarch/repodata.json",
        "https://repo.example.com/channeldata.json",
        "https://repo.example.com/unsupported.json",
    ),
    ids=("invalid-repodata-json", "invalid-channeldata-json", "unsupported-filename"),
)
def test_metadata_response_rejects_invalid_or_unsupported_content(url):
    assert is_valid_metadata_response(url, RequestsResponse()) is False


def test_verify_channel_credentials_passes_on_success_after_auth_failure(monkeypatch):
    calls = install_session(
        monkeypatch,
        (Response(403), Response(200, content=ZSTD_MAGIC + b"payload")),
    )

    verify_channel_credentials(
        Channel("https://repo.example.com/private"),
        CredentialRecord(target="tester", auth_type=TOKEN_NAME, token="secret"),
    )

    assert [call[0] for call in calls] == [
        "https://repo.example.com/private/noarch/repodata_shards.msgpack.zst",
        f"https://repo.example.com/private/{context.subdir}/repodata_shards.msgpack.zst",
    ]
    assert calls[0][1]["headers"] == {"Authorization": "Bearer secret"}
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][2].auth is None


def test_verify_channel_credentials_uses_repodata_as_fallback(monkeypatch):
    calls = install_session(
        monkeypatch,
        (
            Response(404),
            Response(404),
            Response(200, body={"packages": {}, "packages.conda": {}}),
        ),
    )

    verify_channel_credentials(
        Channel("https://repo.example.com/private"),
        CredentialRecord(target="tester", auth_type=TOKEN_NAME, token="secret"),
    )

    assert [call[0] for call in calls] == [
        "https://repo.example.com/private/noarch/repodata_shards.msgpack.zst",
        f"https://repo.example.com/private/{context.subdir}/repodata_shards.msgpack.zst",
        "https://repo.example.com/private/noarch/repodata.json",
    ]


def test_verify_channel_credentials_rejects_invalid_success_metadata(monkeypatch):
    calls = install_session(
        monkeypatch,
        (
            Response(200, content=b"<html>login</html>"),
            Response(200, content=b"<html>login</html>"),
            Response(200, body={"not": "repodata"}),
            Response(200, body={"not": "repodata"}),
            Response(200, body={"not": "channeldata"}),
        ),
    )

    verify_channel_credentials(
        Channel("https://repo.example.com/private"),
        CredentialRecord(target="tester", auth_type=TOKEN_NAME, token="secret"),
    )

    assert len(calls) == 5


@pytest.mark.parametrize("status_code", (401, 403))
def test_verify_channel_credentials_fails_on_auth_rejection(monkeypatch, status_code):
    install_session(monkeypatch, (Response(status_code),) * 5)

    with pytest.raises(CondaAuthError, match=f"HTTP {status_code}"):
        verify_channel_credentials(
            Channel("https://repo.example.com/private"),
            CredentialRecord(
                target="tester",
                auth_type=HTTP_BASIC_AUTH_NAME,
                username="user",
                password="pass",
            ),
        )


def test_verify_channel_credentials_ignores_inconclusive_failures(monkeypatch):
    install_session(
        monkeypatch,
        (
            ConnectionError("offline"),
            Response(404),
            Response(500),
            Response(404),
            Response(500),
        ),
    )

    verify_channel_credentials(
        Channel("https://repo.example.com/private"),
        CredentialRecord(target="tester", auth_type=TOKEN_NAME, token="secret"),
    )


def test_verify_channel_credentials_skips_unprobeable_targets(monkeypatch):
    class FakeSession:
        def __init__(self, auth):
            pass

        def get(self, url, **kwargs):
            raise AssertionError(f"Unexpected verification request for {url!r}")

    monkeypatch.setattr("conda_auth.verification.CondaSession", FakeSession)

    verify_channel_credentials(
        Channel("https://repo.example.com/*"),
        CredentialRecord(target="*", auth_type=TOKEN_NAME, token="secret"),
    )
