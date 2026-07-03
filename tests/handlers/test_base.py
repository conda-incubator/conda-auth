from __future__ import annotations

from types import SimpleNamespace

import pytest
from conda.models.channel import Channel

from conda_auth.constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.base import (
    AuthManager,
    allows_plaintext_http,
    get_url_host,
    is_loopback_host,
    validate_secure_channel,
)


class StubAuthManager(AuthManager):
    def _fetch_secret(self, channel, settings):
        raise NotImplementedError

    def remove_secret(self, channel, settings):
        raise NotImplementedError

    def get_auth_type(self):
        return "test"

    def get_config_parameters(self):
        return ()

    def get_auth_class(self):
        return object


@pytest.mark.parametrize(
    ("channel_name", "allow_plaintext_http"),
    (
        (None, False),
        ("https://repo.example.com/private", False),
        ("http://localhost:8080/private", False),
        ("http://127.0.0.1:8080/private", False),
        ("http://[::1]:8080/private", False),
        ("http://example.com/private", True),
    ),
    ids=("unknown", "https", "localhost", "ipv4-loopback", "ipv6-loopback", "explicit-http"),
)
def test_validate_secure_channel_allows_supported_transports(channel_name, allow_plaintext_http):
    validate_secure_channel(
        Channel(channel_name),
        allow_plaintext_http=allow_plaintext_http,
    )


@pytest.mark.parametrize(
    ("channel_name", "message"),
    (
        ("http://example.com/private", "insecure HTTP channel"),
        ("ftp://example.com/private", "unsupported channel scheme"),
        ("s3://bucket/private", "unsupported channel scheme"),
        ("file:///tmp/private", "unsupported channel scheme"),
    ),
    ids=("remote-http", "ftp", "s3", "file"),
)
def test_validate_secure_channel_rejects_unsupported_transports(channel_name, message):
    with pytest.raises(CondaAuthError, match=message):
        validate_secure_channel(Channel(channel_name))


@pytest.mark.parametrize(
    ("url", "expected_host"),
    (
        ("http://::1:8080/private", "::1"),
        ("http://::1/private", "::1"),
        ("http://127.0.0.1:8080/private", "127.0.0.1"),
        ("http://example.com/private", "example.com"),
        ("http://", None),
        ("http://::x:8080/private", "::x"),
        ("http://:8080/private", None),
    ),
    ids=(
        "ipv6-loopback-port",
        "ipv6-loopback",
        "ipv4-loopback",
        "hostname",
        "missing-host",
        "unbracketed-invalid-ipv6-port",
        "port-only",
    ),
)
def test_get_url_host_handles_normalized_urls(url, expected_host):
    assert get_url_host(url) == expected_host


@pytest.mark.parametrize(
    ("host", "expected"),
    (
        (None, False),
        ("LOCALHOST", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("repo.example.com", False),
    ),
    ids=("missing", "localhost", "ipv4", "ipv6", "remote"),
)
def test_is_loopback_host(host, expected):
    assert is_loopback_host(host) is expected


@pytest.mark.parametrize(
    ("settings", "expected"),
    (
        (None, False),
        ({AUTH_ALLOW_PLAINTEXT_HTTP_PARAM: True}, True),
        ({AUTH_ALLOW_PLAINTEXT_HTTP_PARAM: "yes"}, True),
        ({AUTH_ALLOW_PLAINTEXT_HTTP_PARAM: "not-a-boolean"}, False),
    ),
    ids=("missing", "boolean", "truthy-string", "invalid"),
)
def test_allows_plaintext_http(settings, expected):
    assert allows_plaintext_http(settings) is expected


def test_auth_manager_builds_default_credential_record():
    channel = Channel("tester")

    record = StubAuthManager().create_credential_record(channel, "username", "password")

    assert record == CredentialRecord(
        target="tester",
        auth_type="test",
        username="username",
        password="password",
    )


def test_auth_manager_returns_stored_credential_record(monkeypatch):
    channel = Channel("tester")
    record = CredentialRecord(target="tester", auth_type="test")
    monkeypatch.setattr(
        "conda_auth.handlers.base.storage",
        SimpleNamespace(get_credential=lambda target: record),
    )

    assert StubAuthManager().get_credential_record(channel) == record


def test_auth_manager_default_legacy_credential_behavior():
    channel = Channel("tester")
    auth_manager = StubAuthManager()

    assert auth_manager.migrate_legacy_credential_record(channel, None, "tester") is None
    assert auth_manager.legacy_credential_targets(channel, "shared") == ("shared", "tester")
